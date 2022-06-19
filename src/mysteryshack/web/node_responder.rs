use std::{fs, io::Cursor, ops::Deref};

use async_trait::async_trait;
use rocket::{
    data::ToByteUnit,
    http::{hyper::header, Method, Status},
    response::Responder,
    Data, Response,
};

use crate::{
    models::{self, UserNode},
    web::utils::preconditions_ok,
};

use super::utils::{matches_etag_ifmatch, matches_etag_ifnonematch, RequestHeaders};

#[async_trait]
pub(crate) trait UserNodeResponder {
    async fn respond<'a>(
        &mut self,
        headers: &RequestHeaders<'a>,
        method: rocket::http::Method,
        data: Option<Data<'_>>,
    ) -> ResultResponder<'a> {
        ResultResponder {
            result: match method {
                Method::Get => self.respond_get(headers),
                Method::Put => self.respond_put(headers, data.unwrap()).await,
                Method::Delete => self.respond_delete(headers),
                _ => Err(Status::BadRequest),
            },
        }
    }

    fn respond_get<'a>(&mut self, headers: &RequestHeaders<'a>) -> rocket::response::Result<'a>;
    async fn respond_put<'a>(
        &mut self,
        _: &RequestHeaders<'a>,
        _: Data<'_>,
    ) -> rocket::response::Result<'a> {
        Err(Status::BadRequest)
    }
    fn respond_delete<'r>(&mut self, _: &RequestHeaders<'r>) -> rocket::response::Result<'r> {
        Err(Status::BadRequest)
    }
}

impl<'a> UserNodeResponder for models::UserFolder<'a> {
    fn respond_get<'r>(&mut self, headers: &RequestHeaders<'r>) -> rocket::response::Result<'r> {
        let etag = self.read_etag().ok();
        // https://github.com/remotestorage/spec/issues/93
        let shown_etag = etag.unwrap_or("empty".to_owned());

        if let Some(header) = headers.headers.get("IfNoneMatch").next() {
            if matches_etag_ifnonematch(header, Some(&shown_etag)) {
                return Response::build().status(Status::NotModified).ok();
            }
        };
        let mut r = Response::build();
        r.status(Status::Ok);

        r.raw_header(header::CONTENT_TYPE.as_str(), "application/ld+json");
        r.raw_header(header::CACHE_CONTROL.as_str(), "no-cache");
        r.raw_header(header::ACCEPT_RANGES.as_str(), "none");
        r.raw_header(header::ETAG.as_str(), format!("\"{}\"", shown_etag));

        r.sized_body(None,
            Cursor::new(json!({
                "@context": "http://remotestorage.io/spec/folder-description",
                "items": ({
                    let mut d = std::collections::BTreeMap::new();
                    if let Ok(children) = self.read_children() {
                        for child in &children {
                            match child.json_repr() {
                                Ok(json) => {
                                    d.insert(child.get_basename(), json);
                                },
                                Err(e) => {
                                    println!("Failed to show item {:?}: {:?}", child.get_path(), e);
                                    continue;
                                }
                            };
                        };
                    };
                    d
                })
            })
            .to_string()),
        );
        r.ok()
    }
}

#[async_trait]
impl<'a> UserNodeResponder for models::UserFile<'a> {
    fn respond_get<'b>(&mut self, headers: &RequestHeaders<'b>) -> rocket::response::Result<'b> {
        let etag = self.read_etag().ok();

        if let Some(header) = headers.headers.get(header::IF_NONE_MATCH.as_str()).next() {
            if matches_etag_ifmatch(header, etag.as_ref().map(Deref::deref)) {
                return Response::build().status(Status::NotModified).ok();
            }
        };

        let meta = match self.read_meta() {
            Ok(meta) => meta,
            Err(_) => return Response::build().status(Status::NotFound).ok(),
        };

        let mut r = Response::build();
        r.status(Status::Ok);

        r.raw_header(header::CONTENT_TYPE.as_str(), meta.content_type);
        r.raw_header(
            header::ETAG.as_str(),
            format!(
                "\"{}\"",
                self.read_etag().or(Err(Status::InternalServerError))?
            ),
        );
        r.raw_header(header::CACHE_CONTROL.as_str(), "no-cache");
        r.raw_header(header::ACCEPT_RANGES.as_str(), "none");

        self.open().or(Err(Status::InternalServerError))?;
        r.ok()
    }

    fn respond_delete<'r>(&mut self, headers: &RequestHeaders<'r>) -> rocket::response::Result<'r> {
        let etag = self.read_etag().ok();

        if !preconditions_ok(headers, etag.as_ref().map(Deref::deref)) {
            return Err(Status::PreconditionFailed);
        };

        if etag.is_none() {
            return Err(Status::NotFound);
        }

        self.delete().or(Err(Status::InternalServerError))?;
        Response::build().status(Status::Ok).ok()
    }

    async fn respond_put<'r>(
        &mut self,
        headers: &RequestHeaders<'r>,
        data: Data<'_>,
    ) -> rocket::response::Result<'r> {
        if headers.headers.get("ContentRange").next().is_some() {
            // Content-Range is invalid on PUT, as per RFC 7231. See https://github.com/remotestorage/spec/issues/124
            return Err(Status::BadRequest);
        }

        let etag = self.read_etag().ok();

        if !preconditions_ok(headers, etag.as_ref().map(Deref::deref)) {
            return Err(Status::PreconditionFailed);
        };

        {
            let content_type = match headers.headers.get(header::CONTENT_TYPE.as_str()).next() {
                Some(x) => format!("{}", x),
                None => {
                    //"Missing content type."
                    return Err(Status::BadRequest);
                }
            };
            let local_file = match self.create() {
                Ok(x) => x,
                Err(_) => return Err(Status::Conflict),
            };
            let mut options = fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);

            let content_length = match local_file
                .write_async_with_options(&mut data.open(1.gibibytes()), options)
                .await
            {
                Ok(x) => x,
                Err(_) => {
                    if let Ok(metadata) = std::fs::metadata(self.get_fs_path()) {
                        if metadata.is_dir() {
                            return Err(Status::Conflict);
                        }
                    };
                    return Err(Status::InternalServerError);
                }
            };
            self.write_meta(models::UserFileMeta {
                content_type,
                content_length: content_length.bytes().as_u64(),
            })
            .or(Err(Status::InternalServerError))?;
        }

        Response::build()
            .status(Status::Created)
            .raw_header(
                header::ETAG.as_str(),
                self.read_etag().or(Err(Status::InternalServerError))?,
            )
            .ok()
    }
}

pub struct ResultResponder<'a> {
    result: rocket::response::Result<'a>,
}

impl<'a> Responder<'a, 'a> for ResultResponder<'a> {
    fn respond_to(self, _: &'a rocket::Request<'_>) -> rocket::response::Result<'a> {
        self.result
    }
}
