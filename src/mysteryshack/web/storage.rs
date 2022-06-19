use std::ops::Deref;
use std::path::PathBuf;

use rocket::http::Status;
use rocket::request::{FromRequest, Outcome};
use rocket::{Data, Request, State};

use crate::models::user_node_from_path;
use crate::web::node_responder::{ResultResponder, UserNodeResponder};
use crate::{config, models};

use super::utils::RequestHeaders;

// Routes mounted on /storage
pub struct AuthorizationBearer {
    token: Option<String>,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthorizationBearer {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let mut auth_header = req.headers().get("Authorization");
        let token = match auth_header.find(|&e| e.starts_with("Bearer ")) {
            Some(bearer) => Some(bearer.strip_prefix("Bearer ").unwrap().to_string()),
            None => None,
        };
        Outcome::Success(AuthorizationBearer { token })
    }
}

#[get("/storage/<userid>/<path..>")]
pub async fn get_storage_root<'a>(
    config: &'a State<config::Config>,
    bearer_token: AuthorizationBearer,
    headers: RequestHeaders<'a>,
    userid: &'a str,
    path: PathBuf,
) -> Result<ResultResponder<'a>, Status> {
    user_node_response(
        config,
        bearer_token,
        headers,
        rocket::http::Method::Get,
        userid,
        path,
        None,
    )
    .await
}

#[put("/storage/<userid>/<path..>", data = "<data>")]
pub async fn put_storage_root<'a>(
    config: &'a State<config::Config>,
    bearer_token: AuthorizationBearer,
    headers: RequestHeaders<'a>,
    userid: &'a str,
    path: PathBuf,
    data: Data<'a>,
) -> Result<ResultResponder<'a>, Status> {
    user_node_response(
        config,
        bearer_token,
        headers,
        rocket::http::Method::Put,
        userid,
        path,
        Some(data),
    )
    .await
}

#[delete("/storage/<userid>/<path..>")]
pub async fn delete_storage_root<'a>(
    config: &'a State<config::Config>,
    bearer_token: AuthorizationBearer,
    headers: RequestHeaders<'a>,
    userid: &'a str,
    path: PathBuf,
) -> Result<ResultResponder<'a>, Status> {
    user_node_response(
        config,
        bearer_token,
        headers,
        rocket::http::Method::Delete,
        userid,
        path,
        None,
    )
    .await
}

async fn user_node_response<'a>(
    config: &'a State<config::Config>,
    bearer_token: AuthorizationBearer,
    headers: RequestHeaders<'a>,
    method: rocket::http::Method,
    userid: &'a str,
    path: PathBuf,
    data: Option<Data<'a>>,
) -> Result<ResultResponder<'a>, Status> {
    let write_operation = match method {
        rocket::http::Method::Get | rocket::http::Method::Head => false,
        _ => true,
    };

    let user = match models::User::get(&config.absolute_data_path(), &userid[..]) {
        Some(x) => x,
        None => return Err(Status::Forbidden),
    };

    let access_token = bearer_token.token;

    let path_str = path.to_str().unwrap();
    let permissions = user.permissions(path_str, access_token.as_ref().map(Deref::deref));

    if !permissions.can_read || (write_operation && !permissions.can_write) {
        return Err(Status::Forbidden);
    }

    if write_operation && data.is_none() {
        return Err(Status::BadRequest);
    }

    match user_node_from_path(&user, &path_str[..]) {
        models::UserNodeFromPath::None => Err(Status::BadRequest),
        models::UserNodeFromPath::UserFolder(mut x) => {
            return Ok(x.respond(&headers, method, data).await)
        }
        models::UserNodeFromPath::UserFile(mut x) => {
            return Ok(x.respond(&headers, method, data).await)
        }
    }
}
