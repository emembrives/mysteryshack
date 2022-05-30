use hyper::header;

use rocket::{Request, Data, Response, request::{FromRequest, Outcome}};
use url::Position;

use urlencoded;

use unicase::UniCase;

use crate::models;

pub struct XForwardedMiddleware;

#[rocket::async_trait]
impl rocket::fairing::Fairing for XForwardedMiddleware {
    async fn on_request(&self, request: &mut Request<'_>, _: &mut Data<'_>) {
        macro_rules! h {
            ($x:expr) => {{
                let rv = match request.headers().get_one($x) {
                    Some(x) => x.clone(),
                    None => panic!("Missing header: {:?}. Turn off use_proxy_headers or set proxy headers.", $x)
                };
                assert!(request.headers().remove($x));
                rv
            }}
        }

        let host = h!("X-Forwarded-Host");
        let port = h!("X-Forwarded-Port");
        let scheme = h!("X-Forwarded-Proto");
        let remote_addr = h!("X-Forwarded-For");

        {
            let mut url = request.url.as_mut();
            url.set_host(Some(&host)).unwrap();
            url.set_port(Some(port)).unwrap();
            url.set_scheme(&scheme).unwrap();
        }

        request.remote_addr.set_ip(remote_addr);
    }
}

pub struct SecurityHeaderMiddleware;

#[rocket::async_trait]
impl rocket::fairing::Fairing for SecurityHeaderMiddleware {
    async fn on_response(&self, request: &mut Request, response: &mut Response<'r>) {
        Self::set_security_headers(request, &mut response);
    }
}

impl SecurityHeaderMiddleware {
    fn set_security_headers(rq: &Request, r: &mut Response<'r>) {
        Self::set_cors_headers(rq, r);
        r.headers.set_raw("X-Content-Type-Options", vec![b"nosniff".to_vec()]);
        r.headers.set_raw("X-XSS-Protection", vec![b"1; mode=block".to_vec()]);

        let mut csp = vec!["default-src 'self'"];

        if rq.url.path()[0] != "storage" {
            // It's probably fine to embed user storage data into other documents

            // Prevent clickjacking attacks like described in OAuth RFC
            // https://tools.ietf.org/html/rfc6749#section-10.13
            r.headers.set_raw("X-Frame-Options", vec![b"DENY".to_vec()]);

            // This is a newer way to do what X-Frame-Options does
            // http://www.w3.org/TR/CSP11/#frame-ancestors-and-frame-options
            csp.push("frame-ancestors 'none'");
        };
        r.headers.set_raw("Content-Security-Policy", vec![csp.join(";").as_bytes().to_vec()]);
    }

    /// Required by remoteStorage spec
    fn set_cors_headers(rq: &Request, r: &mut Response<'r>) {
        match &rq.url.path()[0][..] {
            ".well-known" | "storage" => (),
            _ => return
        };

        let origin = match rq.headers.get_raw("Origin") {
            Some(x) => if x.len() == 1 {
                match String::from_utf8(x.to_owned().into_iter().next().unwrap()) {
                    Ok(x) => x,
                    Err(_) => return
                }
            } else {
                return;
            },
            None => return
        };

        r.headers.set("Access-Control-Allow-Origin", origin);
        r.headers.set("Access-Control-Expose-Headers", "ETag, Content-Length".to_owned());
        r.headers.set("Access-Control-Allow-Methods", "GET, PUT, DELETE");
        r.headers.set("Access-Control-Allow-Headers", "Authorization, Content-Type, Origin, If-Match, If-None-Match".to_owned());
    }
}

enum EtagRequest {
    IfNoneMatchAny,
    IfNoneMatchItems(Vec<String>),
    IfMatchAny,
    IfMatch_Items(Vec<String>),
}

pub struct EtagMatcher {
    request: EtagRequest,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for EtagMatcher {
    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        req.headers().get("")
    }
}

impl EtagMatcher {
    fn matches_etag(&self, given: Option<&str>) -> bool {
        match *self {
            header::IfNoneMatch::Any => given.is_some(),
            header::IfNoneMatch::Items(ref values) => {
                match given {
                    Some(given_value) => values.iter().any(|val| val.tag() == &given_value[..]),
                    None => false
                }
            }
        }
    }
}

impl EtagMatcher for header::IfMatch {
    fn matches_etag(&self, given: Option<&str>) -> bool {
        match *self {
            header::IfMatch::Any => given.is_some(),
            header::IfMatch::Items(ref values) => {
                match given {
                    Some(given_value) => values.iter().any(|val| val.tag() == &given_value[..]),
                    None => false
                }
            }
        }
    }
}

pub fn preconditions_ok(request: &Request, etag: Option<&str>) -> bool {
    if let Some(header) = request.headers.get::<header::IF_NONE_MATCH>() {
        if header.matches_etag(etag) {
            return false
        }
    };

    if let Some(header) = request.headers.get::<header::IfMatch>() {
        if !header.matches_etag(etag) {
            return false
        }
    };
    true
}

pub trait FormDataHelper<K: ?Sized, V> {
    fn get_only<Q: AsRef<K>>(&self, k: Q) -> Option<&String>;
}

impl FormDataHelper<str, String> for urlencoded::QueryMap {
    fn get_only<Q: AsRef<str>>(&self, k: Q) -> Option<&String> {
        match self.get(&k.as_ref().to_owned()) {
            Some(x) if x.len() == 1 => Some(&x[0]),
            _ => None
        }
    }
}

pub fn get_account_id(user: &models::User, request: &Request) -> String {
    let netloc = &request.url.as_ref()[Position::BeforeHost..Position::AfterPort];
    format!("{}@{}", user.userid, netloc)
}
