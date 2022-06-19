use csrf::CsrfProtection;
use rocket::fairing::{Info, Kind};
use rocket::http::HeaderMap;
use rocket::request::{self, FromRequest};
use rocket::{http::hyper::header, Request, Response};

use crate::config;

#[macro_export]
macro_rules! alert_tmpl {
    ($msg:expr, $back_to:expr) => ({
        Template::render("alert", json!({
            "msg": $msg,
            "back_to": $back_to
        }))
    })
}

pub struct SecurityHeaderMiddleware;

#[rocket::async_trait]
impl rocket::fairing::Fairing for SecurityHeaderMiddleware {
    fn info(&self) -> rocket::fairing::Info {
        Info {
            name: "SecurityHeaderMiddleware",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        Self::set_security_headers(request, response);
    }
}

impl SecurityHeaderMiddleware {
    fn set_security_headers(req: &Request, res: &mut Response<'_>) {
        Self::set_cors_headers(req, res);
        res.set_raw_header("X-Content-Type-Options", "nosniff");
        res.set_raw_header("X-XSS-Protection", "1; mode=block");

        let mut csp = vec!["default-src 'self'"];

        if req
            .uri()
            .to_owned()
            .into_normalized()
            .path()
            .starts_with("/storage")
        {
            // It's probably fine to embed user storage data into other documents

            // Prevent clickjacking attacks like described in OAuth RFC
            // https://tools.ietf.org/html/rfc6749#section-10.13
            res.set_raw_header("X-Frame-Options", "DENY");

            // This is a newer way to do what X-Frame-Options does
            // http://www.w3.org/TR/CSP11/#frame-ancestors-and-frame-options
            csp.push("frame-ancestors 'none'");
        };
        res.set_raw_header("Content-Security-Policy", csp.join(";"));
    }

    /// Required by remoteStorage spec
    fn set_cors_headers<'r>(req: &Request, res: &mut Response<'r>) {
        let uri = req.uri().clone().into_normalized();
        let path = uri.path();
        if !(path.starts_with("/.well-known") || path.starts_with("/storage")) {
            return;
        };

        let origin = match req.headers().get_one("Origin") {
            Some(x) => x.to_owned(),
            None => return,
        };

        res.set_raw_header("Access-Control-Allow-Origin", origin);
        res.set_raw_header("Access-Control-Expose-Headers", "ETag, Content-Length");
        res.set_raw_header("Access-Control-Allow-Methods", "GET, PUT, DELETE");
        res.set_raw_header(
            "Access-Control-Allow-Headers",
            "Authorization, Content-Type, Origin, If-Match, If-None-Match",
        );
    }
}

pub fn matches_etag_ifnonematch(header: &str, given: Option<&str>) -> bool {
    match header {
        "*" => given.is_some(),
        values => match given {
            Some(given_value) => values.split(", ").any(|val| val == given_value),
            None => false,
        },
    }
}

pub fn matches_etag_ifmatch(header: &str, given: Option<&str>) -> bool {
    match header {
        "*" => given.is_some(),
        values => match given {
            Some(given_value) => values.split(", ").any(|val| val == given_value),
            None => false,
        },
    }
}

pub fn preconditions_ok(headers: &RequestHeaders, etag: Option<&str>) -> bool {
    let if_none_match: Vec<&str> = headers
        .headers
        .get(header::IF_NONE_MATCH.as_str())
        .collect();
    for header in if_none_match {
        if matches_etag_ifnonematch(header, etag) {
            return false;
        }
    }

    let if_match: Vec<&str> = headers.headers.get(header::IF_MATCH.as_str()).collect();
    for header in if_match {
        if !matches_etag_ifmatch(header, etag) {
            return false;
        }
    }
    true
}

pub struct CsrfChecker {
    protect: csrf::AesGcmCsrfProtection,
}

pub enum CsrfCheck {
    Verified,
    Invalid,
}

impl CsrfChecker {
    pub fn new(config: &config::Config) -> CsrfChecker {
        CsrfChecker {
            protect: csrf::AesGcmCsrfProtection::from_key(
                base64::decode(&config.csrf_key)
                    .unwrap()
                    .try_into()
                    .expect("slice with incorrect length"),
            ),
        }
    }

    pub fn generate(self: &Self) -> (String, String) {
        let (token, cookie) = self.protect.generate_token_pair(None, 300).unwrap();
        return (token.b64_string(), cookie.b64_string());
    }

    pub fn verify(self: &Self, token: &str, cookie: &str) -> CsrfCheck {
        let token_bytes = match base64::decode(token.as_bytes()) {
            Ok(t) => t,
            Err(_) => return CsrfCheck::Invalid,
        };
        let cookie_bytes = match base64::decode(cookie.as_bytes()) {
            Ok(c) => c,
            Err(_) => return CsrfCheck::Invalid,
        };

        let parsed_token = match self.protect.parse_token(&token_bytes) {
            Ok(t) => t,
            Err(_) => return CsrfCheck::Invalid,
        };
        let parsed_cookie = match self.protect.parse_cookie(&cookie_bytes) {
            Ok(c) => c,
            Err(_) => return CsrfCheck::Invalid,
        };

        match self
            .protect
            .verify_token_pair(&parsed_token, &parsed_cookie)
        {
            true => CsrfCheck::Verified,
            false => CsrfCheck::Invalid,
        }
    }
}

pub struct RequestHeaders<'a> {
    pub headers: &'a HeaderMap<'a>,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for RequestHeaders<'r> {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        request::Outcome::Success(RequestHeaders {
            headers: req.headers(),
        })
    }
}
