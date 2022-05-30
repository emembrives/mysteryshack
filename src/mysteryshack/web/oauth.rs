use std::collections;
use std::fmt;
use std::error::Error as ErrorTrait;

use rocket::Request;
use rocket::request::FromRequest;
use rocket::request::Outcome;
use serde::{Serialize,Deserialize,Serializer,Deserializer};

use url;

use urlencoded;

use super::super::utils;

/// A OAuth request
#[derive(Debug, Clone)]
pub struct OauthRequest {
    pub session: Option<Session>,  // May be none if malformed
    pub redirect_uri: url::Url,
    pub state: Option<String>,
}


impl Serialize for OauthRequest {
     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
         where S: Serializer {
         self.session.serialize(serializer)
    }
}


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Session {
    pub client_id: String,
    pub permissions: PermissionsMap
}


#[derive(Debug, Clone)]
pub struct PermissionsMap {
    pub permissions: collections::HashMap<String, CategoryPermissions>
}

impl PermissionsMap {
    pub fn permissions_for_category<'a>(&'a self, category: &str) -> Option<&'a CategoryPermissions> {
        match self.permissions.get(category) {
            Some(x) => Some(x),
            None => self.permissions.get("")
        }
    }

    pub fn from_scope_string(scope: &str) -> Option<Self> {
        let mut rv = PermissionsMap {
            permissions: collections::HashMap::new()
        };

        for category_permission in scope.split(' ') {
            let parts = category_permission.split(':').collect::<Vec<_>>();
            if parts.len() != 2 { return None; }

            let (category, permission) = (parts[0], parts[1]);
            if category.is_empty() || permission.is_empty() { return None; }

            let key = if category == "*" { "" } else { category }.to_owned();
            if rv.permissions.get(&key).is_some() { return None; }

            rv.permissions.insert(key, CategoryPermissions {
                can_read: permission.contains('r'),
                can_write: permission.contains('w')
            });
        }

        Some(rv)
    }
}

impl Deserialize<'_> for PermissionsMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer {
        collections::HashMap::<String, CategoryPermissions>::deserialize(deserializer).map(|x| {
            PermissionsMap { permissions: x }
        })
    }
}

impl Serialize for PermissionsMap {
     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
         where S: Serializer {
         self.permissions.serialize(serializer)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct CategoryPermissions {
    pub can_read: bool,
    pub can_write: bool
}

fn expect_param(query: &urlencoded::QueryMap, key: &str) -> Result<String, Error> {
    match query.get(key) {
        Some(x) if x.len() == 1 => Ok(x[0].clone()),
        _ => Err({
            let mut rv = Error::new(ErrorKind::InvalidRequest);
            rv.msg = Some(format!("Missing query parameter: {:?}", key));
            rv
        })
    }
}


#[rocket::async_trait]
impl<'r> FromRequest<'r> for OauthRequest {
    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
    let query = match request.get_ref::<urlencoded::UrlEncodedQuery>().ok() {
            Some(x) => x,
            None => return Err({
                let mut e = Error::new(ErrorKind::InvalidRequest);
                e.msg = Some("No query parameters.".to_owned());
                e
            })
        };
        
        let mut rv = OauthRequest {
            session: None,
            redirect_uri: match url::Url::parse(&expect_param(query, "redirect_uri")?[..]) {
                Ok(x) => x,
                Err(e) => return Err({
                    let mut ne = Error::new(ErrorKind::InvalidRequest);
                    ne.msg = Some(format!("{}", e));
                    ne
                })
            },
            state: expect_param(query, "state").ok() 
        };
        
        rv.session = Some(Session {
            client_id: utils::format_origin(&rv.redirect_uri),
            permissions: match PermissionsMap::from_scope_string(&expect_param(query, "scope")?[..]) {
                Some(x) => x,
                None => {
                    let mut e = Error::new(ErrorKind::InvalidScope);
                    e.msg = Some("Invalid scope.".to_owned());
                    e.request = Some(rv);
                    return Err(e);
                }
            }
        });
        
        Ok(rv)
    }
}

impl OauthRequest {
    pub fn grant(self, token: String) -> Grant {
        Grant { request: self, token: token }
    }

    pub fn reject(self) -> Error {
        let mut e = Error::new(ErrorKind::AccessDenied);
        e.request = Some(self);
        e
    }
}

pub struct Grant {
    pub request: OauthRequest,
    pub token: String
}

impl HttpResponder for Grant {
    fn get_redirect_uri(&self) -> Option<url::Url> {
        Some(self.request.redirect_uri.clone())
    }

    fn get_redirect_uri_params(&self) -> collections::BTreeMap<String, String> {
        let mut rv = collections::BTreeMap::new();
        rv.insert("access_token".to_owned(), self.token.clone());
        self.request.state.as_ref().map(|x| rv.insert("state".to_owned(), x.clone()));
        rv
    }
}

#[derive(Debug)]
pub struct Error {
    pub kind: ErrorKind,
    pub request: Option<OauthRequest>,
    pub error_uri: Option<url::Url>,
    pub msg: Option<String>
}

impl Error {
    pub fn new(kind: ErrorKind) -> Self {
        Error {
            kind: kind,
            request: None,
            error_uri: None,
            msg: None
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum ErrorKind {
    InvalidRequest,
    UnauthorizedClient,
    AccessDenied,
    UnsupportedResponseType,
    InvalidScope,
    ServerError,
    TemporarilyUnavailable
}

impl ErrorKind {
    fn as_snake_case(&self) -> &str {
        match *self {
            ErrorKind::InvalidRequest => "invalid_request",
            ErrorKind::UnauthorizedClient => "unauthorized_client",
            ErrorKind::AccessDenied => "access_denied",
            ErrorKind::UnsupportedResponseType => "unsupported_response_type",
            ErrorKind::InvalidScope => "invalid_scope",
            ErrorKind::ServerError => "server_error",
            ErrorKind::TemporarilyUnavailable => "temporarily_unavailable"
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { self.description().fmt(f) }
}

impl ErrorTrait for Error {
    fn description(&self) -> &str {
        match self.msg {
            Some(ref x) => x,
            None => self.kind.as_snake_case()
        }
    }
    fn cause(&self) -> Option<&ErrorTrait> { None }
}

pub trait HttpResponder {
    fn get_redirect_uri(&self) -> Option<url::Url>;
    fn get_redirect_uri_params(&self) -> collections::BTreeMap<String, String>;

    fn get_response(&self) -> Option<rocket::response::Redirect> {
        self.get_redirect_uri()
            .map(|mut uri| {
                uri.set_fragment(
                    Some(&url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(self.get_redirect_uri_params())
                    .finish()));
                rocket::response::Redirect::found(uri.to_string())
            })
    }
}

impl HttpResponder for Error {
    fn get_redirect_uri(&self) -> Option<url::Url> {
        self.request.as_ref().map(|req| req.redirect_uri.clone())
    }

    fn get_redirect_uri_params(&self) -> collections::BTreeMap<String, String> {
        let mut rv = collections::BTreeMap::new();
        rv.insert("error".to_owned(), self.kind.as_snake_case().to_owned());
        self.msg.as_ref().map(|x| rv.insert("error_description".to_owned(), x.clone()));
        self.request.as_ref().map(|req| req.state.as_ref().map(|state| rv.insert("state".to_owned(), state.clone())));
        rv
    }
}
