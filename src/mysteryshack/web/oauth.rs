use rocket::{http::Status, response::Responder, Response};
use std::collections;
use std::error::Error as ErrorTrait;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use url;

use super::super::utils;

/// A OAuth request
#[derive(Debug, Clone)]
pub struct OauthRequest {
    pub session: Option<Session>, // May be none if malformed
    pub redirect_uri: url::Url,
    pub state: Option<String>,
}

impl Serialize for OauthRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.session.serialize(serializer)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Session {
    pub client_id: String,
    pub permissions: PermissionsMap,
}

#[derive(Debug, Clone)]
pub struct PermissionsMap {
    pub permissions: collections::HashMap<String, CategoryPermissions>,
}

impl PermissionsMap {
    pub fn permissions_for_category<'a>(
        &'a self,
        category: &str,
    ) -> Option<&'a CategoryPermissions> {
        match self.permissions.get(category) {
            Some(x) => Some(x),
            None => self.permissions.get(""),
        }
    }

    pub fn from_scope_string(scope: &str) -> Option<Self> {
        let mut rv = PermissionsMap {
            permissions: collections::HashMap::new(),
        };

        for category_permission in scope.split(' ') {
            let parts = category_permission.split(':').collect::<Vec<_>>();
            if parts.len() != 2 {
                return None;
            }

            let (category, permission) = (parts[0], parts[1]);
            if category.is_empty() || permission.is_empty() {
                return None;
            }

            let key = if category == "*" { "" } else { category }.to_owned();
            if rv.permissions.get(&key).is_some() {
                return None;
            }

            rv.permissions.insert(
                key,
                CategoryPermissions {
                    can_read: permission.contains('r'),
                    can_write: permission.contains('w'),
                },
            );
        }

        Some(rv)
    }
}

impl<'a> Deserialize<'a> for PermissionsMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        collections::HashMap::<String, CategoryPermissions>::deserialize(deserializer)
            .map(|x| PermissionsMap { permissions: x })
    }
}

impl Serialize for PermissionsMap {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.permissions.serialize(serializer)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct CategoryPermissions {
    pub can_read: bool,
    pub can_write: bool,
}

impl OauthRequest {
    pub fn new(
        redirect_uri_opt: Option<String>,
        state_opt: Option<String>,
        scope_opt: Option<String>,
    ) -> Result<OauthRequest, Error> {
        let redirect_uri = match redirect_uri_opt {
            None => {
                let mut ne = Error::new(ErrorKind::InvalidRequest);
                ne.msg = Some("Missing redirect_uri query parameter.".to_owned());
                return Err(ne);
            }
            Some(s) => match url::Url::parse(&s) {
                Err(e) => {
                    let mut ne = Error::new(ErrorKind::InvalidRequest);
                    ne.msg = Some(format!("{}", e));
                    return Err(ne);
                }
                Ok(u) => u,
            },
        };
        let mut rv = OauthRequest {
            session: None,
            redirect_uri,
            state: state_opt,
        };

        let scope = match scope_opt {
            None => {
                let mut ne = Error::new(ErrorKind::InvalidScope);
                ne.msg = Some("Missing scope".to_owned());
                return Err(ne);
            }
            Some(s) => s,
        };
        rv.session = Some(Session {
            client_id: utils::format_origin(&rv.redirect_uri),
            permissions: match PermissionsMap::from_scope_string(&scope) {
                Some(x) => x,
                None => {
                    let mut e = Error::new(ErrorKind::InvalidScope);
                    e.msg = Some("Invalid scope.".to_owned());
                    e.request = Some(rv);
                    return Err(e);
                }
            },
        });

        Ok(rv)
    }

    pub fn grant(self, token: String) -> Grant {
        Grant {
            request: self,
            token,
        }
    }

    pub fn reject(self) -> Error {
        let mut e = Error::new(ErrorKind::AccessDenied);
        e.request = Some(self);
        e
    }
}

pub struct Grant {
    pub request: OauthRequest,
    pub token: String,
}

impl<'r, 'o: 'r> Responder<'r, 'o> for Grant {
    fn respond_to(self, _request: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        let mut redirect_uri = self.request.redirect_uri.clone();

        let mut params = collections::BTreeMap::new();
        params.insert("access_token".to_owned(), self.token.clone());
        self.request
            .state
            .as_ref()
            .map(|x| params.insert("state".to_owned(), x.clone()));

        redirect_uri.set_fragment(Some(
            &url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(params)
                .finish(),
        ));

        Response::build()
            .status(Status::Found)
            .raw_header("Location", redirect_uri.to_string())
            .ok()
    }
}

#[derive(Debug)]
pub struct Error {
    pub kind: ErrorKind,
    pub request: Option<OauthRequest>,
    pub error_uri: Option<url::Url>,
    pub msg: Option<String>,
}

impl Error {
    pub fn new(kind: ErrorKind) -> Self {
        Error {
            kind: kind,
            request: None,
            error_uri: None,
            msg: None,
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
    TemporarilyUnavailable,
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
            ErrorKind::TemporarilyUnavailable => "temporarily_unavailable",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.to_string().fmt(f)
    }
}

impl ErrorTrait for Error {
    fn description(&self) -> &str {
        match self.msg {
            Some(ref x) => x,
            None => self.kind.as_snake_case(),
        }
    }
    fn cause(&self) -> Option<&dyn ErrorTrait> {
        None
    }
}

impl<'r, 'o: 'r> Responder<'r, 'o> for Error {
    fn respond_to(self, _request: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        let mut redirect_uri = self
            .request
            .as_ref()
            .map(|req| req.redirect_uri.clone())
            .ok_or(Status::BadRequest)?;

        let mut params = collections::BTreeMap::new();
        params.insert("error".to_owned(), self.kind.as_snake_case().to_owned());
        self.msg
            .as_ref()
            .map(|x| params.insert("error_description".to_owned(), x.clone()));
        self.request.as_ref().map(|req| {
            req.state
                .as_ref()
                .map(|state| params.insert("state".to_owned(), state.clone()))
        });

        redirect_uri.set_fragment(Some(
            &url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(params)
                .finish(),
        ));

        Response::build()
            .status(Status::SeeOther)
            .raw_header("Location", redirect_uri.to_string())
            .ok()
    }
}
