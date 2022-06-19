use std::str::FromStr;

use crate::utils::ServerError;
use rocket::{
    http::{Status, ContentType},
    response::{Redirect, Responder},
};
use rocket_dyn_templates::Template;
use webicon::Icon;

use super::oauth::{self, Grant};

pub type HttpResult = Result<ReturnType, HttpError>;

pub enum HttpError {
    GenericError,
    StatusError(Status),
    OauthError(oauth::Error),
    ServerError(ServerError),
}

impl<'r, 'o: 'r> Responder<'r, 'o> for HttpError {
    fn respond_to(self, request: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        match self {
            HttpError::GenericError => Status::InternalServerError.respond_to(request),
            HttpError::StatusError(s) => s.respond_to(request),
            HttpError::OauthError(s) => s.respond_to(request),
            HttpError::ServerError(_) => Status::InternalServerError.respond_to(request),
        }
    }
}

impl From<()> for HttpError {
    fn from(_status: ()) -> Self {
        HttpError::GenericError
    }
}

impl From<Status> for HttpError {
    fn from(status: Status) -> Self {
        HttpError::StatusError(status)
    }
}

impl From<oauth::Error> for HttpError {
    fn from(error: oauth::Error) -> Self {
        HttpError::OauthError(error)
    }
}

impl From<ServerError> for HttpError {
    fn from(error: ServerError) -> Self {
        HttpError::ServerError(error)
    }
}

pub enum ReturnType {
    Redirect(Redirect),
    Template(Template),
    Grant(Grant),
    Icon(Icon),
}

impl<'r, 'o: 'r> Responder<'r, 'o> for ReturnType {
    fn respond_to(self, request: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        match self {
            ReturnType::Redirect(r) => r.respond_to(request),
            ReturnType::Template(t) => t.respond_to(request),
            ReturnType::Grant(g) => g.respond_to(request),
            ReturnType::Icon(icon) => (
                ContentType::from_str(&icon.mime_type.unwrap().to_string()).unwrap(),
                icon.raw.unwrap(),
            )
                .respond_to(request),
        }
    }
}

impl From<Redirect> for ReturnType {
    fn from(v: Redirect) -> Self {
        ReturnType::Redirect(v)
    }
}

impl From<Template> for ReturnType {
    fn from(v: Template) -> Self {
        ReturnType::Template(v)
    }
}

impl From<Grant> for ReturnType {
    fn from(v: Grant) -> Self {
        ReturnType::Grant(v)
    }
}

impl From<Icon> for ReturnType {
    fn from(v: Icon) -> Self {
        ReturnType::Icon(v)
    }
}
