use std::path::PathBuf;

use rocket::request::{FromRequest, Outcome};
use rocket::{Request, State};

use crate::models;
use crate::web::app::{AppLock, AppConfig};

// Routes mounted on /storage
struct AuthorizationBearer {
    token: Option<String>
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthorizationBearer {
    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let auth_header = req.headers().get("Authentication");
        match auth_header.find(|&e| {
            e.starts_with("Bearer ")
        }) {
            Some(bearer) => Outcome::Success(Some(bearer.strip_prefix("Bearer ").unwrap().clone())),
            None => Outcome::Success(None)
        }
    }
}

#[get("/storage/<userid>/<path..>")]
pub fn get_storage_root(config: &State<AppConfig>, applock: &State<AppLock>,
    bearer_token: AuthorizationBearer,
    method: rocket::http::Method, userid: &str, path: PathBuf) -> Result<(), rocket::http::Status> {
        user_node_response(config, applock, bearer_token,
            rocket::http::Method::Get, userid, path)
    }

#[put("/storage/<userid>/<path..>")]
pub fn put_storage_root(config: &State<AppConfig>, applock: &State<AppLock>,
    bearer_token: AuthorizationBearer,
    method: rocket::http::Method, userid: &str, path: PathBuf) -> Result<(), rocket::http::Status> {
        user_node_response(config, applock, bearer_token,
            rocket::http::Method::Put, userid, path)
    }

#[delete("/storage/<userid>/<path..>")]
pub fn delete_storage_root(config: &State<AppConfig>, applock: &State<AppLock>,
    bearer_token: AuthorizationBearer,
    method: rocket::http::Method, userid: &str, path: PathBuf) -> Result<(), rocket::http::Status> {
        user_node_response(config, applock, bearer_token,
            rocket::http::Method::Delete, userid, path)
    }

fn user_node_response(config: &State<AppConfig>, applock: &State<AppLock>,
    bearer_token: AuthorizationBearer,
    method: rocket::http::Method, userid: &str, path: PathBuf) -> Result<(), rocket::http::Status> {
    let write_operation = match method {
        rocket::http::Method::Get | rocket::http::Method::Head => false,
        _ => true
    };

    let data_path = &config.main.data_path;

    let user = match models::User::get(data_path, &userid[..]) {
        Some(x) => x,
        None => return Err(rocket::response::status::Forbidden)
    };

    let access_token = bearer_token.token;
    
    let path_str = *path.to_str().unwrap();
    let permissions = user.permissions(&path_str[..], access_token.as_ref().map(Deref::deref));

    if !permissions.can_read || (write_operation && !permissions.can_write) {
        return Err(rocket::response::status::Forbidden)
    }

    let lock = applock.unwrap().clone();
    let _guard = if write_operation {
        (None, Some(lock.write().unwrap()))
    } else {
        (Some(lock.read().unwrap()), None)
    };

    if path_str.is_empty() || path_str.ends_with('/') {
        match models::UserFolder::from_path(&user, &path_str[..]) {
            Some(x) => x.respond(req),
            None => Err(rocket::response::status::BadRequest)
        }
    } else {
        match models::UserFile::from_path(&user, &path_str[..]) {
            Some(x) => x.respond(req),
            None => Err(rocket::response::status::BadRequest)
        }
    }
}
