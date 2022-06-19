use std::collections;
use std::path::PathBuf;

use rocket::State;
use rocket::fairing::AdHoc;
use rocket::http::ContentType;
use rocket::http::Status;
use rocket_dyn_templates::Template;

use serde_json;

use super::dashboard::icon_proxy;
use super::dashboard::oauth_entry_get;
use super::dashboard::oauth_entry_post;
use super::dashboard::rocket_uri_macro_oauth_entry_get;
use super::dashboard::user_dashboard;
use super::dashboard::user_dashboard_change_password;
use super::dashboard::user_dashboard_delete_app;
use super::login::user_login_get;
use super::login::user_login_post;
use super::login::user_logout;
use crate::config;

use super::staticfiles::static_route;
use super::storage::*;
use super::utils::SecurityHeaderMiddleware;

// Routes mounted on /

#[options("/<_..>")]
fn cors() -> (Status, (ContentType, String)) {
    (Status::Ok, (ContentType::Text, "".to_string()))
}

#[get("/")]
fn index() -> Template {
    Template::render("index", json!({}))
}

#[get("/.well-known/webfinger?<query..>")]
fn webfinger_response(
    config: &State<config::Config>,
    query: collections::BTreeMap<String, String>,
) -> (Status, (ContentType, String)) {
    let userid = match query.get("resource").and_then(|x| {
        if x.starts_with("acct:") {
            Some(&x[5..x.find('@').unwrap_or(x.len())])
        } else {
            None
        }
    }) {
        Some(o) => o,
        None => return (Status::Ok, (ContentType::Any, "".to_string())),
    };

    let storage_url = format!("https://{}{}", config.public_hostname, uri!(get_storage_root(userid = userid, path = "/")));
    let oauth_url = format!("https://{}{}", config.public_hostname, uri!(oauth_entry_get(userid, _, _, _)));

    let mut json = serde_json::Map::new();
    json.insert("links".to_owned(), {
        let mut rv = vec![];
        // We need to provide an older webfinger response because remoteStorage.js doesn't
        // support newer ones.
        // https://github.com/remotestorage/remotestorage.js/pull/899
        // https://github.com/silverbucket/webfinger.js/pull/11
        for &(rel, version) in &[
            (
                "http://tools.ietf.org/id/draft-dejong-remotestorage",
                "draft-dejong-remotestorage-20",
            ),
            ("remotestorage", "draft-dejong-remotestorage-02"),
        ] {
            rv.push(json!({
                "href": format!("{}", storage_url),
                "rel": rel,
                "properties": {
                    // Spec version
                    "http://remotestorage.io/spec/version": version,

                    // OAuth as in draft-06
                    "http://tools.ietf.org/html/rfc6749#section-4.2": format!("{}", oauth_url),

                    // No support for providing the access token via URL query param as in
                    // draft-06
                    "http://tools.ietf.org/html/rfc6750#section-2.3": (),

                    // No Content-Range as in draft-02
                    "http://tools.ietf.org/html/rfc2616#section-14.16": (),

                    // No Content-Range as in draft-06
                    "http://tools.ietf.org/html/rfc7233": (),

                    // No web authoring as in draft-06
                    "http://remotestorage.io/spec/web-authoring": ()
                }
            }));
        }
        serde_json::Value::Array(rv)
    });

    (
        Status::Ok,
        (
            ContentType::new("application", "jrd+json"),
            serde_json::to_string(&json).unwrap(),
        ),
    )
}

pub async fn run_server(rocket: rocket::Rocket<rocket::Build>) {
    let rocket_configuration: rocket::Config =
        rocket.figment().extract().expect("Wrong Rocket config");
    let app_configuration: config::Config = rocket.figment().extract().expect("Wrong app config");
    let rocket = rocket
        .mount(
            "/",
            routes![
                index,
                cors,
                webfinger_response,
                // /storage
                get_storage_root,
                put_storage_root,
                delete_storage_root,
                // /dashboard
                icon_proxy,
                user_dashboard,
                user_dashboard_delete_app,
                user_dashboard_change_password,
                user_login_get,
                user_login_post,
                user_logout,
                oauth_entry_get,
                oauth_entry_post,
            ],
        )
        .mount("/static/", routes![static_route])
        .attach(Template::fairing())
        .attach(SecurityHeaderMiddleware {})
        .attach(AdHoc::config::<rocket::Config>())
        .attach(AdHoc::config::<config::Config>())
        .manage(super::utils::CsrfChecker::new(&app_configuration));

    println!(
        "Listening on: http://{}:{}",
        rocket_configuration.address, rocket_configuration.port
    );

    let _result = rocket.launch().await.expect("Failed to launch");
}
