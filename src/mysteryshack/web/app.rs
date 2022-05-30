use std::collections;
use std::io;
use std::fs;
use std::ops::Deref;
use std::error::Error;
use std::path::PathBuf;

use hyper::header;

use persistent;
use iron_sessionstorage::{Value,SessionStorage};
use iron_sessionstorage::backends::SignedCookieBackend;
use iron_sessionstorage::traits::*;

use rocket::Request;
use rocket::http::ContentType;
use rocket::http::Status;
use rocket::request;
use rocket::response::status;
use rocket_dyn_templates::Template;
use urlencoded;

use url;
use rand;
use webicon;

use serde_json;

use crate::models;
use crate::models::UserNode;
use crate::config;


use super::utils::{preconditions_ok,EtagMatcher,SecurityHeaderMiddleware,XForwardedMiddleware,FormDataHelper,get_account_id};
use super::oauth;
use super::oauth::HttpResponder;
use super::staticfiles::generate_static_routes;
use super::storage::*;

#[derive(Copy, Clone)]
pub struct AppConfig;
impl Key for AppConfig { type Value = config::Config; }

#[derive(Copy, Clone)]
pub struct AppLock;
impl Key for AppLock { type Value = (); }

macro_rules! require_login_as {
    ($req:expr, $expect_user:expr) => ({
        let login_redirect = Ok(Response::with((status::Found, Redirect({
            url_for!($req, "user_login",
                     "redirect_to" => $req.url.as_ref().as_str(),
                     "prefill_user" => $expect_user)
        }))));

        match $req.session().get::<Login>()?.map(|l| l.verify($req)) {
            Some(Login::Verified(user)) => {
                if $expect_user.len() == 0 || &user.userid[..] == $expect_user {
                    user
                }
                else { return login_redirect }
            },
            _ => return login_redirect
        }
    })
}

macro_rules! require_login { ($req:expr) => (require_login_as!($req, "")) }

macro_rules! check_csrf {
    ($req:expr) => ({
        let req = &$req;

        iexpect!(
            req.headers.get::<header::Referer>()
                .and_then(|s| url::Url::parse(s).ok())
                .and_then(|referer_u| {
                    let req_u: &url::Url = req.url.as_ref();
                    if referer_u.origin() == req_u.origin() { Some(()) }
                    else { None }
                }),
            (status::BadRequest, "CSRF detected.")
        )
    })
}

macro_rules! alert_tmpl {
    ($msg:expr, $back_to:expr) => ({
        Template::new("alert", json!({
            "msg": $msg,
            "back_to": $back_to
        }))
    })
}

struct ErrorPrinter;
impl iron::middleware::AfterMiddleware for ErrorPrinter {
    fn catch(&self, _: &mut Request, err: IronError) -> IronResult<Response> {
        println!("Server error: {:?}", err);
        Err(err)
    }
}

// Routes mounted on /

#[options("/<_..>")]
fn cors() -> Status { Status::Ok }

#[get("/")]
fn index() -> Template { 
    Template::render("index", json!({}))
}

#[get("/.well-known/webfinger?<query..>")]
fn webfinger_response(query: collections::BTreeMap<str, str>) -> (Status, (ContentType, String)) {
    let userid = match query.get("resource")
        .and_then(|x| if x.starts_with("acct:") {
            Some(&x[5..x.find('@').unwrap_or(x.len())])
        } else {
            None
        }) {
            Some(o) => o,
            None => return Status::Ok,
        };

    let storage_url = uri!(get_storage_root(userid=userid, path=()));
    let oauth_url = uri!(request, "oauth_entry", "userid" => userid);

    let mut json = serde_json::Map::new();
    json.insert("links".to_owned(), {
        let mut rv = vec![];
        // We need to provide an older webfinger response because remoteStorage.js doesn't
        // support newer ones.
        // https://github.com/remotestorage/remotestorage.js/pull/899
        // https://github.com/silverbucket/webfinger.js/pull/11
        for &(rel, version) in &[
            ("http://tools.ietf.org/id/draft-dejong-remotestorage", "draft-dejong-remotestorage-05"),
            ("remotestorage", "draft-dejong-remotestorage-02")
        ] {
            rv.push(json!({
                "href": storage_url.as_ref().as_str(),
                "rel": rel,
                "properties": {
                    // Spec version
                    "http://remotestorage.io/spec/version": version,

                    // OAuth as in draft-06
                    "http://tools.ietf.org/html/rfc6749#section-4.2": oauth_url.as_ref().as_str(),

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
        };
        serde_json::Value::Array(rv)
    });

    (Status::Ok,
        (ContentType::new("application", "jrd+json"),
        serde_json::to_string(&json).unwrap())
    )
}

struct UserLoginParams {
    
}
fn user_login(request: &mut Request) -> IronResult<Response> {
    let url = request.get_ref::<urlencoded::UrlEncodedQuery>().ok()
        .and_then(|query| query.get("redirect_to"))
        .and_then(|params| params.get(0))
        .and_then(|x| iron::Url::parse(x).ok())
        .unwrap_or_else(|| url_for!(request, "user_dashboard"));

    match request.method {
        Method::Get => {
            match try!(request.session().get::<Login>()).map(|l| l.verify(request)) {
                Some(Login::Verified(_)) => {
                    Ok(Response::with((status::Found, Redirect(url))))
                },
                _ => user_login_get(request)
            }
        },
        Method::Post => user_login_post(request, url),
        _ => Ok(Response::with(status::BadRequest))
    }
}

fn user_login_get(request: &mut Request) -> IronResult<Response> {
    let mut r = Response::with(status::Ok);
    r.headers.set(header::ContentType("text/html".parse().unwrap()));
    r.set_mut(Template::new("login", {
        let mut rv = serde_json::Map::new();
        request.get_ref::<urlencoded::UrlEncodedQuery>().ok()
            .and_then(|query| query.get("prefill_user"))
            .and_then(|params| params.get(0))
            .and_then(|x| rv.insert("prefill_user".to_owned(), serde_json::Value::String(x.to_owned())));
        serde_json::Value::Object(rv)
    }));
    Ok(r)
}

fn user_login_post(request: &mut Request, url: iron::Url) -> IronResult<Response> {
    check_csrf!(request);
    let config = request.get::<persistent::Read<AppConfig>>().unwrap();
    let data_path = &config.main.data_path;

    let (username, password) = {
        let formdata = itry!(request.get_ref::<urlencoded::UrlEncodedBody>());
        (
            &iexpect!(formdata.get("user"))[0].clone(),
            &iexpect!(formdata.get("pass"))[0].clone()
        )
    };

    let user = iexpect!(
        models::User::get(data_path, &username[..])
            .and_then(|user| user.get_password_hash().ok()
                      .and_then(|h| if h.equals_password(password) { Some(user) } else { None })),
        (status::Ok, "Wrong credentials.")
    );


    if &url.scheme() != &request.url.scheme() ||
            &url.host() != &request.url.host() ||
            &url.port() != &request.url.port() {
        return Ok(Response::with(status::BadRequest));
    }

    try!(request.session().set(Login::Verified(user)));

    Ok(Response::with(status::Ok)
       .set(status::Found)
       .set(Redirect(url)))
}

fn user_logout(request: &mut Request) -> IronResult<Response> {
    check_csrf!(request);
    try!(request.session().set(Login::Null));
    Ok(Response::with(status::Found)
       .set(Redirect(url_for!(request, "index"))))
}

#[get("/dashboard")]
fn user_dashboard(request: &mut Request) -> IronResult<Response> {
    let user = require_login!(request);

    let apps = user.walk_apps().unwrap_or_else(|_| vec![]);
    Ok(Response::with((
        status::Ok,
        Template::new("dashboard", json!({
            "account_id": get_account_id(&user, &request),
            "apps": apps.iter().map(|app| app.to_json()).collect::<Vec<_>>()
        }))
    )))
}

#[post("/dashboard/delete-app")]
fn user_dashboard_delete_app(request: &mut Request) -> IronResult<Response> {
    let user = require_login!(request);
    check_csrf!(request);

    let client_id = iexpect!(request.get_ref::<urlencoded::UrlEncodedBody>().ok()
                             .and_then(|q| q.get_only("client_id"))).clone();
    let app = iexpect!(models::App::get(&user, &client_id), status::NotFound);
    itry!(app.delete());
    Ok(Response::with((
        status::Found,
        Redirect(url_for!(request, "user_dashboard"))
    )))
}

#[post("/dashboard/change-password")]
fn user_dashboard_change_password(request: &mut Request) -> IronResult<Response> {
    static BACK_TO: &'static str = "/dashboard/#change-password";

    let user = require_login!(request);
    check_csrf!(request);
    
    let (current_pass, new_pass1, new_pass2, regen_key) = {
        let formdata = iexpect!(request.get_ref::<urlencoded::UrlEncodedBody>().ok());
        (
            iexpect!(formdata.get_only("current_pass")).clone(),
            iexpect!(formdata.get_only("new_pass1")).clone(),
            iexpect!(formdata.get_only("new_pass2")).clone(),
            formdata.get_only("regen_key").cloned()
        )
    };

    if new_pass1 != new_pass2 {
        return Ok(Response::with((
            status::Ok,
            alert_tmpl!("Typo in new password: Repeated new password doesn't match new password.
                         Do you have a typo somewhere?", BACK_TO)
        )));
    }

    if !itry!(user.get_password_hash()).equals_password(current_pass) {
        return Ok(Response::with((
            status::Ok,
            alert_tmpl!("Wrong current password.", BACK_TO)
        )));
    }

    let new_hash = models::PasswordHash::from_password(new_pass1);
    itry!(user.set_password_hash(new_hash));

    if let Some(x) = regen_key {
        assert_eq!(x, "yes");
        itry!(user.new_key());
    }

    Ok(Response::with((
        status::Ok,
        alert_tmpl!("Password successfully changed.", BACK_TO)
    )))
}

#[get("/dashboard/oauth/<oauth_userid>")]
fn oauth_entry(oauth_request: oauth::OauthRequest, oauth_userid: &str) -> IronResult<Response> {
    let user = require_login_as!(request, &oauth_userid[..]);
    let oauth_request = match oauth::OauthRequest::from_http(request) {
        Ok(x) => x,
        Err(e) => return Ok(
            e.get_response().unwrap_or_else(|| {
                Response::with(status::BadRequest)
                .set(Template::new("oauth_error", json!({
                    "e_msg": (e.description())
                })))
            })
        )
    };

    match request.method {
        Method::Get => Ok(Response::with(status::Ok).set(Template::new("oauth_entry", oauth_request))),
        Method::Post => {
            check_csrf!(request);
            let formdata = itry!(request.get_ref::<urlencoded::UrlEncodedBody>());
            let allow = iexpect!({
                match &iexpect!(formdata.get("decision"))[0][..] {
                    "allow" => Some(true),
                    "deny" => Some(false),
                    _ => None
                }
            });
            let days = {
                let string = &iexpect!(formdata.get("days"))[0];
                if string == "-1" {
                    None
                } else {
                    Some(iexpect!(u64::from_str(string).ok()))
                }
            };

            if allow {
                let (_, session) = itry!(models::Token::create(
                    &user,
                    oauth_request.session.clone().unwrap(),
                    days
                ));
                Ok(oauth_request.grant(session.token(&user)).get_response().unwrap())
            } else {
                Ok(oauth_request.reject().get_response().unwrap())
            }
        },
        _ => Ok(Response::with(status::BadRequest))
    }
}

trait UserNodeResponder where Self: Sized {
    fn respond(self, request: &mut Request) -> IronResult<Response> {
        match request.method {
            Method::Get => self.respond_get(request),
            Method::Put => if request.headers.get::<header::ContentRange>().is_some() {
                Ok(Response::with((
                    status::BadRequest,
                    "Content-Range is invalid on PUT, as per RFC 7231. See https://github.com/remotestorage/spec/issues/124"
                )))
            } else {
                self.respond_put(request)
            },
            Method::Delete => self.respond_delete(request),
            _ => Ok(Response::with(status::BadRequest))
        }
    }

    fn respond_get(self, request: &Request) -> IronResult<Response>;
    fn respond_put(self, _: &mut Request) -> IronResult<Response> {
        Ok(Response::with(status::BadRequest))
    }
    fn respond_delete(self, _: &Request) -> IronResult<Response> {
        Ok(Response::with(status::BadRequest))
    }
}

impl<'a> UserNodeResponder for models::UserFolder<'a> {
    fn respond_get(self, request: &Request) -> IronResult<Response> {
        let etag = self.read_etag().ok();
        // https://github.com/remotestorage/spec/issues/93
        let shown_etag = etag.unwrap_or("empty".to_owned());

        if let Some(header) = request.headers.get::<header::IfNoneMatch>() {
            if header.matches_etag(Some(&shown_etag[..])) {
                return Ok(Response::with(status::NotModified));
            }
        };
        let mut r = Response::with(status::Ok);

        r.headers.set(header::ContentType("application/ld+json".parse().unwrap()));
        r.headers.set(header::CacheControl(vec![header::CacheDirective::NoCache]));
        r.headers.set(header::AcceptRanges(vec![header::RangeUnit::None]));
        r.headers.set(header::ETag(header::EntityTag::new(false, shown_etag)));

        r.set_mut(json!({
            "@context": "http://remotestorage.io/spec/folder-description",
            "items": ({
                let mut d = collections::BTreeMap::new();
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
        }).to_string());
        Ok(r)
    }
}

impl<'a> UserNodeResponder for models::UserFile<'a> {
    fn respond_get(self, request: &Request) -> IronResult<Response> {
        let etag = self.read_etag().ok();

        if let Some(header) = request.headers.get::<header::IfNoneMatch>() {
            if header.matches_etag(etag.as_ref().map(Deref::deref)) {
                return Ok(Response::with(status::NotModified));
            }
        };

        let meta = match self.read_meta() {
            Ok(meta) => meta,
            Err(_) => return Ok(Response::with(status::NotFound))
        };

        let mut r = Response::with(status::Ok);

        r.headers.set(header::ContentType(meta.content_type.parse().unwrap()));
        r.headers.set(header::ETag(header::EntityTag::new(false, itry!(self.read_etag()))));
        r.headers.set(header::CacheControl(vec![header::CacheDirective::NoCache]));
        r.headers.set(header::AcceptRanges(vec![header::RangeUnit::None]));
        r.set_mut(itry!(self.open()));
        Ok(r)
    }

    fn respond_delete(self, request: &Request) -> IronResult<Response> {
        let etag = self.read_etag().ok();
        
        if !preconditions_ok(request, etag.as_ref().map(Deref::deref)) {
            return Ok(Response::with(status::PreconditionFailed));
        };

        if etag.is_none() {
            return Ok(Response::with(status::NotFound));
        }

        itry!(self.delete());
        Ok(Response::with(status::Ok))
    }

    fn respond_put(self, request: &mut Request) -> IronResult<Response> {
        let etag = self.read_etag().ok();

        if !preconditions_ok(request, etag.as_ref().map(Deref::deref)) {
            return Ok(Response::with(status::PreconditionFailed));
        };

        {
            let content_type = match request.headers.get::<header::ContentType>() {
                Some(x) => format!("{}", x),
                None => return Ok(Response::with((status::BadRequest, "Missing content type.")))
            };
            let local_file = match self.create() {
                Ok(x) => x,
                Err(_) => return Ok(Response::with(status::Conflict))
            };
            let content_length = match local_file.write(|mut f| {
                io::copy(&mut request.body, &mut f)
            }) {
                Ok(x) => x,
                Err(e) => {
                    if let Ok(metadata) = fs::metadata(self.get_fs_path()) {
                        if metadata.is_dir() {
                            return Ok(Response::with(status::Conflict))
                        }
                    };

                    itry!(Err(e))
                }
            };
            itry!(self.write_meta(models::UserFileMeta {
                content_type: content_type,
                content_length: content_length
            }));
        }

        Ok(Response::with((
            status::Created,
            Header(header::ETag(header::EntityTag::new(false, itry!(self.read_etag()))))
        )))
    }
}

enum Login {
    Verified(models::User),
    Unverified(String),
    Null,
}

impl Value for Login {
    fn get_key() -> &'static str { "logged_in_user" }
    fn into_raw(self) -> String {
        match self {
            Login::Verified(user) => user.userid,
            Login::Unverified(userid) => userid,
            Login::Null => "".to_owned()
        }
    }
    fn from_raw(value: String) -> Option<Self> {
        if value.is_empty() {
            None
        } else {
            Some(Login::Unverified(value))
        }
    }
}

impl Login {
    pub fn verify(self, request: &mut Request) -> Login {
        match self {
            Login::Unverified(ref userid) if !userid.is_empty() => {
                let config = request.get::<persistent::Read<AppConfig>>().unwrap();
                if let Some(x) = models::User::get(&config.main.data_path, userid) {
                    return Login::Verified(x);
                }
            },
            _ => ()
        };
        return self
    }
}

#[get("/dashboard/icon")]
fn icon_proxy(request: &mut Request) -> IronResult<Response> {
    require_login!(request);
    let url = iexpect!(request.get_ref::<urlencoded::UrlEncodedQuery>().ok()
        .and_then(|query| query.get("url"))
        .and_then(|params| params.get(0))
        .and_then(|x| url::Url::parse(x).ok())
        .and_then(|url| url.join("/").ok()));

    let mut parser = webicon::IconScraper::from_http(url);
    let mut icon = iexpect!(
        parser.fetch_icons().at_least(128, 128),
        (
            status::Ok,
            Header(header::ContentType("image/svg+xml".parse().unwrap())),
            &include_bytes!("../../static/app.svg")[..],
        )
    );
    itry!(icon.fetch());
    Ok(Response::with((status::Ok, icon.mime_type.unwrap(), icon.raw.unwrap())))
}

pub fn run_server(config: config::Config) {
    let rocket_builder = rocket::build()
        .mount("/", vec![index, cors, webfinger_response,
            // /storage
            get_storage_root, put_storage_root, delete_storage_root, 
            // /dashboard
            icon_proxy, user_dashboard, user_dashboard_delete_app, user_dashboard_change_password, user_login, user_logout, oauth_entry])
        .mount("/static/", generate_static_routes)
        .attach(Template::fairing())
        .manage(config.clone())
        .manage(AppLock{});

    let router = myrouter! {
        get "/dashboard/icon" => icon_proxy,
        get "/dashboard/" => user_dashboard,
        post "/dasboard/delete-app" => user_dashboard_delete_app,
        post "/dashboard/change-password" => user_dashboard_change_password,
        any "/dashboard/login/" => user_login,
        any "/dashboard/logout/" => user_logout,
        any "/dashboard/oauth/:userid/" => oauth_entry,

        get "/" => index
    };


    let mut chain = Chain::new(mount);
    if config.main.use_proxy_headers { chain.link_before(XForwardedMiddleware); }
    chain.link(persistent::Read::<AppConfig>::both(config.clone()));
    chain.link(persistent::State::<AppLock>::both(()));
    chain.around(SessionStorage::new({
        let mut rv = SignedCookieBackend::new({
            println!("Generating session keys...");
            let mut rng = rand::rngs::OsRng::new().unwrap();
            rng.gen_iter::<u8>().take(64).collect()
        });
        rv.set_cookie_modifier(|mut cookie| {
            cookie.path = Some("/dashboard/".to_owned());
            cookie
        });
        rv
    }));

    let mut error_router = error_router::ErrorRouter::new();
    error_router.modifier_for_status(status::NotFound, (
        status::NotFound,
        alert_tmpl!("Error 404, content not found.", "/"),
    ));
    error_router.modifier_for_status(status::InternalServerError, (
        status::InternalServerError,
        alert_tmpl!("Error 500, internal server error.", "/"),
    ));

    chain.link_after(error_router);
    chain.link_after(get_template_engine());
    chain.link_after(SecurityHeaderMiddleware);
    chain.link_after(ErrorPrinter);

    let listen = &config.main.listen[..];
    println!("Listening on: http://{}", listen);
    Iron::new(chain).http(listen).unwrap();
}
