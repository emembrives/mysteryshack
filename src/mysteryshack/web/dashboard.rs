use rocket::form::{Form, FromForm};
use rocket::http::Status;
use rocket::http::{Cookie, CookieJar};
use rocket::response::Redirect;
use rocket::State;
use rocket_dyn_templates::{context, Template};

use crate::alert_tmpl;
use crate::config::Config;
use crate::web::oauth;
use crate::web::return_types::{HttpError, HttpResult};
use crate::{
    models,
    web::utils::{CsrfCheck, CsrfChecker},
};

use super::login::{rocket_uri_macro_user_login_get, UserLogin};
use super::oauth::OauthRequest;

#[get("/dashboard")]
pub fn user_dashboard(user_login: UserLogin, config: &State<Config>) -> HttpResult {
    let user = match user_login.user {
        Some(u) => u,
        None => {
            return Ok(Redirect::found(uri!(user_login_get(
                prefill_user = user_login.userid.as_ref(),
                redirect_to = Some("/dashboard")
            )))
            .into())
        }
    };

    let apps = user.walk_apps().unwrap_or_else(|_| vec![]);
    Ok(Template::render(
        "dashboard",
        json!({
            "account_id": format!("{}@{}", &user.userid, config.public_hostname),
            "apps": apps.iter().map(|app| app.to_json()).collect::<Vec<_>>()
        }),
    )
    .into())
}

#[derive(FromForm)]
pub struct DeleteAppForm<'r> {
    csrf: &'r str,
    client_id: &'r str,
}
#[post("/dashboard/delete-app", data = "<data>")]
pub fn user_dashboard_delete_app(
    user_login: UserLogin,
    csrf_checker: &State<CsrfChecker>,
    jar: &CookieJar<'_>,
    data: Form<DeleteAppForm<'_>>,
) -> HttpResult {
    let user = match user_login.user {
        Some(u) => u,
        None => {
            return Ok(Redirect::found(uri!(user_login_get(
                prefill_user = user_login.userid.as_ref(),
                redirect_to = Some("/dashboard")
            )))
            .into())
        }
    };
    let csrf_check = csrf_checker.verify(
        data.csrf,
        jar.get("csrf").and_then(|c| Some(c.value())).unwrap_or(""),
    );
    match csrf_check {
        CsrfCheck::Invalid => {
            return Err(Status::BadRequest.into());
        }
        CsrfCheck::Verified => {}
    }

    let app = match models::App::get(&user, &data.client_id) {
        Some(app) => app,
        None => return Err(Status::NotFound.into()),
    };

    if app.delete().is_err() {
        return Err(Status::InternalServerError.into());
    }
    Ok(Redirect::found(uri!(user_dashboard())).into())
}

#[derive(FromForm)]
pub struct ChangePasswordForm<'r> {
    csrf: &'r str,
    current_password: &'r str,
    new_password1: &'r str,
    new_password2: &'r str,
    regen_key: Option<&'r str>,
}
#[post("/dashboard/change-password", data = "<data>")]
pub fn user_dashboard_change_password(
    user_login: UserLogin,
    csrf_checker: &State<CsrfChecker>,
    jar: &CookieJar<'_>,
    data: Form<ChangePasswordForm<'_>>,
) -> HttpResult {
    static BACK_TO: &'static str = "/dashboard/#change-password";

    let user = match user_login.user {
        Some(user) => user,
        None => {
            return Ok(Redirect::found(uri!(user_login_get(
                prefill_user = user_login.userid.as_ref(),
                redirect_to = Some("/dashboard")
            )))
            .into())
        }
    };

    let csrf_check = csrf_checker.verify(
        data.csrf,
        jar.get("csrf").and_then(|c| Some(c.value())).unwrap_or(""),
    );
    match csrf_check {
        CsrfCheck::Invalid => {
            return Err(Status::BadRequest.into());
        }
        CsrfCheck::Verified => {}
    }

    if data.new_password1 != data.new_password2 {
        return Ok(alert_tmpl!(
            "Typo in new password: Repeated new password doesn't match new password.
                         Do you have a typo somewhere?",
            BACK_TO
        )
        .into());
    }

    let user_pass_hash = match user.get_password_hash() {
        Ok(h) => h,
        Err(_) => return Err(Status::InternalServerError.into()),
    };
    if !user_pass_hash.equals_password(data.current_password.as_bytes()) {
        return Ok(alert_tmpl!("Wrong current password.", BACK_TO).into());
    }

    let new_hash = models::PasswordHash::from_password(data.new_password1);
    if let Err(_) = user.set_password_hash(new_hash) {
        return Err(Status::InternalServerError.into());
    }

    if let Some(x) = data.regen_key {
        assert_eq!(x, "yes");
        if let Err(_) = user.new_key() {
            return Err(Status::InternalServerError.into());
        }
    }

    Ok(alert_tmpl!("Password successfully changed.", BACK_TO).into())
}

#[get("/dashboard/oauth/<oauth_userid>?<redirect_uri>&<state>&<scope>")]
pub fn oauth_entry_get(
    cookies: &CookieJar<'_>,
    csrf_checker: &State<CsrfChecker>,
    user_login: UserLogin,
    oauth_userid: &str,
    redirect_uri: Option<String>,
    state: Option<String>,
    scope: Option<String>,
) -> HttpResult {
    println!(
        "logged user: {:?} ; requested user: {:?}",
        user_login
            .user
            .as_ref()
            .unwrap_or(&models::User {
                user_path: "".to_owned().into(),
                userid: "".to_owned()
            })
            .userid,
        oauth_userid
    );
    if user_login.user.is_none() || user_login.user.as_ref().unwrap().userid != oauth_userid {
        return Ok(Redirect::found(uri!(user_login_get(
            prefill_user = user_login.userid.as_ref(),
            redirect_to =
                Some(uri!(oauth_entry_get(oauth_userid, redirect_uri, state, scope)).to_string())
        )))
        .into());
    }

    let (token, cookie) = csrf_checker.generate();
    cookies.add(Cookie::new("csrf", cookie));
    let oauth_request = oauth::OauthRequest::new(redirect_uri, state, scope)?;
    return Ok(Template::render(
        "oauth_entry",
        context! {
            client_id: &oauth_request.session.as_ref().ok_or(HttpError::GenericError)?.client_id,
            permissions: &oauth_request.session.as_ref().ok_or(HttpError::GenericError)?.permissions.permissions,
            token: token,
        },
    )
    .into());
}

#[derive(FromForm)]
pub struct OauthForm<'r> {
    csrf: &'r str,
    decision: &'r str,
    days: Option<u64>,
}

#[post(
    "/dashboard/oauth/<oauth_userid>?<redirect_uri>&<state>&<scope>",
    data = "<data>"
)]
pub fn oauth_entry_post(
    user_login: UserLogin,
    oauth_userid: &str,
    redirect_uri: Option<String>,
    state: Option<String>,
    scope: Option<String>,
    csrf_checker: &State<CsrfChecker>,
    jar: &CookieJar<'_>,
    data: Form<OauthForm>,
) -> HttpResult {
    if user_login.user.is_none() || user_login.user.as_ref().unwrap().userid != oauth_userid {
        return Ok(Redirect::found(uri!(user_login_get(
            prefill_user = user_login.userid.as_ref(),
            redirect_to = Some(format!("/dashboard/oauth/{}", oauth_userid))
        )))
        .into());
    }

    let user = user_login.user.unwrap();

    let csrf_check = csrf_checker.verify(
        data.csrf,
        jar.get("csrf")
            .and_then(|c| Some(c.value()))
            .unwrap_or_default(),
    );
    match csrf_check {
        CsrfCheck::Invalid => {
            return Err(Status::BadRequest.into());
        }
        CsrfCheck::Verified => {}
    }

    let oauth_request = OauthRequest::new(redirect_uri, state, scope)?;

    let allow = data.decision == "allow";

    let days = data.days;

    if allow {
        let (_, session) =
            models::Token::create(&user, oauth_request.session.clone().unwrap(), days)?;
        Ok(oauth_request.grant(session.token(&user)).into())
    } else {
        Err(oauth_request.reject().into())
    }
}

#[get("/dashboard/icon?<query_url>")]
pub async fn icon_proxy(user_login: UserLogin, query_url: &str) -> HttpResult {
    match &user_login.user {
        Some(_) => {}
        None => {
            return Ok(Redirect::found(uri!(user_login_get(
                prefill_user = user_login.userid.as_ref(),
                redirect_to = Some("/dashboard")
            )))
            .into())
        }
    };

    let url = match url::Url::parse(query_url)
        .ok()
        .and_then(|url| url.join("/").ok())
    {
        Some(u) => u,
        None => return Err(Status::BadRequest.into()),
    };

    get_icon(url).await
}

async fn get_icon(url: url::Url) -> HttpResult {
    let collection = webicon::IconScraper::fetch_icons(url).await;

    let mut icon = match collection.at_least(128, 128) {
        Some(i) => i,
        None => return Err(Status::NotFound.into()),
    };
    if icon.fetch().await.is_err() {
        return Err(Status::NotFound.into());
    }
    Ok(icon.into())
}
