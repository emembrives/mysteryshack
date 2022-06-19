use rocket::form::Form;
use rocket::http::Status;
use rocket::request::{self, FromRequest};
use rocket::State;
use rocket::{
    http::{Cookie, CookieJar},
    outcome::Outcome,
    response::Redirect,
    Request,
};
use rocket_dyn_templates::{context, Template};

use crate::web::return_types::HttpResult;
use crate::{
    config::Config,
    models::{self, User},
    web::utils::{CsrfCheck, CsrfChecker},
};

pub struct UserLogin {
    pub userid: Option<String>,
    pub user: Option<User>,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for UserLogin {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let cookie_jar = req.cookies();
        let config = req
            .guard::<&'r State<Config>>()
            .await
            .expect("Unable to get config");
        let login_cookie = cookie_jar.get_private("login");
        if let Some(c) = login_cookie {
            let userid = c.value().to_owned();
            let user: Option<User> = User::get(&config.absolute_data_path(), &userid);
            return Outcome::Success(UserLogin {
                userid: Some(userid),
                user,
            });
        }
        return Outcome::Success(UserLogin {
            userid: None,
            user: None,
        });
    }
}

#[get("/dashboard/login?<prefill_user>&<redirect_to>")]
pub fn user_login_get(
    cookies: &CookieJar<'_>,
    csrf_checker: &State<CsrfChecker>,
    prefill_user: Option<&str>,
    redirect_to: Option<&str>,
) -> Template {
    let (token, cookie) = csrf_checker.generate();
    cookies.add(Cookie::new("csrf", cookie));
    return Template::render(
        "login",
        context! {
            prefill_user: prefill_user,
            redirect_to: redirect_to.unwrap_or("/dashboard/"),
            token: token,
        },
    );
}

// Data from the login form.
#[derive(FromForm)]
pub struct LoginForm<'r> {
    csrf: &'r str,
    user: &'r str,
    pass: &'r str,
    redirect_to: &'r str,
}

#[post("/dashboard/login", data = "<login_form>")]
pub fn user_login_post(
    config: &State<Config>,
    csrf_checker: &State<CsrfChecker>,
    jar: &CookieJar<'_>,
    login_form: Form<LoginForm<'_>>,
) -> HttpResult {
    let csrf_check = csrf_checker.verify(
        login_form.csrf,
        jar.get("csrf")
            .and_then(|c| Some(c.value()))
            .unwrap_or_default(),
    );

    match csrf_check {
        CsrfCheck::Invalid => {
            return Err(().into());
        }
        CsrfCheck::Verified => {}
    }

    let user =
        match models::User::get(&config.absolute_data_path(), login_form.user).and_then(|user| {
            user.get_password_hash().ok().and_then(|h| {
                if h.equals_password(login_form.pass.as_bytes()) {
                    Some(user)
                } else {
                    None
                }
            })
        }) {
            Some(u) => u,
            None => return Err(Status::Forbidden.into()),
        };

    jar.add_private(
        Cookie::build("login", user.userid)
            .secure(true)
            .http_only(true)
            .finish(),
    );

    Ok(Redirect::to(login_form.redirect_to.to_string()).into())
}

#[get("/dashboard/logout?<csrf_token>")]
pub fn user_logout(
    csrf_token: &str,
    csrf_checker: &State<CsrfChecker>,
    jar: &CookieJar<'_>,
) -> HttpResult {
    let csrf_check = csrf_checker.verify(
        csrf_token,
        jar.get("csrf")
            .and_then(|c| Some(c.value()))
            .unwrap_or_default(),
    );

    match csrf_check {
        CsrfCheck::Invalid => {
            return Err(().into());
        }
        CsrfCheck::Verified => {}
    }

    if let Some(login_cookie) = jar.get_private("login") {
        jar.remove_private(login_cookie);
    }

    Ok(Redirect::found(uri!("/")).into())
}
