// Generated using scripts/make_static.py. Do NOT edit directly!

use rocket::{Route, http::ContentType};
use rust_embed::RustEmbed;
use rocket::http::Method::Get;

#[derive(RustEmbed)]
#[folder = "src/static/"]
struct Asset;

pub fn generate_static_routes() -> Vec<Route> {
    let mut routes = Vec::<Route>::new();
    for file in Asset::iter() {
        let content_type = match file.split(".").last() {
            Some("css") => ContentType::CSS,
            Some("svg") => ContentType::SVG,
            _ => panic!("Unknown file type")
        };
        routes.push(
            Route::new(Get, "/" + file, |content_type, file| {
                (content_type, Asset::get(file))
            })
        )
    }
    routes
}
