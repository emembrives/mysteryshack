// Generated using scripts/make_static.py. Do NOT edit directly!

use std::borrow::Cow;

use rocket::http::{ContentType, Status};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "src/static/"]
struct Asset;

#[get("/<filename>")]
pub fn static_route<'a>(filename: &'a str) -> Result<(ContentType, Cow<'static, [u8]>), Status> {
    let asset = match Asset::get(&filename) {
        Some(a) => a,
        None => return Err(Status::NotFound),
    };

    let content_type = match filename.split(".").last() {
        Some("css") => ContentType::CSS,
        Some("svg") => ContentType::SVG,
        _ => panic!("Unknown file type"),
    };

    Ok((content_type, asset.data.to_owned()))
}
