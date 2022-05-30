#![cfg_attr(feature = "clippy", allow(unstable_features))]
#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]
#![cfg_attr(feature = "clippy", deny(warnings))]

extern crate serde;
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate serde_json;

extern crate base64;

extern crate toml;
extern crate unicase;
extern crate atomicwrites;
extern crate url;
extern crate urlencoded;
extern crate clap;
#[macro_use] extern crate please_clap;
extern crate sodiumoxide;
extern crate rand;
extern crate handlebars;
extern crate mount;
extern crate regex;
#[macro_use] extern crate quick_error;
extern crate time;
extern crate filetime;
extern crate chrono;
extern crate nix;
extern crate webicon;
extern crate termion;
#[macro_use] extern crate rocket;

#[cfg(test)]
extern crate tempdir;

mod utils;
pub mod cli;
mod web;
mod models;
mod config;
