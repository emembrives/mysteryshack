use std::path;
use std::process;
use std::str::FromStr;

use sodiumoxide;

use clap::{Command, Arg};

use crate::config;
use crate::models;
use crate::web;
use crate::utils;


#[rocket::main]
async fn main() {
    let username_arg = Arg::with_name("USERNAME")
        .help("The username to perform the operation with.")
        .required(true)
        .index(1);

    let matches =
        Command::new("mysteryshack")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Markus Unterwaditzer & contributors")
        .about("A remoteStorage server.")
        .args_from_usage("-c, --config=[FILE] 'Use specified config file, defaults to ./config'")
        .setting(Command::subcommand_required)
        .subcommand(Command::with_name("serve")
                    .about("Start server"))
        .subcommand(Command::with_name("user")
                    .about("User management")
                    .setting(Command::subcommand_required)
                    .subcommand(Command::with_name("create")
                                .about("Create a new user")
                                .arg(username_arg.clone()))
                    .subcommand(Command::with_name("setpass")
                                .about("Change password for user")
                                .arg(username_arg.clone()))
                    .subcommand(Command::with_name("delete")
                                .about("Delete a user")
                                .arg(username_arg.clone()))
                    .subcommand(Command::with_name("authorize")
                                .about("Create a OAuth token. This is mostly useful for development.")
                                .arg(username_arg.clone())
                                .arg(Arg::with_name("days")
                                     .long("days")
                                     .help("How long the token should last. Use -1 for infinite. \
                                           Defaults to 180 days (~6 months)."))
                                .arg(Arg::with_name("CLIENT_ID").required(true).index(2))
                                .arg(Arg::with_name("SCOPE").required(true).index(3))))
        .get_matches();

    assert!(sodiumoxide::init());

    let config_path = path::Path::new(matches.value_of("config").unwrap_or("./config"));

    let config = match config::Config::read_file(config_path) {
        Ok(x) => x,
        Err(e) => {
            println!("Failed to parse config: {}", e);
            process::exit(1);
        }
    };

    clap_dispatch!(matches; {
        serve() => web::run_server(config),
        user(user_matches) => clap_dispatch!(user_matches; {
            create(_, USERNAME as username) => {
                if models::User::get(&config.main.data_path, username).is_some() {
                    println!("User already exists. Please delete the user first.");
                    process::exit(1);
                }

                let password_hash = models::PasswordHash::from_password(
                    utils::double_password_prompt("Password for new user: ").unwrap_or_else(|| process::exit(1)));

                match models::User::create(&config.main.data_path, username).map(|user| {
                    user.set_password_hash(password_hash)
                }) {
                    Ok(_) => (),
                    Err(e) => {
                        println!("Failed to create user {}: {}", username, e);
                        process::exit(1);
                    }
                };

                println!("Successfully created user {}", username);
            },
            setpass(_, USERNAME as username) => {
                let user = match models::User::get(&config.main.data_path, username) {
                    Some(x) => x,
                    None => {
                        println!("User does not exist: {}", username);
                        process::exit(1);
                    }
                };

                let password_hash = models::PasswordHash::from_password(
                    utils::double_password_prompt("New password: ").unwrap_or_else(|| process::exit(1)));
                match user.set_password_hash(password_hash) {
                    Ok(_) => (),
                    Err(e) => {
                        println!("Failed to set password for user {}: {}", username, e);
                        process::exit(1);
                    }
                };

                println!("Changed password for user {}", username);
            },
            delete(_, USERNAME as username) => {
                let user = match models::User::get(&config.main.data_path, username) {
                    Some(x) => x,
                    None => {
                        println!("User does not exist: {}", username);
                        process::exit(1);
                    }
                };

                println!("You are about to delete the user {} and ALL the user's user data. This
                         process is irreversible.", username);
                if !utils::prompt_confirm(format!("Do you want to delete the user {}?", username), false) {
                    println!("Aborted!");
                    process::exit(1);
                }

                match user.delete() {
                    Ok(_) => println!("Successfully deleted user {}.", username),
                    Err(e) => {
                        println!("Failed to delete user: {:?}", e);
                        process::exit(1);
                    }
                };
            },
            authorize(options, USERNAME as username, SCOPE as scope, CLIENT_ID as client_id) => {
                let days = {
                    let string = options.value_of("days").unwrap_or("180");
                    if string == "-1" {
                        None
                    } else {
                        match u64::from_str(string) {
                            Ok(x) => Some(x),
                            Err(e) => {
                                println!("Invalid parameter for --days: {}", e);
                                process::exit(1);
                            }
                        }
                    }
                };

                let user = match models::User::get(&config.main.data_path, username) {
                    Some(x) => x,
                    None => {
                        println!("User does not exist: {}", username);
                        process::exit(1);
                    }
                };

                let oauth_session = web::oauth::Session {
                    client_id: client_id.to_owned(),
                    permissions: match web::oauth::PermissionsMap::from_scope_string(scope) {
                        Some(x) => x,
                        None => {
                            println!("Invalid scope: {}", scope);
                            process::exit(1);
                        }
                    }
                };

                let (_, token) = models::Token::create(&user, oauth_session, days).unwrap();
                println!("{}", token.token(&user));
            }
        })
    });
}
