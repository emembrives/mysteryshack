use std::fs;
use std::io;
use std::io::Read;
use std::io::Write;
use std::path;

use crate::models;
use atomicwrites;


use url;

use serde::Serialize;
use serde_json;
use toml;

use termion::input::TermRead;
use termion::raw::IntoRawMode;

quick_error! {
    // FIXME: https://github.com/tailhook/quick-error/issues/3
    #[derive(Debug)]
    pub enum ServerError {
        Io(error: io::Error) {
            display("{}", error)
            source(error)
            from()
        }
        Json(error: serde_json::Error) {
            display("{}", error)
            source(error)
            from()
        }
        Config(error: toml::de::Error) {
            display("{}", error)
            source(error)
            from()
        }
        Model(error: models::Error) {
            display("{}", error)
            source(error)
            from()
        }
    }
}

pub fn safe_join<P: AsRef<path::Path>, Q: AsRef<path::Path>>(
    base: P,
    user_input: Q,
) -> Option<path::PathBuf> {
    let a = base.as_ref();
    let b = user_input.as_ref();

    let rv = a.join(b);
    if rv.starts_with(a) && rv.is_absolute() {
        Some(rv)
    } else {
        None
    }
}

pub fn prompt<T: AsRef<str>>(text: T) -> String {
    let mut stdout = io::stdout();
    stdout.write_all(text.as_ref().as_bytes()).unwrap();
    stdout.flush().unwrap();

    let stdin = io::stdin();
    let mut response = String::new();
    stdin.read_line(&mut response).unwrap();
    if response.ends_with('\n') {
        response.pop();
    }
    response
}

pub fn double_password_prompt<T: AsRef<str>>(text: T) -> Option<String> {
    let stdin = io::stdin();
    let mut stdin = stdin.lock();
    let stdout = io::stdout();
    let mut stdout = stdout.lock();

    let again_text = {
        let mut x = "(repeat to confirm) ".to_owned();
        x.push_str(text.as_ref());
        x
    };

    fn read_passwd<R: Read, W: Write>(
        reader: &mut R,
        writer: &mut W,
    ) -> io::Result<Option<String>> {
        let _raw = writer.into_raw_mode();
        reader.read_line()
    }

    macro_rules! p {
        ($text:expr) => {{
            stdout.write_all($text).unwrap();
            stdout.flush().unwrap();
            let result = read_passwd(&mut stdin, &mut stdout);
            stdout.write_all(b"\n").unwrap();

            match result {
                Ok(Some(x)) => {
                    if x.len() == 0 {
                        println!("Empty input.");
                        return None;
                    } else {
                        x
                    }
                }
                _ => return None,
            }
        }};
    }

    let first = p!(text.as_ref().as_bytes());
    let second = p!(again_text.as_bytes());

    if first != second {
        println!("Inputs don't match.");
        return None;
    };

    Some(first)
}

pub fn prompt_confirm<T: AsRef<str>>(question: T, default: bool) -> bool {
    let mut question = question.as_ref().to_owned();
    question.push_str(" ");
    question.push_str(if default { "[Y/n]" } else { "[y/N]" });
    question.push_str(" ");
    loop {
        let response = prompt(&question[..]);
        return match response.trim() {
            "y" | "Y" => true,
            "n" | "N" => false,
            "" => default,
            _ => {
                println!("Invalid answer.");
                continue;
            }
        };
    }
}

pub fn read_json_file<'a, P: AsRef<path::Path>, T: for<'de> serde::Deserialize<'de>>(
    p: P,
) -> Result<T, ServerError> {
    let mut f = fs::File::open(p.as_ref())?;
    Ok(serde_json::from_reader(&mut f)?)
}

pub fn write_json_file<T: Serialize, P: AsRef<path::Path>>(t: T, p: P) -> Result<(), ServerError> {
    let f = atomicwrites::AtomicFile::new(p, atomicwrites::AllowOverwrite);
    match f.write(|f| serde_json::to_writer(f, &t)) {
        Ok(_) => Ok(()),
        Err(atomicwrites::Error::User(e)) => Err(ServerError::Json(e)),
        Err(atomicwrites::Error::Internal(e)) => Err(ServerError::Io(e)),
    }
}

/// Apply a function to each parent directory of given file `f_path`, stops at folder path `until`.
///
/// The function's Ok-value indicates whether mapping should continue.
pub fn map_parent_dirs<F, A, B>(f_path: A, until: B, f: F) -> io::Result<()>
where
    F: Fn(&path::Path) -> io::Result<bool>,
    A: AsRef<path::Path>,
    B: AsRef<path::Path>,
{
    let mut cur_dir = f_path.as_ref();
    let stop = until.as_ref();

    loop {
        cur_dir = match cur_dir.parent() {
            Some(x) => x,
            None => break,
        };

        if !cur_dir.starts_with(stop) && cur_dir != stop {
            break;
        }

        if !f(cur_dir)? {
            break;
        }
    }

    Ok(())
}

pub fn format_origin(u: &url::Url) -> String {
    // FIXME: Ugly
    let origin = u.origin();
    if !origin.is_tuple() {
        panic!("Invalid URL: {:?}", u);
    }
    origin.ascii_serialization()
}
