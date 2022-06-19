use std::fs;
use std::io;
use std::io::Read;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path;

use argon2::password_hash::SaltString;
use argon2::Argon2;
use argon2::PasswordHasher;
use argon2::PasswordVerifier;
use atomicwrites;
use base64;
use chrono;
use filetime;
use hmac::digest::crypto_common::KeySizeUser;
use hmac::digest::typenum::Unsigned;
use hmac::Hmac;
use hmac::Mac;
use nix::errno;
use rand;
use rand::distributions::Alphanumeric;
use rand::Rng;
use rand::RngCore;
use regex;
use serde_json;
use sha3::Sha3_256;
use url;

use crate::utils;
use crate::utils::ServerError;
use crate::web::oauth::{CategoryPermissions, PermissionsMap, Session as OauthSession};

type HmacSha256 = Hmac<Sha3_256>;
const HMAC_KEY_SIZE: usize = <HmacSha256 as KeySizeUser>::KeySize::USIZE;
type HmacKey = [u8; HMAC_KEY_SIZE];

pub fn is_safe_identifier(string: &str) -> bool {
    regex::Regex::new(r"^[A-Za-z0-9_-]+$")
        .unwrap()
        .is_match(string)
}

quick_error! {
    #[derive(Debug)]
    pub enum Error {
        InvalidUserName {
            display("Invalid chars in username. Allowed are numbers (0-9), letters (a-zA-Z), \
                        `_` and `-`.")
        }
        AlreadyExisting {
            display("Resource already exists.")
        }
        InvalidPath {
            display("Invalid path")
        }
    }
}

pub struct User {
    pub user_path: path::PathBuf,
    pub userid: String,
}

impl User {
    fn new_unchecked(basepath: &path::Path, userid: &str) -> Result<User, Error> {
        assert!(basepath.is_absolute());
        if is_safe_identifier(userid) {
            Ok(User {
                user_path: basepath.join(userid.to_owned()),
                userid: userid.to_owned(),
            })
        } else {
            Err(Error::InvalidUserName)
        }
    }

    pub fn get(basepath: &path::Path, userid: &str) -> Option<User> {
        User::new_unchecked(basepath, userid).ok().and_then(|user| {
            match fs::metadata(user.user_info_path()) {
                Ok(ref x) if x.is_file() => Some(user),
                _ => None,
            }
        })
    }

    pub fn create(basepath: &path::Path, userid: &str) -> Result<User, ServerError> {
        let user = User::new_unchecked(basepath, userid)?;
        if user.user_path.exists() {
            return Err(Error::AlreadyExisting.into());
        };

        fs::create_dir_all(user.data_path())?;
        fs::create_dir_all(user.meta_path())?;
        fs::create_dir_all(user.tmp_path())?;
        fs::create_dir_all(user.apps_path())?;
        fs::File::create(user.user_info_path())?;
        user.new_key()?;
        Ok(user)
    }

    pub fn delete(self) -> io::Result<()> {
        fs::remove_dir_all(self.user_path)?;
        Ok(())
    }

    pub fn get_password_hash(&self) -> Result<PasswordHash, ServerError> {
        let mut f = fs::File::open(self.password_path())?;
        let mut x: Vec<u8> = vec![];
        f.read_to_end(&mut x)?;
        Ok(PasswordHash::from_hash(&x))
    }

    pub fn set_password_hash(&self, hash: PasswordHash) -> io::Result<()> {
        let f = atomicwrites::AtomicFile::new(self.password_path(), atomicwrites::AllowOverwrite);
        f.write(|f| f.write_all(&hash.content.as_bytes()[..]))?;
        Ok(())
    }

    fn user_info_path(&self) -> path::PathBuf {
        self.user_path.join("user.json")
    }
    fn password_path(&self) -> path::PathBuf {
        self.user_path.join("password")
    }
    pub fn data_path(&self) -> path::PathBuf {
        self.user_path.join("data/")
    }
    pub fn meta_path(&self) -> path::PathBuf {
        self.user_path.join("meta/")
    }
    pub fn tmp_path(&self) -> path::PathBuf {
        self.user_path.join("tmp/")
    }
    pub fn apps_path(&self) -> path::PathBuf {
        self.user_path.join("apps/")
    }

    pub fn key_path(&self) -> path::PathBuf {
        self.user_path.join("user.key")
    }

    pub fn walk_apps(&self) -> io::Result<Vec<App>> {
        let mut rv = vec![];
        for entry in fs::read_dir(self.apps_path())? {
            let entry = entry?;
            if entry.metadata()?.is_dir() {
                rv.push(App::get(self, &entry.file_name().into_string().unwrap()).unwrap());
            };
        }
        Ok(rv)
    }

    pub fn permissions(&self, path: &str, token: Option<&str>) -> CategoryPermissions {
        let anonymous = CategoryPermissions {
            can_read: path.starts_with("public/") && !path.ends_with('/'),
            can_write: false,
        };

        let (_, session) = match token.and_then(|t| Token::get(self, t)) {
            Some(x) => x,
            None => {
                return anonymous
            },
        };

        let category = {
            let mut rv = path.splitn(2, '/').nth(0).unwrap();
            if rv == "public" {
                rv = path.splitn(3, '/').nth(1).unwrap();
            }
            rv
        };

        *session
            .permissions
            .permissions_for_category(category)
            .unwrap_or_else(|| {
                &anonymous
            })
    }

    pub fn get_key(&self) -> HmacKey {
        let mut f = fs::File::open(self.key_path()).unwrap();
        let mut s = vec![];
        f.read_to_end(&mut s).unwrap();
        s.try_into().unwrap()
    }

    pub fn new_key(&self) -> io::Result<()> {
        let mut key: HmacKey = [0; HMAC_KEY_SIZE];
        rand::rngs::OsRng::default().fill_bytes(&mut key);
        let f = atomicwrites::AtomicFile::new(self.key_path(), atomicwrites::AllowOverwrite);
        f.write(|f| f.write_all(&key))?;

        for app in self.walk_apps()? {
            app.delete()?;
        }

        Ok(())
    }
}

pub struct App<'a> {
    pub client_id: String,
    pub app_id: String,
    pub user: &'a User,
}

impl<'a> App<'a> {
    // for passing to template
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "client_id": self.client_id,
            "app_id": self.app_id
        })
    }

    fn get_path(u: &User, client_id: &str) -> path::PathBuf {
        u.apps_path().join(client_id.replace("/", ""))
    }

    fn normalize_client_id(client_id: &str) -> String {
        let u = url::Url::parse(client_id).unwrap();
        utils::format_origin(&u)
    }

    pub fn get(u: &'a User, client_id: &str) -> Option<App<'a>> {
        let p = App::get_path(u, client_id).join("app_id");
        let mut f = match fs::File::open(p) {
            Ok(x) => x,
            Err(_) => return None,
        };

        let app_id = {
            let mut rv = String::new();
            match f.read_to_string(&mut rv) {
                Ok(_) => (),
                Err(_) => return None,
            };
            rv
        };

        Some(App {
            user: u,
            client_id: App::normalize_client_id(client_id),
            app_id: app_id,
        })
    }

    pub fn delete(&self) -> io::Result<()> {
        fs::remove_dir_all(App::get_path(self.user, &self.client_id))
    }

    pub fn create(u: &'a User, client_id: &str) -> Result<App<'a>, io::Error> {
        let app_id: String = {
            let mut rng = rand::rngs::OsRng::default();
            (0..64).map(|_| rng.sample(Alphanumeric) as char).collect()
        };

        let p = App::get_path(u, client_id);
        fs::create_dir_all(&p)?;

        let f = atomicwrites::AtomicFile::new(p.join("app_id"), atomicwrites::DisallowOverwrite);

        f.write(|f| f.write_all(app_id.as_bytes()))?;

        Ok(App {
            user: u,
            client_id: client_id.to_owned(),
            app_id: app_id,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Token {
    // Expiration date as POSIX timestamp. Never expires if None.
    pub exp: Option<i64>,

    // Each user has a server-stored mapping from client_id/Origin to app_id. The app_id is a
    // UUIDv4 that is generated when a client is approved the first time.
    //
    // This value allows the user to reject all tokens for a client_id, but then issue new tokens
    // for the same client_id (because the app_id changed, and the old value doesn't validate
    // anymore).
    pub app_id: String,

    // The client_id as specified in OAuth and remoteStorage specifications. In our case it is
    // always the Origin.
    pub client_id: String,
    pub permissions: PermissionsMap,
}

impl Token {
    pub fn get<'a>(u: &'a User, token: &str) -> Option<(App<'a>, Self)> {
        let key = u.get_key();

        let token: Self = {
            let mut token_parts = token.split('.').map(|x| base64::decode(x));
            let payload = match token_parts.next() {
                Some(Ok(x)) => x,
                _ => return None,
            };

            let tag = match token_parts.next() {
                Some(Ok(x)) => x,
                _ => return None,
            };

            let mut hmac = HmacSha256::new_from_slice(&key).unwrap();
            hmac.update(&payload);
            if !hmac.verify_slice(&tag).is_ok() {
                return None;
            };

            let payload_string = match String::from_utf8(payload) {
                Ok(x) => x,
                Err(_) => return None,
            };

            match serde_json::from_str(&payload_string) {
                Ok(x) => x,
                Err(_) => return None,
            }
        };

        if let Some(exp) = token.exp {
            let now = chrono::offset::Utc::now().timestamp();
            if exp < now {
                return None;
            }
        }

        let app = match App::get(u, &token.client_id[..]) {
            Some(app) => {
                if app.app_id == token.app_id {
                    app
                } else {
                    return None;
                }
            }
            _ => return None,
        };

        Some((app, token))
    }

    pub fn create(
        u: &User,
        sess: OauthSession,
        days: Option<u64>,
    ) -> Result<(App, Self), ServerError> {
        let app = match App::get(u, &sess.client_id) {
            Some(x) => x,
            None => App::create(u, &sess.client_id)?,
        };

        let app_id_cp = app.app_id.clone();

        Ok((
            app,
            Token {
                app_id: app_id_cp,
                client_id: sess.client_id,
                permissions: sess.permissions,
                exp: days.map(|d| {
                    (chrono::offset::Utc::now() + chrono::Duration::days(d as i64)).timestamp()
                }),
            },
        ))
    }

    pub fn token(&self, u: &User) -> String {
        let key = u.get_key();
        let payload_string = serde_json::to_string(self).unwrap();
        let payload = payload_string.as_bytes();
        let mut hmac = HmacSha256::new_from_slice(&key).unwrap();
        hmac.update(payload);
        let tag = hmac.finalize().into_bytes();

        {
            let mut rv = String::new();
            rv.push_str(&base64::encode(payload));
            rv.push('.');
            rv.push_str(&base64::encode(&tag));
            rv
        }
    }
}

#[derive(Debug)]
pub struct PasswordHash {
    content: password_hash::PasswordHashString,
}

impl PasswordHash {
    pub fn from_password(pwd: &str) -> PasswordHash {
        let salt = SaltString::generate(&mut rand::rngs::OsRng);
        let hashed_password = Argon2::default().hash_password(pwd.as_bytes(), &salt).unwrap();
        PasswordHash {
            content: hashed_password.into(),
        }
    }

    pub fn from_hash(hash: &[u8]) -> PasswordHash {
        PasswordHash{
            content: password_hash::PasswordHashString::new(&String::from_utf8(hash.to_vec()).unwrap()).unwrap()
        }
    }

    pub fn equals_password(&self, pwd: &[u8]) -> bool {
        Argon2::default().verify_password(pwd, &self.content.password_hash()).is_ok()
    }
}

pub trait UserNode<'a> {
    fn from_path(user: &'a User, path: &str) -> Option<Self>
    where
        Self: Sized;

    // Get frontent-facing path relative to root
    fn get_path(&self) -> &str;
    fn get_basename(&self) -> String;
    fn get_user(&self) -> &User;

    // Get absolute path on filesystem
    fn get_fs_path(&self) -> &path::Path;

    // Get json repr for folder listing
    fn json_repr(&self) -> Result<serde_json::Value, ServerError>;

    // Get etag
    fn read_etag(&self) -> Result<String, ServerError> {
        let metadata = fs::metadata(&self.get_fs_path())?;
        Ok(format!("{}", metadata.mtime_nsec()))
    }
}

#[derive(Serialize, Deserialize)]
pub struct UserFileMeta {
    pub content_type: String,
    pub content_length: u64,
}

pub struct UserFile<'a> {
    pub user: &'a User,
    pub path: String,
    data_path: path::PathBuf,
    meta_path: path::PathBuf,
}

impl<'a> UserFile<'a> {
    pub fn read_meta(&self) -> Result<UserFileMeta, ServerError> {
        utils::read_json_file(&self.meta_path)
    }

    pub fn open(&self) -> io::Result<fs::File> {
        fs::File::open(&self.data_path)
    }

    pub fn create(&self) -> io::Result<atomicwrites::AtomicFile> {
        fs::create_dir_all(self.data_path.parent().unwrap())?;
        fs::create_dir_all(self.meta_path.parent().unwrap())?;

        Ok(atomicwrites::AtomicFile::new_with_tmpdir(
            &self.data_path,
            atomicwrites::AllowOverwrite,
            &self.user.tmp_path(),
        ))
    }

    pub fn write_meta(&self, meta: UserFileMeta) -> Result<(), ServerError> {
        utils::write_json_file(meta, &self.meta_path)?;
        match self.touch_parents() {
            Ok(_) => (),
            Err(e) => println!("Failed to touch parent directories: {:?}", e),
        };
        Ok(())
    }

    fn touch_parents(&self) -> io::Result<()> {
        let timestamp = filetime::FileTime::now();

        utils::map_parent_dirs(&self.data_path, self.user.data_path(), |p| {
            filetime::set_file_times(p, timestamp, timestamp).map(|_| true)
        })
        .map(|_| ())
    }

    pub fn delete(&mut self) -> io::Result<()> {
        fn f(p: &path::Path) -> io::Result<bool> {
            match fs::remove_dir(p) {
                Err(e) => {
                    if let Some(errno) = e.raw_os_error() {
                        if errno::Errno::from_i32(errno) == errno::Errno::ENOTEMPTY {
                            return Ok(false);
                        }
                    }
                    println!("Failed to remove directory during cleanup: {:?}", e);
                    Err(e)
                }
                Ok(_) => Ok(true),
            }
        }

        fs::remove_file(&self.data_path)?;
        fs::remove_file(&self.meta_path)?;
        utils::map_parent_dirs(&self.data_path, self.user.data_path(), f)?;
        utils::map_parent_dirs(&self.meta_path, self.user.meta_path(), f)?;
        Ok(())
    }
}

impl<'a> UserNode<'a> for UserFile<'a> {
    fn from_path(user: &'a User, path: &str) -> Option<UserFile<'a>> {
        if path.ends_with('/') {
            return None;
        };

        let data_path = match utils::safe_join(user.data_path(), path) {
            Some(x) => x,
            None => return None,
        };
        let meta_path = match utils::safe_join(user.meta_path(), path) {
            Some(x) => x,
            None => return None,
        };

        Some(UserFile {
            path: path.to_owned(),
            data_path: data_path,
            meta_path: meta_path,
            user: user,
        })
    }
    fn get_user(&self) -> &User {
        self.user
    }

    fn get_path(&self) -> &str {
        &self.path
    }
    fn get_basename(&self) -> String {
        self.path.rsplitn(2, '/').nth(0).unwrap().to_owned()
    }
    fn get_fs_path(&self) -> &path::Path {
        self.data_path.as_path()
    }

    fn json_repr(&self) -> Result<serde_json::Value, ServerError> {
        let meta = self.read_meta()?;
        Ok(json!({
            "Content-Type": meta.content_type,
            "Content-Length": meta.content_length,
            "ETag": self.read_etag()?
        }))
    }
}

pub struct UserFolder<'a> {
    pub user: &'a User,
    data_path: path::PathBuf,
    path: String,
}

impl<'a> UserFolder<'a> {
    pub fn read_children<'b>(&'b self) -> Result<Vec<Box<dyn UserNode + 'b>>, ServerError> {
        let mut rv: Vec<Box<dyn UserNode>> = vec![];
        for entry in fs::read_dir(&self.data_path)? {
            let entry = entry?;
            let path = entry.path();
            let meta = fs::metadata(&path)?;
            let fname_string = entry.file_name();
            let fname_str = fname_string.to_str().unwrap();

            let entry_path = match std::path::Path::new(&self.path).join(fname_str).to_str() {
                Some(e) => e.to_owned(),
                None => return Err(ServerError::Model(Error::InvalidPath))
            };
            if meta.is_dir() {
                rv.push(Box::new(
                    UserFolder::from_path(self.user, &(entry_path + "/"))
                        .unwrap(),
                ));
            } else if !fname_str.starts_with(".~") {
                rv.push(Box::new(
                    UserFile::from_path(self.user, &entry_path).unwrap(),
                ));
            }
        }
        Ok(rv)
    }
}

impl<'a> UserNode<'a> for UserFolder<'a> {
    fn from_path(user: &'a User, path: &str) -> Option<UserFolder<'a>> {
        Some(UserFolder {
            path: path.to_owned(),
            data_path: match utils::safe_join(user.data_path(), path) {
                Some(x) => x,
                None => return None,
            },
            user: user,
        })
    }

    fn get_path(&self) -> &str {
        &self.path
    }
    fn get_user(&self) -> &User {
        self.user
    }
    fn get_basename(&self) -> String {
        self.path.rsplitn(3, '/').nth(1).unwrap().to_owned() + "/"
    }

    fn get_fs_path(&self) -> &path::Path {
        self.data_path.as_path()
    }

    fn json_repr(&self) -> Result<serde_json::Value, ServerError> {
        Ok(json!({
            "ETag": self.read_etag()?
        }))
    }
}

pub enum UserNodeFromPath<'a> {
    None,
    UserFolder(UserFolder<'a>),
    UserFile(UserFile<'a>),
}

pub fn user_node_from_path<'a>(user: &'a User, path: &str) -> UserNodeFromPath<'a> {
    if path.ends_with('/') || path.is_empty() {
        match UserFolder::from_path(user, path) {
            Some(f) => return UserNodeFromPath::UserFolder(f),
            None => return UserNodeFromPath::None,
        };
    }

    let data_path= match utils::safe_join(user.data_path(), path) {
        Some(x) => x,
        None => return UserNodeFromPath::None,
    };

    match std::fs::read_dir(data_path) {
        Ok(_) => match UserFolder::from_path(user, path) {
            Some(f) => UserNodeFromPath::UserFolder(f),
            None => UserNodeFromPath::None,
        }
        Err(_) => match UserFile::from_path(user, path) {
            Some(f) => UserNodeFromPath::UserFile(f),
            None => UserNodeFromPath::None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::oauth::CategoryPermissions;
    use crate::web::oauth::PermissionsMap;
    use crate::web::oauth::Session as OauthSession;
    use std::collections;
    use tempdir::TempDir;
    use utils::ServerError;

    fn get_tmp() -> TempDir {
        TempDir::new("mysteryshack").unwrap()
    }

    fn get_root_token<'a>(u: &'a User) -> (App<'a>, Token) {
        Token::create(
            &u,
            OauthSession {
                client_id: "http://example.com".to_owned(),
                permissions: PermissionsMap {
                    permissions: {
                        let mut rv = collections::HashMap::new();
                        rv.insert(
                            "".to_owned(),
                            CategoryPermissions {
                                can_read: true,
                                can_write: true,
                            },
                        );
                        rv
                    },
                },
            },
            Some(30),
        )
        .unwrap()
    }

    #[test]
    fn test_create_existing_user() {
        let t = get_tmp();
        User::create(t.path(), "foo").unwrap();

        match User::create(t.path(), "foo") {
            Err(ServerError::Model(Error::AlreadyExisting)) => (),
            _ => panic!("User creation successful."),
        };
    }

    #[test]
    fn test_sessions() {
        let t = get_tmp();
        let u = User::create(t.path(), "foo").unwrap();

        assert!(Token::get(&u, "aint a jwt").is_none());

        let (app, token) = get_root_token(&u);
        assert!(Token::get(&u, &token.token(&u)).is_some());

        app.delete().unwrap();
        assert!(Token::get(&u, &token.token(&u)).is_none());
    }

    #[test]
    fn tokens_expiration_time() {
        let t = get_tmp();
        let u = User::create(t.path(), "foo").unwrap();

        assert!(Token::get(&u, "aint a jwt").is_none());

        let (_, mut token) = get_root_token(&u);
        assert!(Token::get(&u, &token.token(&u)).is_some());

        token.exp = Some(token.exp.unwrap() - 2700000 * 60);
        assert!(Token::get(&u, &token.token(&u)).is_none());
    }
}
