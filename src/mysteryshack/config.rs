use std::path::{Path, PathBuf};

#[derive(Deserialize)]
pub struct Config {
    pub data_path: String,
    pub use_proxy_headers: bool,
    pub csrf_key: String,
    pub template_dir: String,
    pub public_hostname: String,
}

impl Config {
    pub fn absolute_data_path(&self) -> PathBuf {
        let path = Path::new(&self.data_path);
        path.canonicalize().expect("Unable to canonicalize data_path")
    }
}