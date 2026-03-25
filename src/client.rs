use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::{fs, io};
/// Validate that a package name or version contains only safe characters.
/// Allowed: printable ASCII 33–126, excluding `/\,:;*?'"` and whitespace.
/// Must not be empty, start with `.`, or end with `.` or space.
pub(crate) const FORBIDDEN_SPEC_CHARS: &[u8] = b"/\\,:;*?'`\"@%$[]<>|";

/// Check if a byte is a safe printable ASCII character (33–126, not in `FORBIDDEN_SPEC_CHARS`).
pub(crate) fn is_safe_spec_char(b: u8) -> bool {
    (33..=126).contains(&b) && !FORBIDDEN_SPEC_CHARS.contains(&b)
}

pub(crate) fn validate_pkg_spec(label: &str, value: &str) -> io::Result<()> {
    if value.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{label} must not be empty")));
    }
    if value.starts_with('.') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{label} must not start with '.'")));
    }
    if value.ends_with('.') || value.ends_with(' ') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{label} must not end with '.' or space")));
    }
    for &b in value.as_bytes() {
        if !is_safe_spec_char(b) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{label} contains invalid character (0x{b:02x}): {value}"),
            ));
        }
    }
    Ok(())
}

/// Windows reserved device names that must not be used as filenames.
pub(crate) const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Validate that a file path and destination directory from a manifest are safe.
pub(crate) fn validate_manifest_path(file: &str, dest_dir: &str, pkg_name: &str) -> io::Result<()> {
    for (label, value) in [("file", file), ("dest_dir", dest_dir)] {
        if value.contains("..") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Path traversal in {label} for {pkg_name}: {value}"),
            ));
        }
        // Reject absolute paths: drive letters (C:), UNC (\\), leading slashes
        if value.starts_with('/') || value.starts_with('\\') || value.contains(':') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Absolute path in {label} for {pkg_name}: {value}"),
            ));
        }
        // Reject null bytes (cause path truncation on Windows)
        if value.contains('\0') {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("Null byte in {label} for {pkg_name}")));
        }
    }
    // Check both file and dest_dir segments against Windows reserved device names
    for (label, value) in [("file", file), ("dest_dir", dest_dir)] {
        for segment in value.split(['/', '\\']) {
            let stem = segment.split('.').next().unwrap_or(segment);
            if WINDOWS_RESERVED.iter().any(|r| r.eq_ignore_ascii_case(stem)) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Reserved device name in {label} for {pkg_name}: {segment}"),
                ));
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server_url: String,
    pub base_dir: PathBuf,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub server_fingerprint: String,
    /// Number of days to keep cached downloads (0 = no cache, default: 1)
    #[serde(default = "default_cache_days")]
    pub cache_days: u32,
    /// Cache directory override (not serialized; defaults to ~/.blob/cache)
    #[serde(skip)]
    pub cache_dir: Option<PathBuf>,
}

impl Config {
    pub(crate) fn cache_dir(&self) -> io::Result<PathBuf> {
        if let Some(dir) = &self.cache_dir {
            Ok(dir.clone())
        } else {
            default_cache_dir()
        }
    }
}

fn default_cache_days() -> u32 {
    1
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InstallReason {
    Manual,
    Auto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledPackage {
    pub version: String,
    pub reason: InstallReason,
    pub files: BTreeMap<String, PathBuf>,
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Database {
    pub packages: BTreeMap<String, InstalledPackage>,
    #[serde(skip)]
    path: Option<PathBuf>,
}

pub(crate) fn blob_dir() -> io::Result<PathBuf> {
    dirs::home_dir()
        .map(|p| p.join(".blob"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Could not determine home directory"))
}

pub(crate) fn default_cache_dir() -> io::Result<PathBuf> {
    blob_dir().map(|p| p.join("cache"))
}

pub fn config_path() -> io::Result<PathBuf> {
    blob_dir().map(|p| p.join("config.json"))
}

fn db_path() -> io::Result<PathBuf> {
    blob_dir().map(|p| p.join("db.json"))
}

impl Config {
    /// Load config from `~/.blob/config.json`, or create a default one.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or parsed.
    pub fn load() -> io::Result<Self> {
        let path = config_path()?;
        if path.is_file() {
            let content = fs::read_to_string(&path)?;
            serde_json::from_str(&content).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "No config found. Run 'blob config' first."))
        }
    }

    /// Save config to `~/.blob/config.json`.
    ///
    /// # Errors
    /// Returns an error if the file cannot be written.
    pub fn save(&self) -> io::Result<()> {
        let path = config_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(self).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(&path, &content)?;
        match crate::platform::restrict_to_owner_if_inherited(&path) {
            Ok(true) => println!("Restricted {} to owner-only (contains credentials)", path.display()),
            Ok(false) => {}
            Err(e) => eprintln!("Warning: could not restrict permissions on {}: {e}", path.display()),
        }
        Ok(())
    }
}

impl Database {
    /// Load database from `~/.blob/db.json`, or create an empty one.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or parsed.
    pub fn load() -> io::Result<Self> {
        let path = db_path()?;
        Self::load_from(&path)
    }

    /// Save database to its loaded path.
    ///
    /// # Errors
    /// Returns an error if the file cannot be written.
    pub fn save(&self) -> io::Result<()> {
        let path = self.path.clone().map_or_else(db_path, Ok)?;
        self.save_to(&path)
    }

    /// Load database from a specific path.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or parsed.
    pub fn load_from(path: &Path) -> io::Result<Self> {
        let mut db = if path.is_file() {
            let content = fs::read_to_string(path)?;
            serde_json::from_str::<Self>(&content).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        } else {
            Self { packages: BTreeMap::new(), path: None }
        };
        db.path = Some(path.to_path_buf());
        Ok(db)
    }

    /// Save database to a specific path.
    ///
    /// # Errors
    /// Returns an error if the file cannot be written.
    pub fn save_to(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(self).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(path, content)?;
        if let Err(e) = crate::platform::restrict_to_owner_if_inherited(path) {
            eprintln!("Warning: could not restrict permissions on {}: {e}", path.display());
        }
        Ok(())
    }
}

/// An HTTP client with config for auth.
pub struct HttpClient {
    client: reqwest::blocking::Client,
    pub config: Config,
}

impl HttpClient {
    /// Build an HTTP client from config, handling TLS/TOFU.
    ///
    /// # Errors
    /// Returns an error if the TLS config or client build fails.
    pub fn new(config: &Config) -> io::Result<Self> {
        if !config.server_url.starts_with("https://") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Server URL must use https://. Plaintext HTTP would expose credentials on the wire.",
            ));
        }
        let client = crate::tls::build_client(config)?;
        Ok(Self { client, config: config.clone() })
    }

    fn send(&self, mut req: reqwest::blocking::RequestBuilder) -> io::Result<reqwest::blocking::Response> {
        if !self.config.username.is_empty() {
            req = req.basic_auth(&self.config.username, Some(&self.config.password));
        }
        let resp = req.send().map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Authentication failed. Check username/password in 'blob config'.",
            ));
        }
        Ok(resp)
    }

    pub(crate) fn get(&self, url: &str) -> io::Result<reqwest::blocking::Response> {
        self.send(self.client.get(url))
    }

    pub(crate) fn post(&self, url: &str, body: Vec<u8>) -> io::Result<reqwest::blocking::Response> {
        self.send(self.client.post(url).body(body))
    }

    pub(crate) fn delete(&self, url: &str) -> io::Result<reqwest::blocking::Response> {
        self.send(self.client.delete(url))
    }

    pub(crate) fn download_to_file(
        &self,
        url: &str,
        dest: &std::path::Path,
        label: &str,
    ) -> io::Result<()> {
        let mut resp = self.get(url)?;
        if !resp.status().is_success() {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("GET {url}: {}", resp.status())));
        }
        let total = resp.content_length().unwrap_or(0);
        let pb = indicatif::ProgressBar::new(total);
        pb.set_style(
            indicatif::ProgressStyle::with_template(
                "{msg} [{bar:40}] {bytes}/{total_bytes} ({bytes_per_sec})",
            )
            .expect("hardcoded progress template")
            .progress_chars("=>-"),
        );
        pb.set_message(label.to_string());
        let file = std::fs::File::create(dest)?;
        let mut writer = io::BufWriter::new(file);
        io::copy(&mut pb.wrap_read(&mut resp), &mut writer)?;
        pb.finish_and_clear();
        Ok(())
    }

    pub(crate) fn post_with_progress(
        &self,
        url: &str,
        body: Vec<u8>,
        label: &str,
    ) -> io::Result<reqwest::blocking::Response> {
        let total = body.len() as u64;
        let pb = indicatif::ProgressBar::new(total);
        pb.set_style(
            indicatif::ProgressStyle::with_template(
                "{msg} [{bar:40}] {bytes}/{total_bytes} ({bytes_per_sec})",
            )
            .expect("hardcoded progress template")
            .progress_chars("=>-"),
        );
        pb.set_message(label.to_string());
        let reader = pb.wrap_read(std::io::Cursor::new(body));
        let stream_body = reqwest::blocking::Body::sized(reader, total);
        let resp = self.send(self.client.post(url).body(stream_body));
        pb.finish_and_clear();
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_absolute_path_in_manifest() {
        let result = validate_manifest_path("evil.exe", "C:\\Windows\\System32", "badpkg");
        assert!(result.is_err());

        let result = validate_manifest_path("evil.exe", "/etc", "badpkg");
        assert!(result.is_err());

        let result = validate_manifest_path("C:\\evil.exe", "util", "badpkg");
        assert!(result.is_err());
    }

    #[test]
    fn reject_traversal_in_manifest() {
        let result = validate_manifest_path("..\\..\\evil.exe", "util", "badpkg");
        assert!(result.is_err());

        let result = validate_manifest_path("evil.exe", "..\\..\\Windows", "badpkg");
        assert!(result.is_err());
    }

    #[test]
    fn reject_null_bytes_in_manifest() {
        let result = validate_manifest_path("evil\0.exe", "util", "badpkg");
        assert!(result.is_err());

        let result = validate_manifest_path("evil.exe", "util\0hidden", "badpkg");
        assert!(result.is_err());
    }

    #[test]
    fn reject_windows_device_names() {
        let result = validate_manifest_path("CON", "util", "badpkg");
        assert!(result.is_err());

        let result = validate_manifest_path("con.txt", "util", "badpkg");
        assert!(result.is_err());

        let result = validate_manifest_path("NUL.exe", "util", "badpkg");
        assert!(result.is_err());

        let result = validate_manifest_path("COM1", "util", "badpkg");
        assert!(result.is_err());

        let result = validate_manifest_path("COM0", "util", "badpkg");
        assert!(result.is_err());

        let result = validate_manifest_path("LPT0", "util", "badpkg");
        assert!(result.is_err());
    }

    #[test]
    fn accept_valid_manifest_paths() {
        let result = validate_manifest_path("tool.exe", "util", "goodpkg");
        assert!(result.is_ok());

        let result = validate_manifest_path("helper.py", "scripts", "goodpkg");
        assert!(result.is_ok());

        let result = validate_manifest_path("console.exe", "util", "goodpkg");
        assert!(result.is_ok());
    }

    #[test]
    fn config_save_and_load() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.json");

        let config = Config {
            server_url: "http://example.com:9090".to_string(),
            base_dir: PathBuf::from("D:/tools"),
            username: String::new(),
            password: String::new(),
            server_fingerprint: String::new(),
            cache_days: 1,
            cache_dir: None,
        };

        fs::write(&path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        let loaded: Config = serde_json::from_str(&content).unwrap();
        assert_eq!(loaded.server_url, "http://example.com:9090");
        assert_eq!(loaded.base_dir, PathBuf::from("D:/tools"));
    }

    #[test]
    fn database_empty_on_missing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("db.json");

        let db = Database::load_from(&path).unwrap();
        assert!(db.packages.is_empty());
    }

    #[test]
    fn database_save_and_load() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("db.json");

        let mut db = Database { packages: BTreeMap::new(), path: None };
        db.packages.insert(
            "testpkg".to_string(),
            InstalledPackage {
                version: "1.0".to_string(),
                reason: InstallReason::Manual,
                files: BTreeMap::from([("test.exe".to_string(), PathBuf::from("C:/bin/util/test.exe"))]),
                dependencies: vec![],
            },
        );

        db.save_to(&path).unwrap();

        let loaded = Database::load_from(&path).unwrap();
        assert_eq!(loaded.packages.len(), 1);
        assert_eq!(loaded.packages["testpkg"].version, "1.0");
        assert_eq!(loaded.packages["testpkg"].files["test.exe"], PathBuf::from("C:/bin/util/test.exe"));
    }

    #[test]
    fn database_roundtrip_json() {
        let db = Database { packages: BTreeMap::new(), path: None };
        let json = serde_json::to_string(&db).unwrap();
        let loaded: Database = serde_json::from_str(&json).unwrap();
        assert!(loaded.packages.is_empty());
    }
}
