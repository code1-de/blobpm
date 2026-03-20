use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::{fs, io};

use crate::repo::Manifest;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server_url: String,
    pub base_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledPackage {
    pub version: String,
    pub files: BTreeMap<String, PathBuf>,
    pub dependencies: Vec<String>,
    pub manifest: Manifest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Database {
    pub packages: BTreeMap<String, InstalledPackage>,
}

fn blob_dir() -> PathBuf {
    dirs::home_dir()
        .expect("Could not determine home directory")
        .join(".blob")
}

fn config_path() -> PathBuf {
    blob_dir().join("config.json")
}

fn db_path() -> PathBuf {
    blob_dir().join("db.json")
}

impl Config {
    /// Load config from `~/.blob/config.json`, or create a default one.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or parsed.
    pub fn load() -> io::Result<Self> {
        let path = config_path();
        if path.is_file() {
            let content = fs::read_to_string(&path)?;
            serde_json::from_str(&content)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        } else {
            let config = Self {
                server_url: "http://localhost:8803".to_string(),
                base_dir: PathBuf::from("C:/"),
            };
            config.save()?;
            Ok(config)
        }
    }

    /// Save config to `~/.blob/config.json`.
    ///
    /// # Errors
    /// Returns an error if the file cannot be written.
    pub fn save(&self) -> io::Result<()> {
        let path = config_path();
        fs::create_dir_all(path.parent().unwrap())?;
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(&path, content)
    }

    /// Load config from a specific path.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or parsed.
    pub fn load_from(path: &Path) -> io::Result<Self> {
        let content = fs::read_to_string(path)?;
        serde_json::from_str(&content)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

impl Database {
    /// Load database from `~/.blob/db.json`, or create an empty one.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or parsed.
    pub fn load() -> io::Result<Self> {
        let path = db_path();
        if path.is_file() {
            let content = fs::read_to_string(&path)?;
            serde_json::from_str(&content)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        } else {
            let db = Self {
                packages: BTreeMap::new(),
            };
            db.save()?;
            Ok(db)
        }
    }

    /// Save database to `~/.blob/db.json`.
    ///
    /// # Errors
    /// Returns an error if the file cannot be written.
    pub fn save(&self) -> io::Result<()> {
        let path = db_path();
        fs::create_dir_all(path.parent().unwrap())?;
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(&path, content)
    }

    /// Load database from a specific path.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or parsed.
    pub fn load_from(path: &Path) -> io::Result<Self> {
        if path.is_file() {
            let content = fs::read_to_string(path)?;
            serde_json::from_str(&content)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        } else {
            Ok(Self {
                packages: BTreeMap::new(),
            })
        }
    }

    /// Save database to a specific path.
    ///
    /// # Errors
    /// Returns an error if the file cannot be written.
    pub fn save_to(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(path, content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_save_and_load() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.json");

        let config = Config {
            server_url: "http://example.com:9090".to_string(),
            base_dir: PathBuf::from("D:/tools"),
        };

        fs::write(
            &path,
            serde_json::to_string_pretty(&config).unwrap(),
        )
        .unwrap();

        let loaded = Config::load_from(&path).unwrap();
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

        let mut db = Database {
            packages: BTreeMap::new(),
        };
        db.packages.insert(
            "testpkg".to_string(),
            InstalledPackage {
                version: "1.0".to_string(),
                files: BTreeMap::from([
                    ("test.exe".to_string(), PathBuf::from("C:/bin/util/test.exe")),
                ]),
                dependencies: vec![],
                manifest: Manifest {
                    name: "testpkg".to_string(),
                    description: "A test".to_string(),
                    files: BTreeMap::from([("test.exe".to_string(), "util/".to_string())]),
                    dependencies: vec![],
                },
            },
        );

        db.save_to(&path).unwrap();

        let loaded = Database::load_from(&path).unwrap();
        assert_eq!(loaded.packages.len(), 1);
        assert_eq!(loaded.packages["testpkg"].version, "1.0");
        assert_eq!(
            loaded.packages["testpkg"].files["test.exe"],
            PathBuf::from("C:/bin/util/test.exe")
        );
    }

    #[test]
    fn database_roundtrip_json() {
        let db = Database {
            packages: BTreeMap::new(),
        };
        let json = serde_json::to_string(&db).unwrap();
        let loaded: Database = serde_json::from_str(&json).unwrap();
        assert!(loaded.packages.is_empty());
    }
}
