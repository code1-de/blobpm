use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::{fs, io};

use crate::repo::Manifest;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server_url: String,
    pub base_dir: PathBuf,
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
    pub manifest: Manifest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Database {
    pub packages: BTreeMap<String, InstalledPackage>,
}

fn blob_dir() -> io::Result<PathBuf> {
    dirs::home_dir()
        .map(|p| p.join(".blob"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Could not determine home directory"))
}

fn config_path() -> io::Result<PathBuf> {
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
        let path = config_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
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
        let path = db_path()?;
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
        let path = db_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
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

/// Fetch the package index from the server.
///
/// # Errors
/// Returns an error if the HTTP request fails or the response is not valid JSON.
pub fn fetch_index(server_url: &str) -> io::Result<BTreeMap<String, String>> {
    let url = format!("{server_url}/index");
    let resp = reqwest::blocking::get(&url)
        .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;
    resp.json()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Fetch a manifest from the server.
///
/// # Errors
/// Returns an error if the HTTP request fails or the response is not valid JSON.
pub fn fetch_manifest(server_url: &str, name: &str, version: &str) -> io::Result<Manifest> {
    let url = format!("{server_url}/packages/{name}/{version}/blob.json");
    let resp = reqwest::blocking::get(&url)
        .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;
    if !resp.status().is_success() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Package {name} {version} not found"),
        ));
    }
    resp.json()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Download a file from the server.
///
/// # Errors
/// Returns an error if the HTTP request fails.
pub fn download_file(server_url: &str, name: &str, version: &str, file: &str) -> io::Result<Vec<u8>> {
    let url = format!("{server_url}/packages/{name}/{version}/{file}");
    let resp = reqwest::blocking::get(&url)
        .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;
    if !resp.status().is_success() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("File {file} not found in {name} {version}"),
        ));
    }
    resp.bytes()
        .map(|b| b.to_vec())
        .map_err(io::Error::other)
}

/// Resolve dependencies recursively. Returns packages in install order (dependencies first).
///
/// # Errors
/// Returns an error if a dependency cycle is detected or a dependency is not in the index.
pub fn resolve_dependencies(
    name: &str,
    server_url: &str,
    index: &BTreeMap<String, String>,
    db: &Database,
) -> io::Result<Vec<(String, String, Manifest)>> {
    let mut result = Vec::new();
    let mut visited = HashSet::new();
    let mut in_stack = HashSet::new();
    resolve_recursive(name, server_url, index, db, &mut result, &mut visited, &mut in_stack)?;
    Ok(result)
}

fn resolve_recursive(
    name: &str,
    server_url: &str,
    index: &BTreeMap<String, String>,
    db: &Database,
    result: &mut Vec<(String, String, Manifest)>,
    visited: &mut HashSet<String>,
    in_stack: &mut HashSet<String>,
) -> io::Result<()> {
    if visited.contains(name) {
        return Ok(());
    }
    if in_stack.contains(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Dependency cycle detected: {name}"),
        ));
    }

    in_stack.insert(name.to_string());

    let version = index.get(name).ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, format!("Package {name} not found in index"))
    })?;

    let manifest = fetch_manifest(server_url, name, version)?;

    for dep in &manifest.dependencies {
        if !db.packages.contains_key(dep) {
            resolve_recursive(dep, server_url, index, db, result, visited, in_stack)?;
        }
    }

    in_stack.remove(name);
    visited.insert(name.to_string());
    result.push((name.to_string(), version.clone(), manifest));
    Ok(())
}

/// Install a package and its dependencies.
///
/// # Errors
/// Returns an error if fetching, downloading, or writing files fails.
pub fn install(name: &str, config: &Config, db: &mut Database) -> io::Result<()> {
    // If already installed at latest version, just ensure it's marked manual
    if let Some(existing) = db.packages.get(name) {
        let index = fetch_index(&config.server_url)?;
        if index.get(name).is_some_and(|v| *v == existing.version) {
            if existing.reason == InstallReason::Auto {
                if let Some(pkg) = db.packages.get_mut(name) {
                    pkg.reason = InstallReason::Manual;
                }
                db.save()?;
                println!("{name} marked as manually installed");
            } else {
                println!("{name} {} is already installed", existing.version);
            }
            return Ok(());
        }
    }

    let index = fetch_index(&config.server_url)?;
    let to_install = resolve_dependencies(name, &config.server_url, &index, db)?;

    if to_install.is_empty() {
        println!("{name} is already installed");
        return Ok(());
    }

    for (pkg_name, version, manifest) in &to_install {
        println!("Installing {pkg_name} {version}...");

        let mut installed_files = BTreeMap::new();

        for (file, dest_dir) in &manifest.files {
            let dest = config.base_dir.join(dest_dir.replace('/', "\\")).join(file);
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)?;
            }

            let bytes = download_file(&config.server_url, pkg_name, version, file)?;
            fs::write(&dest, &bytes)?;
            println!("  {} -> {}", file, dest.display());
            installed_files.insert(file.clone(), dest);
        }

        let reason = if pkg_name == name {
            InstallReason::Manual
        } else {
            InstallReason::Auto
        };

        db.packages.insert(
            pkg_name.clone(),
            InstalledPackage {
                version: version.clone(),
                reason,
                files: installed_files,
                dependencies: manifest.dependencies.clone(),
                manifest: manifest.clone(),
            },
        );

        println!("  Installed {pkg_name} {version}");
    }

    db.save()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server;
    use std::sync::Arc;

    fn create_test_repo(base: &Path) {
        let pkg_dir = base.join("packages").join("toolA").join("1.0");
        fs::create_dir_all(&pkg_dir).unwrap();
        fs::write(
            pkg_dir.join("blob.json"),
            r#"{"name":"toolA","description":"Tool A","files":{"toolA.exe":"util/"},"dependencies":[]}"#,
        ).unwrap();
        fs::write(pkg_dir.join("toolA.exe"), b"toolA-binary").unwrap();

        let pkg_dir2 = base.join("packages").join("toolB").join("2.0");
        fs::create_dir_all(&pkg_dir2).unwrap();
        fs::write(
            pkg_dir2.join("blob.json"),
            r#"{"name":"toolB","description":"Tool B","files":{"toolB.exe":"util/"},"dependencies":["toolA"]}"#,
        ).unwrap();
        fs::write(pkg_dir2.join("toolB.exe"), b"toolB-binary").unwrap();
    }

    fn start_test_server(repo_path: &Path) -> (tokio::runtime::Runtime, u16) {
        let index = crate::repo::RepoIndex::scan(repo_path).unwrap();
        let state = Arc::new(server::AppState { index });
        let app = server::build_router(state);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let listener = rt.block_on(async {
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap()
        });
        let port = listener.local_addr().unwrap().port();

        rt.spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        (rt, port)
    }

    #[test]
    fn fetch_index_from_server() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let (_rt, port) = start_test_server(tmp.path());

        let index = fetch_index(&format!("http://127.0.0.1:{port}")).unwrap();
        assert_eq!(index["toolA"], "1.0");
        assert_eq!(index["toolB"], "2.0");
    }

    #[test]
    fn install_single_package() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let install_tmp = tempfile::tempdir().unwrap();
        let db_path = install_tmp.path().join("db.json");
        create_test_repo(repo_tmp.path());
        let (_rt, port) = start_test_server(repo_tmp.path());

        let config = Config {
            server_url: format!("http://127.0.0.1:{port}"),
            base_dir: install_tmp.path().to_path_buf(),
        };
        let mut db = Database::load_from(&db_path).unwrap();

        install("toolA", &config, &mut db).unwrap();

        assert!(install_tmp.path().join("util").join("toolA.exe").exists());
        assert_eq!(db.packages["toolA"].version, "1.0");
    }

    #[test]
    fn install_with_dependency() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let install_tmp = tempfile::tempdir().unwrap();
        let db_path = install_tmp.path().join("db.json");
        create_test_repo(repo_tmp.path());
        let (_rt, port) = start_test_server(repo_tmp.path());

        let config = Config {
            server_url: format!("http://127.0.0.1:{port}"),
            base_dir: install_tmp.path().to_path_buf(),
        };
        let mut db = Database::load_from(&db_path).unwrap();

        install("toolB", &config, &mut db).unwrap();

        assert!(install_tmp.path().join("util").join("toolA.exe").exists());
        assert!(install_tmp.path().join("util").join("toolB.exe").exists());
        assert_eq!(db.packages.len(), 2);
        assert_eq!(db.packages["toolA"].version, "1.0");
        assert_eq!(db.packages["toolA"].reason, InstallReason::Auto);
        assert_eq!(db.packages["toolB"].version, "2.0");
        assert_eq!(db.packages["toolB"].reason, InstallReason::Manual);
    }

    #[test]
    fn install_flips_auto_to_manual() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let install_tmp = tempfile::tempdir().unwrap();
        let db_path = install_tmp.path().join("db.json");
        create_test_repo(repo_tmp.path());
        let (_rt, port) = start_test_server(repo_tmp.path());

        let config = Config {
            server_url: format!("http://127.0.0.1:{port}"),
            base_dir: install_tmp.path().to_path_buf(),
        };
        let mut db = Database::load_from(&db_path).unwrap();

        // Install toolB, which auto-installs toolA
        install("toolB", &config, &mut db).unwrap();
        assert_eq!(db.packages["toolA"].reason, InstallReason::Auto);

        // Explicitly install toolA — should flip to manual
        install("toolA", &config, &mut db).unwrap();
        assert_eq!(db.packages["toolA"].reason, InstallReason::Manual);
    }

    #[test]
    fn dependency_cycle_detection() {
        let tmp = tempfile::tempdir().unwrap();

        let pkg_a = tmp.path().join("packages").join("cycleA").join("1.0");
        fs::create_dir_all(&pkg_a).unwrap();
        fs::write(
            pkg_a.join("blob.json"),
            r#"{"name":"cycleA","description":"A","files":{},"dependencies":["cycleB"]}"#,
        ).unwrap();

        let pkg_b = tmp.path().join("packages").join("cycleB").join("1.0");
        fs::create_dir_all(&pkg_b).unwrap();
        fs::write(
            pkg_b.join("blob.json"),
            r#"{"name":"cycleB","description":"B","files":{},"dependencies":["cycleA"]}"#,
        ).unwrap();

        let (_rt, port) = start_test_server(tmp.path());

        let index = fetch_index(&format!("http://127.0.0.1:{port}")).unwrap();
        let db = Database { packages: BTreeMap::new() };
        let result = resolve_dependencies("cycleA", &format!("http://127.0.0.1:{port}"), &index, &db);
        assert!(result.is_err());
    }

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
                reason: InstallReason::Manual,
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
