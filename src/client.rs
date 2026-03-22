use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::{fs, io};

use crate::repo::Manifest;

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
    #[serde(skip)]
    path: Option<PathBuf>,
}

fn blob_dir() -> io::Result<PathBuf> {
    dirs::home_dir()
        .map(|p| p.join(".blob"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Could not determine home directory"))
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
            serde_json::from_str(&content)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        } else {
            let config = Self {
                server_url: "https://localhost:8803".to_string(),
                base_dir: PathBuf::from("C:/"),
                username: String::new(),
                password: String::new(),
                server_fingerprint: String::new(),
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
            serde_json::from_str::<Self>(&content)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        } else {
            Self {
                packages: BTreeMap::new(),
                path: None,
            }
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
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(path, content)
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
        let client = crate::tls::build_client(config)?;
        Ok(Self { client, config: config.clone() })
    }

    fn get(&self, url: &str) -> io::Result<reqwest::blocking::Response> {
        let mut req = self.client.get(url);
        if !self.config.username.is_empty() {
            req = req.basic_auth(&self.config.username, Some(&self.config.password));
        }
        req.send()
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))
    }
}

/// Fetch the package index from the server.
///
/// # Errors
/// Returns an error if the HTTP request fails or the response is not valid JSON.
pub fn fetch_index(http: &HttpClient) -> io::Result<BTreeMap<String, String>> {
    let url = format!("{}/index", http.config.server_url);
    let resp = http.get(&url)?;
    resp.json()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Fetch available versions for a package from the server.
///
/// # Errors
/// Returns an error if the HTTP request fails or the response is not valid JSON.
pub fn fetch_versions(http: &HttpClient, name: &str) -> io::Result<Vec<String>> {
    let url = format!("{}/packages/{name}", http.config.server_url);
    let resp = http.get(&url)?;
    if !resp.status().is_success() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Package {name} not found"),
        ));
    }
    let value: serde_json::Value = resp.json()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let versions = value["versions"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();
    Ok(versions)
}

/// Fetch a manifest from the server.
///
/// # Errors
/// Returns an error if the HTTP request fails or the response is not valid JSON.
pub fn fetch_manifest(http: &HttpClient, name: &str, version: &str) -> io::Result<Manifest> {
    let url = format!("{}/packages/{name}/{version}/blob.json", http.config.server_url);
    let resp = http.get(&url)?;
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
pub fn download_file(http: &HttpClient, name: &str, version: &str, file: &str) -> io::Result<Vec<u8>> {
    let url = format!("{}/packages/{name}/{version}/{file}", http.config.server_url);
    let resp = http.get(&url)?;
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
    target_version: &str,
    http: &HttpClient,
    index: &BTreeMap<String, String>,
    db: &Database,
) -> io::Result<Vec<(String, String, Manifest)>> {
    let mut result = Vec::new();
    let mut visited = HashSet::new();
    let mut in_stack = HashSet::new();
    resolve_recursive(name, Some(target_version), http, index, db, &mut result, &mut visited, &mut in_stack)?;
    Ok(result)
}

fn resolve_recursive(
    name: &str,
    version_override: Option<&str>,
    http: &HttpClient,
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

    let version = match version_override {
        Some(v) => v.to_string(),
        None => index.get(name).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("Package {name} not found in index"))
        })?.clone(),
    };

    let manifest = fetch_manifest(http, name, &version)?;

    for dep in &manifest.dependencies {
        if !db.packages.contains_key(dep) {
            resolve_recursive(dep, None, http, index, db, result, visited, in_stack)?;
        }
    }

    in_stack.remove(name);
    visited.insert(name.to_string());
    result.push((name.to_string(), version, manifest));
    Ok(())
}

/// Windows reserved device names that must not be used as filenames.
const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Validate that a file path and destination directory from a manifest are safe.
fn validate_manifest_path(file: &str, dest_dir: &str, pkg_name: &str) -> io::Result<()> {
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
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Null byte in {label} for {pkg_name}"),
            ));
        }
    }
    // Check filename against Windows reserved device names
    let file_stem = file.split('.').next().unwrap_or(file);
    if WINDOWS_RESERVED.iter().any(|r| r.eq_ignore_ascii_case(file_stem)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Reserved device name in file for {pkg_name}: {file}"),
        ));
    }
    Ok(())
}

/// Install a package and its dependencies.
///
/// # Errors
/// Returns an error if fetching, downloading, or writing files fails.
pub fn install(name: &str, version: Option<&str>, force: bool, http: &HttpClient, db: &mut Database) -> io::Result<()> {
    let config = &http.config;
    let index = fetch_index(http)?;

    // Determine which version to install
    let target_version = match version {
        Some(v) => v.to_string(),
        None => index.get(name).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("Package {name} not found in index"))
        })?.clone(),
    };

    // If already installed, just ensure it's marked manual (unless --force)
    if let Some(existing) = db.packages.get(name).filter(|_| !force) {
        if existing.reason == InstallReason::Auto {
            if let Some(pkg) = db.packages.get_mut(name) {
                pkg.reason = InstallReason::Manual;
            }
            db.save()?;
            println!("{name} marked as manually installed");
        } else {
            println!("{name} is already installed ({}). Use --force to reinstall.", existing.version);
        }
        return Ok(());
    }

    let to_install = resolve_dependencies(name, &target_version, http, &index, db)?;

    if to_install.is_empty() {
        println!("{name} is already installed");
        return Ok(());
    }

    for (pkg_name, version, manifest) in &to_install {
        let reason = if pkg_name == name {
            InstallReason::Manual
        } else {
            InstallReason::Auto
        };

        println!("Installing {pkg_name} {version}...");
        install_files(pkg_name, version, manifest, reason, http, db)?;
        println!("  Installed {pkg_name} {version}");
    }

    // Clean up orphaned auto-deps (e.g. after --force changed the dep tree)
    purge_orphans(db)?;

    db.save()?;
    Ok(())
}

/// Update installed packages to their latest versions.
/// If `name` is given, update only that package. Otherwise update all.
///
/// # Errors
/// Returns an error if fetching, downloading, or writing files fails.
pub fn update(name: Option<&str>, http: &HttpClient, db: &mut Database) -> io::Result<()> {
    let config = &http.config;
    let index = fetch_index(http)?;

    let packages: Vec<(String, String)> = match name {
        Some(n) => {
            if !db.packages.contains_key(n) {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("{n} is not installed"),
                ));
            }
            let latest = index.get(n).ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, format!("{n} not found in index"))
            })?;
            if *latest == db.packages[n].version {
                println!("{n} is already at latest version ({latest}).");
                return Ok(());
            }
            vec![(n.to_string(), latest.clone())]
        }
        None => {
            let mut list = Vec::new();
            for (n, pkg) in &db.packages {
                if let Some(latest) = index.get(n) {
                    if *latest != pkg.version {
                        list.push((n.clone(), latest.clone()));
                    }
                }
            }
            if list.is_empty() {
                println!("Everything is up to date.");
                return Ok(());
            }
            list
        }
    };

    for (pkg_name, new_version) in &packages {
        let old_version = db.packages[pkg_name].version.clone();
        println!("Updating {pkg_name} {old_version} -> {new_version}...");

        // Resolve and install new deps
        let new_deps = resolve_dependencies(pkg_name, new_version, http, &index, db)?;
        for (dep_name, dep_version, dep_manifest) in &new_deps {
            if dep_name == pkg_name {
                continue; // we handle the main package below
            }
            if db.packages.contains_key(dep_name) {
                continue;
            }
            println!("  Installing new dependency {dep_name} {dep_version}...");
            install_files(dep_name, dep_version, dep_manifest, InstallReason::Auto, http, db)?;
        }

        // Get the manifest for the new version
        let manifest = fetch_manifest(http,pkg_name, new_version)?;

        // Remove old files that are no longer in the new manifest
        if let Some(old_pkg) = db.packages.get(pkg_name) {
            for (old_file, old_path) in &old_pkg.files {
                if !manifest.files.contains_key(old_file) && old_path.is_file() {
                    fs::remove_file(old_path)?;
                    println!("  Removed old file {old_file}");
                }
            }
        }

        let reason = db.packages.get(pkg_name).map_or(InstallReason::Manual, |p| p.reason);
        install_files(pkg_name, new_version, &manifest, reason, http, db)?;
    }

    purge_orphans(db)?;
    db.save()?;

    println!("Updated {} package(s).", packages.len());
    Ok(())
}

/// Download and write files for a single package, update db entry.
fn install_files(
    name: &str,
    version: &str,
    manifest: &Manifest,
    reason: InstallReason,
    http: &HttpClient,
    db: &mut Database,
) -> io::Result<()> {
    let mut installed_files = BTreeMap::new();

    for (file, dest_dir) in &manifest.files {
        validate_manifest_path(file, dest_dir, name)?;

        let dest = http.config.base_dir.join(dest_dir.replace('/', "\\")).join(file);

        let canonical_base = dunce::canonicalize(&http.config.base_dir)?;
        if !dest.starts_with(&canonical_base) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Install target escapes base dir for {name}: {}", dest.display()),
            ));
        }

        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }

        let bytes = download_file(http,name, version, file)?;
        fs::write(&dest, &bytes)?;
        println!("  {} -> {}", file, dest.display());
        installed_files.insert(file.clone(), dest);
    }

    db.packages.insert(
        name.to_string(),
        InstalledPackage {
            version: version.to_string(),
            reason,
            files: installed_files,
            dependencies: manifest.dependencies.clone(),
            manifest: manifest.clone(),
        },
    );
    Ok(())
}

/// Search for packages on the server matching a regex pattern.
///
/// # Errors
/// Returns an error if the index cannot be fetched or the regex is invalid.
pub fn search(pattern: &str, show_versions: bool, http: &HttpClient) -> io::Result<()> {
    let re = regex::Regex::new(pattern)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid regex: {e}")))?;

    let index = fetch_index(http)?;
    let mut found = false;

    for (name, latest) in &index {
        if re.is_match(name) {
            if show_versions {
                let versions = fetch_versions(http,name)?;
                println!("{name} (latest: {latest}) — versions: {}", versions.join(", "));
            } else {
                println!("{name} {latest}");
            }
            found = true;
        }
    }

    if !found {
        println!("No packages matching '{pattern}'");
    }

    Ok(())
}

/// Find all installed packages that depend on `name`.
fn reverse_deps(name: &str, db: &Database) -> Vec<String> {
    db.packages
        .iter()
        .filter(|(_, pkg)| pkg.dependencies.contains(&name.to_string()))
        .map(|(n, _)| n.clone())
        .collect()
}

/// Find auto-installed dependencies of `name` that no other package needs.
fn orphaned_deps(name: &str, db: &Database) -> Vec<String> {
    let Some(pkg) = db.packages.get(name) else {
        return vec![];
    };

    let mut orphans = Vec::new();
    for dep in &pkg.dependencies {
        let Some(dep_pkg) = db.packages.get(dep) else {
            continue;
        };
        if dep_pkg.reason != InstallReason::Auto {
            continue;
        }
        // Check if any other installed package (besides `name`) depends on this
        let still_needed = db.packages.iter().any(|(n, p)| {
            n != name && p.dependencies.contains(dep)
        });
        if !still_needed {
            orphans.push(dep.clone());
        }
    }
    orphans
}

/// Remove all orphaned auto-installed packages.
fn purge_orphans(db: &mut Database) -> io::Result<()> {
    loop {
        let orphans: Vec<String> = db
            .packages
            .iter()
            .filter(|(_, pkg)| pkg.reason == InstallReason::Auto)
            .filter(|(dep_name, _)| {
                !db.packages
                    .iter()
                    .any(|(_, p)| p.dependencies.contains(dep_name))
            })
            .map(|(n, _)| n.clone())
            .collect();

        if orphans.is_empty() {
            break;
        }

        for orphan in &orphans {
            println!("Removing orphaned dependency {orphan}...");
            remove_package_files(orphan, db)?;
        }
    }
    Ok(())
}

/// Purge all orphaned auto-installed packages and save.
///
/// # Errors
/// Returns an error if file removal or database save fails.
pub fn purge(db: &mut Database) -> io::Result<()> {
    purge_orphans(db)?;
    db.save()
}

/// Remove files for a single package and delete its db entry.
fn remove_package_files(name: &str, db: &mut Database) -> io::Result<()> {
    let Some(pkg) = db.packages.get(name) else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{name} is not installed"),
        ));
    };

    for (file, path) in &pkg.files {
        if path.is_file() {
            fs::remove_file(path)?;
            println!("  Removed {file} ({})", path.display());
        }
    }

    db.packages.remove(name);
    Ok(())
}

/// Remove a package, auto-clean orphaned deps, optionally cascade to dependents.
///
/// # Errors
/// Returns an error if the package is not installed, is depended on (without --force/--transitive),
/// or if file removal fails.
pub fn remove(name: &str, force: bool, transitive: bool, no_purge: bool, db: &mut Database) -> io::Result<()> {
    if !db.packages.contains_key(name) {
        if transitive {
            return Ok(()); // already removed by cascade
        }
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{name} is not installed"),
        ));
    }

    // Check reverse dependencies
    let rdeps = reverse_deps(name, db);
    if !rdeps.is_empty() && !force && !transitive {
        eprintln!("Cannot remove {name}: depended on by:");
        for dep in &rdeps {
            eprintln!("  {dep}");
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Use --force to override, or --transitive to also remove dependents.".to_string(),
        ));
    }

    // --transitive: remove dependents first (upward cascade)
    if transitive {
        for rdep in &rdeps {
            remove(rdep, false, true, true, db)?;
        }
    }

    // Already removed by transitive cascade
    if !db.packages.contains_key(name) {
        return Ok(());
    }

    println!("Removing {name}...");
    remove_package_files(name, db)?;

    if !no_purge {
        purge_orphans(db)?;
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

    /// Start a TLS test server and return (runtime, port, fingerprint).
    fn start_test_server(repo_path: &Path) -> (tokio::runtime::Runtime, u16, String) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let index = crate::repo::RepoIndex::scan(repo_path).unwrap();
        let state = Arc::new(server::AppState { index });
        let app = server::build_router(state);

        // Generate a test cert
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            rcgen::DnValue::Utf8String("test".to_string()),
        );
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_der = cert.der();
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();
        let fingerprint = crate::tls::cert_fingerprint(cert_der.as_ref());

        let rt = tokio::runtime::Runtime::new().unwrap();
        let port = rt.block_on(async {
            // Bind a TCP listener first to get the port
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);

            let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem(
                cert_pem.into_bytes(),
                key_pem.into_bytes(),
            ).await.unwrap();

            let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));

            tokio::spawn(async move {
                axum_server::bind_rustls(addr, tls_config)
                    .serve(app.into_make_service())
                    .await
                    .unwrap();
            });

            // Small delay to let the server start
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            port
        });

        (rt, port, fingerprint)
    }

    fn test_config(port: u16, base_dir: &Path, fingerprint: &str) -> Config {
        Config {
            server_url: format!("https://localhost:{port}"),
            base_dir: base_dir.to_path_buf(),
            username: String::new(),
            password: String::new(),
            server_fingerprint: fingerprint.to_string(),
        }
    }

    #[test]
    fn fetch_index_from_server() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let (_rt, port, fp) = start_test_server(tmp.path());

        let config = test_config(port, Path::new(""), &fp);
        let http = HttpClient::new(&config).unwrap();
        let index = fetch_index(&http).unwrap();
        assert_eq!(index["toolA"], "1.0");
        assert_eq!(index["toolB"], "2.0");
    }

    #[test]
    fn install_single_package() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let install_tmp = tempfile::tempdir().unwrap();
        let db_path = install_tmp.path().join("db.json");
        create_test_repo(repo_tmp.path());
        let (_rt, port, fp) = start_test_server(repo_tmp.path());

        let config = test_config(port, install_tmp.path(), &fp);
        let http = HttpClient::new(&config).unwrap();
        let mut db = Database::load_from(&db_path).unwrap();

        install("toolA", None, false, &http, &mut db).unwrap();

        assert!(install_tmp.path().join("util").join("toolA.exe").exists());
        assert_eq!(db.packages["toolA"].version, "1.0");
    }

    #[test]
    fn install_with_dependency() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let install_tmp = tempfile::tempdir().unwrap();
        let db_path = install_tmp.path().join("db.json");
        create_test_repo(repo_tmp.path());
        let (_rt, port, fp) = start_test_server(repo_tmp.path());

        let config = test_config(port, install_tmp.path(), &fp);
        let http = HttpClient::new(&config).unwrap();
        let mut db = Database::load_from(&db_path).unwrap();

        install("toolB", None, false, &http, &mut db).unwrap();

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
        let (_rt, port, fp) = start_test_server(repo_tmp.path());

        let config = test_config(port, install_tmp.path(), &fp);
        let http = HttpClient::new(&config).unwrap();
        let mut db = Database::load_from(&db_path).unwrap();

        // Install toolB, which auto-installs toolA
        install("toolB", None, false, &http, &mut db).unwrap();
        assert_eq!(db.packages["toolA"].reason, InstallReason::Auto);

        // Explicitly install toolA — should flip to manual
        install("toolA", None, false, &http, &mut db).unwrap();
        assert_eq!(db.packages["toolA"].reason, InstallReason::Manual);
    }

    #[test]
    fn remove_simple_package() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let install_tmp = tempfile::tempdir().unwrap();
        let db_path = install_tmp.path().join("db.json");
        create_test_repo(repo_tmp.path());
        let (_rt, port, fp) = start_test_server(repo_tmp.path());

        let config = test_config(port, install_tmp.path(), &fp);
        let http = HttpClient::new(&config).unwrap();
        let mut db = Database::load_from(&db_path).unwrap();

        install("toolA", None, false, &http, &mut db).unwrap();
        assert!(install_tmp.path().join("util").join("toolA.exe").exists());

        remove("toolA", false, false, false, &mut db).unwrap();
        assert!(!install_tmp.path().join("util").join("toolA.exe").exists());
        assert!(!db.packages.contains_key("toolA"));
    }

    #[test]
    fn remove_blocked_by_dependent() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let install_tmp = tempfile::tempdir().unwrap();
        let db_path = install_tmp.path().join("db.json");
        create_test_repo(repo_tmp.path());
        let (_rt, port, fp) = start_test_server(repo_tmp.path());

        let config = test_config(port, install_tmp.path(), &fp);
        let http = HttpClient::new(&config).unwrap();
        let mut db = Database::load_from(&db_path).unwrap();

        install("toolB", None, false, &http, &mut db).unwrap();

        // toolA is a dep of toolB — remove should fail
        let result = remove("toolA", false, false, false, &mut db);
        assert!(result.is_err());
        // toolA should still be installed
        assert!(db.packages.contains_key("toolA"));
    }

    #[test]
    fn remove_force_ignores_dependents() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let install_tmp = tempfile::tempdir().unwrap();
        let db_path = install_tmp.path().join("db.json");
        create_test_repo(repo_tmp.path());
        let (_rt, port, fp) = start_test_server(repo_tmp.path());

        let config = test_config(port, install_tmp.path(), &fp);
        let http = HttpClient::new(&config).unwrap();
        let mut db = Database::load_from(&db_path).unwrap();

        install("toolB", None, false, &http, &mut db).unwrap();

        // Force remove toolA even though toolB depends on it
        remove("toolA", true, false, false, &mut db).unwrap();
        assert!(!db.packages.contains_key("toolA"));
        assert!(db.packages.contains_key("toolB"));
    }

    #[test]
    fn remove_auto_cleans_orphans() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let install_tmp = tempfile::tempdir().unwrap();
        let db_path = install_tmp.path().join("db.json");
        create_test_repo(repo_tmp.path());
        let (_rt, port, fp) = start_test_server(repo_tmp.path());

        let config = test_config(port, install_tmp.path(), &fp);
        let http = HttpClient::new(&config).unwrap();
        let mut db = Database::load_from(&db_path).unwrap();

        // toolB depends on toolA (auto-installed)
        install("toolB", None, false, &http, &mut db).unwrap();
        assert_eq!(db.packages["toolA"].reason, InstallReason::Auto);

        // Remove toolB: toolA should be auto-cleaned (orphaned auto dep)
        remove("toolB", false, false, false, &mut db).unwrap();
        assert!(!db.packages.contains_key("toolB"));
        assert!(!db.packages.contains_key("toolA"));
        assert!(!install_tmp.path().join("util").join("toolA.exe").exists());
        assert!(!install_tmp.path().join("util").join("toolB.exe").exists());
    }

    #[test]
    fn remove_keeps_manual_deps() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let install_tmp = tempfile::tempdir().unwrap();
        let db_path = install_tmp.path().join("db.json");
        create_test_repo(repo_tmp.path());
        let (_rt, port, fp) = start_test_server(repo_tmp.path());

        let config = test_config(port, install_tmp.path(), &fp);
        let http = HttpClient::new(&config).unwrap();
        let mut db = Database::load_from(&db_path).unwrap();

        // Install toolB (auto-installs toolA), then manually install toolA
        install("toolB", None, false, &http, &mut db).unwrap();
        install("toolA", None, false, &http, &mut db).unwrap();
        assert_eq!(db.packages["toolA"].reason, InstallReason::Manual);

        // Remove toolB: toolA should stay (it's manual)
        remove("toolB", false, false, false, &mut db).unwrap();
        assert!(!db.packages.contains_key("toolB"));
        assert!(db.packages.contains_key("toolA"));
    }

    #[test]
    fn remove_transitive_cascades_upward() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let install_tmp = tempfile::tempdir().unwrap();
        let db_path = install_tmp.path().join("db.json");
        create_test_repo(repo_tmp.path());
        let (_rt, port, fp) = start_test_server(repo_tmp.path());

        let config = test_config(port, install_tmp.path(), &fp);
        let http = HttpClient::new(&config).unwrap();
        let mut db = Database::load_from(&db_path).unwrap();

        // toolB depends on toolA
        install("toolB", None, false, &http, &mut db).unwrap();

        // Remove toolA with --transitive: should also remove toolB
        remove("toolA", false, true, false, &mut db).unwrap();
        assert!(!db.packages.contains_key("toolA"));
        assert!(!db.packages.contains_key("toolB"));
    }

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

    /// Create a diamond-shaped dep tree: C and D both depend on B, B depends on A.
    /// Also toolE v1.0 and v2.0 (v2 adds dep on A).
    fn create_diamond_repo(base: &Path) {
        for (name, ver, deps, file) in [
            ("depA", "1.0", "[]", "depA.exe"),
            ("depB", "1.0", r#"["depA"]"#, "depB.exe"),
            ("depC", "1.0", r#"["depB"]"#, "depC.exe"),
            ("depD", "1.0", r#"["depB"]"#, "depD.exe"),
            ("toolE", "1.0", "[]", "toolE.exe"),
            ("toolE", "2.0", r#"["depA"]"#, "toolE.exe"),
        ] {
            let dir = base.join("packages").join(name).join(ver);
            fs::create_dir_all(&dir).unwrap();
            fs::write(
                dir.join("blob.json"),
                format!(r#"{{"name":"{name}","description":"","files":{{"{file}":"util/"}},"dependencies":{deps}}}"#),
            ).unwrap();
            fs::write(dir.join(file), format!("{name}-{ver}-binary").as_bytes()).unwrap();
        }
    }

    #[test]
    fn diamond_deps_installed_once() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let install_tmp = tempfile::tempdir().unwrap();
        let db_path = install_tmp.path().join("db.json");
        create_diamond_repo(repo_tmp.path());
        let (_rt, port, fp) = start_test_server(repo_tmp.path());

        let config = test_config(port, install_tmp.path(), &fp);
        let http = HttpClient::new(&config).unwrap();
        let mut db = Database::load_from(&db_path).unwrap();

        // Install C and D — both depend on B which depends on A
        install("depC", None, false, &http, &mut db).unwrap();
        install("depD", None, false, &http, &mut db).unwrap();
        assert_eq!(db.packages.len(), 4); // A, B, C, D
        assert_eq!(db.packages["depA"].reason, InstallReason::Auto);
        assert_eq!(db.packages["depB"].reason, InstallReason::Auto);
    }

    #[test]
    fn diamond_remove_one_branch_keeps_shared_dep() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let install_tmp = tempfile::tempdir().unwrap();
        let db_path = install_tmp.path().join("db.json");
        create_diamond_repo(repo_tmp.path());
        let (_rt, port, fp) = start_test_server(repo_tmp.path());

        let config = test_config(port, install_tmp.path(), &fp);
        let http = HttpClient::new(&config).unwrap();
        let mut db = Database::load_from(&db_path).unwrap();

        install("depC", None, false, &http, &mut db).unwrap();
        install("depD", None, false, &http, &mut db).unwrap();

        // Remove C — B and A should stay because D still needs B
        remove("depC", false, false, false, &mut db).unwrap();
        assert!(!db.packages.contains_key("depC"));
        assert!(db.packages.contains_key("depB"));
        assert!(db.packages.contains_key("depA"));
    }

    #[test]
    fn diamond_remove_both_branches_cleans_all() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let install_tmp = tempfile::tempdir().unwrap();
        let db_path = install_tmp.path().join("db.json");
        create_diamond_repo(repo_tmp.path());
        let (_rt, port, fp) = start_test_server(repo_tmp.path());

        let config = test_config(port, install_tmp.path(), &fp);
        let http = HttpClient::new(&config).unwrap();
        let mut db = Database::load_from(&db_path).unwrap();

        install("depC", None, false, &http, &mut db).unwrap();
        install("depD", None, false, &http, &mut db).unwrap();

        // Remove C, then D — everything should be cleaned up
        remove("depC", false, false, false, &mut db).unwrap();
        remove("depD", false, false, false, &mut db).unwrap();
        assert!(db.packages.is_empty());
    }

    #[test]
    fn transitive_remove_with_diamond() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let install_tmp = tempfile::tempdir().unwrap();
        let db_path = install_tmp.path().join("db.json");
        create_diamond_repo(repo_tmp.path());
        let (_rt, port, fp) = start_test_server(repo_tmp.path());

        let config = test_config(port, install_tmp.path(), &fp);
        let http = HttpClient::new(&config).unwrap();
        let mut db = Database::load_from(&db_path).unwrap();

        install("depC", None, false, &http, &mut db).unwrap();
        install("depD", None, false, &http, &mut db).unwrap();

        // Transitive remove A — should cascade up through B to C and D
        remove("depA", false, true, false, &mut db).unwrap();
        assert!(db.packages.is_empty());
    }

    #[test]
    fn update_installs_new_deps() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let install_tmp = tempfile::tempdir().unwrap();
        let db_path = install_tmp.path().join("db.json");
        create_diamond_repo(repo_tmp.path());
        let (_rt, port, fp) = start_test_server(repo_tmp.path());

        let config = test_config(port, install_tmp.path(), &fp);
        let http = HttpClient::new(&config).unwrap();
        let mut db = Database::load_from(&db_path).unwrap();

        // Install toolE v1.0 (no deps)
        install("toolE", Some("1.0"), false, &http, &mut db).unwrap();
        assert_eq!(db.packages.len(), 1);

        // Update — toolE goes to v2.0 which depends on depA
        update(None, &http, &mut db).unwrap();
        assert_eq!(db.packages["toolE"].version, "2.0");
        assert!(db.packages.contains_key("depA"));
    }

    #[test]
    fn remove_nonexistent_package_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("db.json");
        let mut db = Database::load_from(&db_path).unwrap();

        let result = remove("nonexistent", false, false, false, &mut db);
        assert!(result.is_err());
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

        let (_rt, port, fp) = start_test_server(tmp.path());

        let config = test_config(port, Path::new(""), &fp);
        let http = HttpClient::new(&config).unwrap();
        let index = fetch_index(&http).unwrap();
        let db = Database { packages: BTreeMap::new(), path: None };
        let result = resolve_dependencies("cycleA", "1.0", &http, &index, &db);
        assert!(result.is_err());
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
            path: None,
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
            path: None,
        };
        let json = serde_json::to_string(&db).unwrap();
        let loaded: Database = serde_json::from_str(&json).unwrap();
        assert!(loaded.packages.is_empty());
    }
}
