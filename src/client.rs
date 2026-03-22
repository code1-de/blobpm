use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::{fs, io};

use crate::repo::Manifest;

/// Validate that a package name or version contains only safe characters.
/// Allowed: printable ASCII 33–126, excluding `/\,:;*?'"` and whitespace.
/// Must not be empty, start with `.`, or end with `.` or space.
pub(crate) const FORBIDDEN_SPEC_CHARS: &[u8] = b"/\\,:;*?'`\"";

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

// TODO: Security: restrict file permissions on config.json to owner-only (contains password in plaintext)
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
        fs::write(&path, content)
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

    fn get(&self, url: &str) -> io::Result<reqwest::blocking::Response> {
        self.send(self.client.get(url))
    }

    fn post(&self, url: &str, body: Vec<u8>) -> io::Result<reqwest::blocking::Response> {
        self.send(self.client.post(url).body(body))
    }
}

/// Fetch the package index from the server.
///
/// # Errors
/// Returns an error if the HTTP request fails or the response is not valid JSON.
pub fn fetch_index(http: &HttpClient) -> io::Result<BTreeMap<String, String>> {
    let url = format!("{}/index", http.config.server_url);
    let resp = http.get(&url)?;
    resp.json().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Fetch available versions for a package from the server.
///
/// # Errors
/// Returns an error if the HTTP request fails or the response is not valid JSON.
pub fn fetch_versions(http: &HttpClient, name: &str) -> io::Result<Vec<String>> {
    let url = format!("{}/packages/{name}", http.config.server_url);
    let resp = http.get(&url)?;
    if !resp.status().is_success() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("Package {name} not found")));
    }
    let value: serde_json::Value = resp.json().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
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
    let url = format!("{}/packages/{name}/{version}/manifest.json", http.config.server_url);
    let resp = http.get(&url)?;
    if !resp.status().is_success() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("Package {name} {version} not found")));
    }
    let manifest: Manifest = resp.json().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if manifest.name != name {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Manifest name mismatch for {name}: manifest contains '{}'", manifest.name),
        ));
    }
    Ok(manifest)
}

/// Download a package zip to the cache. Returns the path to the cached zip.
///
/// # Errors
/// Returns an error if the HTTP request fails or the file cannot be written.
fn cache_zip_path_in(name: &str, version: &str, base_dir: &Path) -> PathBuf {
    base_dir.join(".cache").join(name).join(version).join("files.zip")
}

fn download_zip(http: &HttpClient, name: &str, version: &str) -> io::Result<PathBuf> {
    let zip_path = cache_zip_path_in(name, version, &http.config.base_dir);
    // TODO: Security: verify cached zip integrity (hash) against server-provided checksum to prevent cache poisoning
    if zip_path.is_file() {
        return Ok(zip_path);
    }
    if let Some(parent) = zip_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let url = format!("{}/packages/{name}/{version}/files.zip", http.config.server_url);
    let resp = http.get(&url)?;
    if !resp.status().is_success() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("Package {name} {version} not found on server")));
    }
    let bytes = resp.bytes().map_err(io::Error::other)?;
    fs::write(&zip_path, &bytes)?;
    Ok(zip_path)
}

/// Extract files from a zip to target directories based on the manifest.
///
/// # Errors
/// Returns an error if extraction or path validation fails.
/// Maximum decompressed file size (1 GB) — zip bomb protection.
const MAX_EXTRACT_SIZE: u64 = 1024 * 1024 * 1024;

/// Maximum total decompressed size across all files in a package (2 GB) — aggregate zip bomb protection.
const MAX_TOTAL_EXTRACT_SIZE: u64 = 2 * 1024 * 1024 * 1024;

/// Maximum number of entries in a zip archive — prevents inode exhaustion from many tiny files.
const MAX_ZIP_ENTRIES: usize = 50_000;

fn extract_zip(
    zip_path: &Path,
    manifest: &Manifest,
    base_dir: &Path,
    name: &str,
) -> io::Result<BTreeMap<String, PathBuf>> {
    let canonical_base = dunce::canonicalize(base_dir)?;
    let zip_file = fs::File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(zip_file)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Invalid zip for {name}: {e}")))?;

    if archive.len() > MAX_ZIP_ENTRIES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Zip for {name} has {} entries (max {MAX_ZIP_ENTRIES})", archive.len()),
        ));
    }

    let mut installed_files = BTreeMap::new();
    let mut total_written: u64 = 0;

    for (file, dest_dir) in &manifest.files {
        validate_manifest_path(file, dest_dir, name)?;

        let dest = canonical_base.join(dest_dir.replace('/', "\\")).join(file);
        if !dest.starts_with(&canonical_base) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Install target escapes base dir for {name}: {}", dest.display()),
            ));
        }

        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
            // Defense in depth: verify canonical path is still inside base after mkdir (catches symlink escapes)
            let canonical_parent = dunce::canonicalize(parent)?;
            if !canonical_parent.starts_with(&canonical_base) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Install target escapes base dir for {name}: {}", canonical_parent.display()),
                ));
            }
        }

        let mut entry = archive
            .by_name(file)
            .map_err(|e| io::Error::new(io::ErrorKind::NotFound, format!("File {file} not in zip for {name}: {e}")))?;

        if entry.size() > MAX_EXTRACT_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("File {file} in {name} exceeds max size ({} bytes)", entry.size()),
            ));
        }

        let mut out = fs::File::create(&dest)?;
        let written = io::copy(&mut entry, &mut out)?;
        if written > MAX_EXTRACT_SIZE {
            fs::remove_file(&dest)?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("File {file} in {name} exceeded max size during extraction"),
            ));
        }

        total_written = total_written.saturating_add(written);
        if total_written > MAX_TOTAL_EXTRACT_SIZE {
            fs::remove_file(&dest)?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Total extraction size exceeds 2 GB limit for {name}"),
            ));
        }

        println!("  {} -> {}", file, dest.display());
        installed_files.insert(file.clone(), dest);
    }

    Ok(installed_files)
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

#[allow(clippy::too_many_arguments)]
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
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("Dependency cycle detected: {name}")));
    }

    in_stack.insert(name.to_string());

    let version = match version_override {
        Some(v) => v.to_string(),
        None => index
            .get(name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("Package {name} not found in index")))?
            .clone(),
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
pub(crate) const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2",
    "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
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

/// Install a package and its dependencies.
///
/// # Errors
/// Returns an error if fetching, downloading, or writing files fails.
pub fn install(name: &str, version: Option<&str>, force: bool, http: &HttpClient, db: &mut Database) -> io::Result<()> {
    validate_pkg_spec("package name", name)?;
    if let Some(v) = version {
        validate_pkg_spec("version", v)?;
    }
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

    let index = fetch_index(http)?;

    // Determine which version to install
    let target_version = match version {
        Some(v) => v.to_string(),
        None => index
            .get(name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("Package {name} not found in index")))?
            .clone(),
    };

    let to_install = resolve_dependencies(name, &target_version, http, &index, db)?;

    if to_install.is_empty() {
        println!("{name} is already installed");
        return Ok(());
    }

    download_and_install(&to_install, name, http, db)?;

    // Clean up orphaned auto-deps (e.g. after --force changed the dep tree)
    purge_orphans(db)?;

    db.save()?;
    Ok(())
}

/// Download all zips then extract all. `manual_name` is the top-level package (marked manual).
fn download_and_install(
    packages: &[(String, String, Manifest)],
    manual_name: &str,
    http: &HttpClient,
    db: &mut Database,
) -> io::Result<()> {
    // Phase 1: download all zips
    println!("Downloading {} package(s)...", packages.len());
    let mut downloads: Vec<(&str, &str, &Manifest, PathBuf)> = Vec::new();
    for (pkg_name, version, manifest) in packages {
        let zip_path = download_zip(http, pkg_name, version)?;
        println!("  Downloaded {pkg_name} {version}");
        downloads.push((pkg_name, version, manifest, zip_path));
    }

    // Phase 2: extract all
    for (pkg_name, version, manifest, zip_path) in &downloads {
        let reason = if *pkg_name == manual_name { InstallReason::Manual } else { InstallReason::Auto };

        println!("Installing {pkg_name} {version}...");
        let installed_files = extract_zip(zip_path, manifest, &http.config.base_dir, pkg_name)?;

        db.packages.insert(
            pkg_name.to_string(),
            InstalledPackage {
                version: version.to_string(),
                reason,
                files: installed_files,
                dependencies: manifest.dependencies.clone(),
            },
        );
        println!("  Installed {pkg_name} {version}");
    }
    Ok(())
}

/// Update installed packages to their latest versions.
/// If `name` is given, update only that package. Otherwise update all.
///
/// # Errors
/// Returns an error if fetching, downloading, or writing files fails.
pub fn update(name: Option<&str>, http: &HttpClient, db: &mut Database) -> io::Result<()> {
    let index = fetch_index(http)?;

    let packages: Vec<(String, String)> = if let Some(n) = name {
        if !db.packages.contains_key(n) {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("{n} is not installed")));
        }
        let latest =
            index.get(n).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{n} not found in index")))?;
        if *latest == db.packages[n].version {
            println!("{n} is already at latest version ({latest}).");
            return Ok(());
        }
        vec![(n.to_string(), latest.clone())]
    } else {
        let mut list = Vec::new();
        for (n, pkg) in &db.packages {
            if let Some(latest) = index.get(n)
                && *latest != pkg.version
            {
                list.push((n.clone(), latest.clone()));
            }
        }
        if list.is_empty() {
            println!("Everything is up to date.");
            return Ok(());
        }
        list
    };

    for (pkg_name, new_version) in &packages {
        let old_version = db.packages[pkg_name].version.clone();
        println!("Updating {pkg_name} {old_version} -> {new_version}...");

        let resolved = resolve_dependencies(pkg_name, new_version, http, &index, db)?;

        // Remove old files that are no longer in the new manifest
        if let Some(new_manifest) = resolved.iter().find(|(n, _, _)| n == pkg_name).map(|(_, _, m)| m)
            && let Some(old_pkg) = db.packages.get(pkg_name)
        {
            for (old_file, old_path) in &old_pkg.files {
                if !new_manifest.files.contains_key(old_file) && old_path.is_file() {
                    fs::remove_file(old_path)?;
                    println!("  Removed old file {old_file}");
                }
            }
        }

        // Filter to only packages that need installing (skip already-installed deps)
        let to_install: Vec<_> =
            resolved.into_iter().filter(|(n, _, _)| n == pkg_name || !db.packages.contains_key(n)).collect();

        // Use a sentinel — download_and_install marks main as Manual,
        // but for updates we preserve the original reason
        let original_reason = db.packages.get(pkg_name).map_or(InstallReason::Manual, |p| p.reason);
        download_and_install(&to_install, pkg_name, http, db)?;
        if let Some(pkg) = db.packages.get_mut(pkg_name) {
            pkg.reason = original_reason;
        }
    }

    purge_orphans(db)?;
    db.save()?;

    println!("Updated {} package(s).", packages.len());
    Ok(())
}

/// Search for packages on the server matching a regex pattern.
///
/// # Errors
/// Returns an error if the index cannot be fetched or the regex is invalid.
pub fn search(pattern: &str, show_versions: bool, http: &HttpClient) -> io::Result<()> {
    if pattern.len() > 1024 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Regex pattern too long (max 1024 bytes)"));
    }
    let re = regex::Regex::new(pattern)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid regex: {e}")))?;

    let index = fetch_index(http)?;
    let mut found = false;

    for (name, latest) in &index {
        if re.is_match(name) {
            if show_versions {
                let versions = fetch_versions(http, name)?;
                println!("{name} — {}", versions.join(", "));
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

/// Parse mapping rules ("`glob:dest_dir`/") and match files.
/// Absolute globs use basename as filename. Relative globs use path relative to `from`.
/// Returns a map of (filename → `dest_dir`) and a map of (filename → absolute source path).
fn resolve_mappings(
    from: &Path,
    mappings: &[String],
) -> io::Result<(BTreeMap<String, String>, BTreeMap<String, PathBuf>)> {
    let mut files = BTreeMap::new();
    let mut sources = BTreeMap::new();
    let mut from_cache: Option<PathBuf> = None;

    for mapping in mappings {
        let (pattern, dest) = mapping.rsplit_once(':').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid mapping (missing ':'): {mapping}"))
        })?;

        let is_absolute = Path::new(pattern).is_absolute() || (pattern.len() >= 2 && pattern.as_bytes()[1] == b':');

        let full_pattern = if is_absolute {
            pattern.to_string()
        } else {
            let base = if let Some(p) = &from_cache {
                p.clone()
            } else {
                let p = dunce::canonicalize(from)?;
                from_cache = Some(p.clone());
                p
            };
            base.join(pattern).to_string_lossy().to_string()
        };

        let matched = glob::glob(&full_pattern)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid glob '{pattern}': {e}")))?;

        for entry in matched {
            let path = entry.map_err(|e| io::Error::other(format!("Glob error: {e}")))?;
            if !path.is_file() {
                continue;
            }
            let name = if is_absolute {
                path.file_name().ok_or_else(|| io::Error::other("No filename"))?.to_string_lossy().to_string()
            } else {
                let base = from_cache.as_ref().ok_or_else(|| io::Error::other("No base path"))?;
                path.strip_prefix(base)
                    .map_err(|e| io::Error::other(format!("Path error: {e}")))?
                    .to_string_lossy()
                    .replace('\\', "/")
            };
            if !files.contains_key(&name) {
                files.insert(name.clone(), dest.to_string());
                sources.insert(name, path);
            }
        }
    }

    if files.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "No files matched the mapping patterns"));
    }

    Ok((files, sources))
}

/// Create a zip file from source paths.
/// Note: loads all files into memory. This is acceptable for typical package sizes.
// TODO: for very large packages (thousands of files), consider streaming to a temp file instead.
fn create_package_zip(sources: &BTreeMap<String, PathBuf>) -> io::Result<Vec<u8>> {
    let mut buf = io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buf);
        let options = zip::write::SimpleFileOptions::default();
        for (zip_name, src_path) in sources {
            let content = fs::read(src_path)?;
            zip.start_file(zip_name, options).map_err(|e| io::Error::other(format!("Zip error: {e}")))?;
            io::Write::write_all(&mut zip, &content)?;
        }
        zip.finish().map_err(|e| io::Error::other(format!("Zip error: {e}")))?;
    }
    Ok(buf.into_inner())
}

/// Upload a package to the server.
///
/// # Errors
/// Returns an error if glob matching, zip creation, or upload fails.
#[allow(clippy::too_many_arguments)]
pub fn upload(
    name: &str,
    version: &str,
    from: &Path,
    mappings: &[String],
    deps: &[String],
    description: &str,
    force: bool,
    http: &HttpClient,
) -> io::Result<()> {
    validate_pkg_spec("package name", name)?;
    validate_pkg_spec("version", version)?;
    // Check if version already exists on server
    if !force {
        let versions = fetch_versions(http, name).unwrap_or_default();
        if versions.contains(&version.to_string()) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{name}@{version} already exists on server. Use --force to overwrite."),
            ));
        }
    }

    let (files, sources) = resolve_mappings(from, mappings)?;

    println!("Package: {name}@{version}");
    println!("Files: {}", files.len());
    for (file, dest) in &files {
        println!("  {file} -> {dest}");
    }

    let manifest = crate::repo::Manifest {
        name: name.to_string(),
        description: description.to_string(),
        files,
        dependencies: deps.to_vec(),
    };

    let manifest_json =
        serde_json::to_string_pretty(&manifest).map_err(|e| io::Error::other(format!("JSON error: {e}")))?;
    let zip_data = create_package_zip(&sources)?;

    println!("Uploading {name}@{version} ({} bytes)...", zip_data.len());

    // Upload zip first, then manifest (server updates index on manifest upload,
    // so if zip upload fails, the package won't appear in the index)
    let url = format!("{}/upload/{name}/{version}/files.zip", http.config.server_url);
    let resp = http.post(&url, zip_data)?;
    if !resp.status().is_success() {
        return Err(io::Error::other(format!("Failed to upload zip: {}", resp.status())));
    }

    let url = format!("{}/upload/{name}/{version}/manifest.json", http.config.server_url);
    let resp = http.post(&url, manifest_json.into_bytes())?;
    if !resp.status().is_success() {
        return Err(io::Error::other(format!("Failed to upload manifest: {}", resp.status())));
    }

    println!("Uploaded {name}@{version}");
    Ok(())
}

pub fn prompt_line(label: &str, default: &str) -> io::Result<String> {
    if default.is_empty() {
        print!("{label}: ");
    } else {
        print!("{label} [{default}]: ");
    }
    io::Write::flush(&mut io::stdout())?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim();
    if input.is_empty() { Ok(default.to_string()) } else { Ok(input.to_string()) }
}

/// Interactive upload — review and edit all fields before uploading.
///
/// # Errors
/// Returns an error if the upload fails.
#[allow(clippy::too_many_arguments)]
pub fn upload_interactive(
    name: &str,
    version: &str,
    from: &Path,
    existing_mappings: &[String],
    existing_deps: &[String],
    existing_desc: &str,
    force: bool,
    http: &HttpClient,
) -> io::Result<()> {
    println!("Upload {name}@{version} from {}", from.display());

    // Show existing mappings, allow adding more
    let mut mappings: Vec<String> = existing_mappings.to_vec();
    if !mappings.is_empty() {
        println!("Current mappings:");
        for m in &mappings {
            println!("  {m}");
        }
    }
    println!("Enter additional file mappings (glob:dest_dir/), empty line to finish:");
    loop {
        print!("  mapping> ");
        io::Write::flush(&mut io::stdout())?;
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        let line = line.trim();
        if line.is_empty() {
            break;
        }
        mappings.push(line.to_string());
    }

    if mappings.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "No mappings provided"));
    }

    let description = prompt_line("Description", existing_desc)?;

    let deps_default = existing_deps.join(", ");
    let deps_str = prompt_line("Dependencies (comma-separated)", &deps_default)?;
    let deps: Vec<String> = deps_str.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect();

    upload(name, version, from, &mappings, &deps, &description, force, http)
}

/// Find all installed packages that depend on `name`.
fn reverse_deps(name: &str, db: &Database) -> Vec<String> {
    db.packages.iter().filter(|(_, pkg)| pkg.dependencies.contains(&name.to_string())).map(|(n, _)| n.clone()).collect()
}

// TODO: build reverse-dep index for O(n) lookup instead of O(n²) per iteration
/// Remove all orphaned auto-installed packages.
fn purge_orphans(db: &mut Database) -> io::Result<()> {
    loop {
        let orphans: Vec<String> = db
            .packages
            .iter()
            .filter(|(_, pkg)| pkg.reason == InstallReason::Auto)
            .filter(|(dep_name, _)| !db.packages.iter().any(|(_, p)| p.dependencies.contains(dep_name)))
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
    let before = db.packages.len();
    purge_orphans(db)?;
    let removed = before - db.packages.len();
    if removed == 0 {
        println!("No orphaned packages found.");
    } else {
        println!("Purged {removed} orphaned package(s).");
    }
    db.save()
}

/// Remove files for a single package and delete its db entry.
fn remove_package_files(name: &str, db: &mut Database) -> io::Result<()> {
    let Some(pkg) = db.packages.get(name) else {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("{name} is not installed")));
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
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("{name} is not installed")));
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
        db.save()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::testutil::helpers::create_zip;

    fn create_test_repo(base: &Path) {
        let pkg_dir = base.join("packages").join("toolA").join("1.0");
        fs::create_dir_all(&pkg_dir).unwrap();
        fs::write(
            pkg_dir.join("manifest.json"),
            r#"{"name":"toolA","description":"Tool A","files":{"toolA.exe":"util/"},"dependencies":[]}"#,
        )
        .unwrap();
        create_zip(&pkg_dir, &[("toolA.exe", b"toolA-binary")]);

        let pkg_dir2 = base.join("packages").join("toolB").join("2.0");
        fs::create_dir_all(&pkg_dir2).unwrap();
        fs::write(
            pkg_dir2.join("manifest.json"),
            r#"{"name":"toolB","description":"Tool B","files":{"toolB.exe":"util/"},"dependencies":["toolA"]}"#,
        )
        .unwrap();
        create_zip(&pkg_dir2, &[("toolB.exe", b"toolB-binary")]);
    }

    use crate::testutil::helpers::{TEST_PASS, TEST_USER, start_tls_server};

    fn test_config(port: u16, base_dir: &Path, fingerprint: &str) -> Config {
        Config {
            server_url: format!("https://localhost:{port}"),
            base_dir: base_dir.to_path_buf(),
            username: TEST_USER.to_string(),
            password: TEST_PASS.to_string(),
            server_fingerprint: fingerprint.to_string(),
        }
    }

    #[test]
    fn fetch_index_from_server() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let (_rt, port, fp) = start_tls_server(tmp.path());

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
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());

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
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());

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
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());

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
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());

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
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());

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
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());

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
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());

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
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());

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
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());

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
                dir.join("manifest.json"),
                format!(r#"{{"name":"{name}","description":"","files":{{"{file}":"util/"}},"dependencies":{deps}}}"#),
            )
            .unwrap();
            create_zip(&dir, &[(file, format!("{name}-{ver}-binary").as_bytes())]);
        }
    }

    #[test]
    fn diamond_deps_installed_once() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let install_tmp = tempfile::tempdir().unwrap();
        let db_path = install_tmp.path().join("db.json");
        create_diamond_repo(repo_tmp.path());
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());

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
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());

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
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());

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
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());

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
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());

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
            pkg_a.join("manifest.json"),
            r#"{"name":"cycleA","description":"A","files":{},"dependencies":["cycleB"]}"#,
        )
        .unwrap();

        let pkg_b = tmp.path().join("packages").join("cycleB").join("1.0");
        fs::create_dir_all(&pkg_b).unwrap();
        fs::write(
            pkg_b.join("manifest.json"),
            r#"{"name":"cycleB","description":"B","files":{},"dependencies":["cycleA"]}"#,
        )
        .unwrap();

        let (_rt, port, fp) = start_tls_server(tmp.path());

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

    #[test]
    fn cache_reuse_skips_download() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let install_tmp = tempfile::tempdir().unwrap();
        let db_path = install_tmp.path().join("db.json");
        create_test_repo(repo_tmp.path());
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());

        let config = test_config(port, install_tmp.path(), &fp);
        let http = HttpClient::new(&config).unwrap();
        let mut db = Database::load_from(&db_path).unwrap();

        // Install toolA — downloads zip to cache
        install("toolA", None, false, &http, &mut db).unwrap();
        let cache_path = cache_zip_path_in("toolA", "1.0", install_tmp.path());
        assert!(cache_path.is_file());

        // Remove toolA but keep cache
        remove("toolA", false, false, false, &mut db).unwrap();
        assert!(cache_path.is_file()); // cache should still exist

        // Reinstall — should reuse cache (no download needed)
        install("toolA", None, false, &http, &mut db).unwrap();
        assert!(install_tmp.path().join("util").join("toolA.exe").exists());
    }

    #[test]
    fn download_all_before_install() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let install_tmp = tempfile::tempdir().unwrap();
        let db_path = install_tmp.path().join("db.json");
        create_test_repo(repo_tmp.path());
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());

        let config = test_config(port, install_tmp.path(), &fp);
        let http = HttpClient::new(&config).unwrap();
        let mut db = Database::load_from(&db_path).unwrap();

        // Install toolB (depends on toolA) — both zips should be cached
        install("toolB", None, false, &http, &mut db).unwrap();
        assert!(cache_zip_path_in("toolA", "1.0", install_tmp.path()).is_file());
        assert!(cache_zip_path_in("toolB", "2.0", install_tmp.path()).is_file());
        assert!(install_tmp.path().join("util").join("toolA.exe").exists());
        assert!(install_tmp.path().join("util").join("toolB.exe").exists());
    }

    #[test]
    fn failed_download_leaves_nothing_installed() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let install_tmp = tempfile::tempdir().unwrap();
        let db_path = install_tmp.path().join("db.json");

        // Create repo with toolC that depends on "missing" (which doesn't exist)
        let pkg_dir = repo_tmp.path().join("packages").join("missing_dep").join("1.0");
        fs::create_dir_all(&pkg_dir).unwrap();
        fs::write(
            pkg_dir.join("manifest.json"),
            r#"{"name":"missing_dep","description":"","files":{"x.exe":"util/"},"dependencies":["nonexistent"]}"#,
        )
        .unwrap();
        create_zip(&pkg_dir, &[("x.exe", b"binary")]);

        let (_rt, port, fp) = start_tls_server(repo_tmp.path());
        let config = test_config(port, install_tmp.path(), &fp);
        let http = HttpClient::new(&config).unwrap();
        let mut db = Database::load_from(&db_path).unwrap();

        // Install should fail because "nonexistent" dep isn't in the index
        let result = install("missing_dep", None, false, &http, &mut db);
        assert!(result.is_err());
        // Nothing should be installed
        assert!(db.packages.is_empty());
        assert!(!install_tmp.path().join("util").join("x.exe").exists());
    }

    #[test]
    fn extract_zip_missing_file_in_archive() {
        let tmp = tempfile::tempdir().unwrap();

        // Create a zip with only "a.exe" but manifest expects "b.exe"
        create_zip(tmp.path(), &[("a.exe", b"binary-a")]);

        let manifest = crate::repo::Manifest {
            name: "bad".to_string(),
            description: "bad".to_string(),
            files: BTreeMap::from([("b.exe".to_string(), "util/".to_string())]),
            dependencies: vec![],
        };

        let base = tmp.path().join("install");
        fs::create_dir_all(&base).unwrap();

        let result = extract_zip(&tmp.path().join("files.zip"), &manifest, &base, "bad");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("b.exe"));
    }

    #[test]
    fn upload_and_install_roundtrip() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let install_tmp = tempfile::tempdir().unwrap();
        let src_tmp = tempfile::tempdir().unwrap();
        let db_path = install_tmp.path().join("db.json");

        // Create empty repo, start server
        fs::create_dir_all(repo_tmp.path().join("packages")).unwrap();
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());
        let config = test_config(port, install_tmp.path(), &fp);
        let http = HttpClient::new(&config).unwrap();

        // Create a source file
        fs::write(src_tmp.path().join("tool.exe"), b"tool-binary").unwrap();

        // Upload
        upload("newtool", "1.0", src_tmp.path(), &["*.exe:util/".to_string()], &[], "A new tool", false, &http)
            .unwrap();

        // Verify it appears in index
        let index = fetch_index(&http).unwrap();
        assert_eq!(index["newtool"], "1.0");

        // Install it
        let mut db = Database::load_from(&db_path).unwrap();
        install("newtool", None, false, &http, &mut db).unwrap();
        assert!(install_tmp.path().join("util").join("tool.exe").exists());
    }
}
