use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::{fs, io};

use crate::client::{validate_manifest_path, validate_pkg_spec, Database, HttpClient, InstallReason, InstalledPackage};
use crate::remove::purge_orphans;
use crate::repo::Manifest;

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
pub(crate) fn cache_zip_path_in(name: &str, version: &str, base_dir: &Path) -> PathBuf {
    base_dir.join(".cache").join(name).join(version).join("files.zip")
}

fn download_zip(http: &HttpClient, name: &str, version: &str) -> io::Result<PathBuf> {
    let zip_path = cache_zip_path_in(name, version, &http.config.base_dir);
    // TODO: Security: sign zips on server, verify signature on client before extraction
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

/// Delete cached files older than `max_age_days` (0 = delete all). Silently skips errors.
pub fn clean_cache(base_dir: &Path, max_age_days: u32) {
    let cache_dir = base_dir.join(".cache");
    if !cache_dir.is_dir() {
        return;
    }
    let max_age = std::time::Duration::from_secs(u64::from(max_age_days) * 86400);
    let mut removed = 0u32;
    let Ok(packages) = fs::read_dir(&cache_dir) else { return };
    for pkg_entry in packages.flatten() {
        let Ok(versions) = fs::read_dir(pkg_entry.path()) else { continue };
        for ver_entry in versions.flatten() {
            let Ok(meta) = ver_entry.path().join("files.zip").metadata() else { continue };
            let stale = meta
                .modified()
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age > max_age);
            if stale {
                let pkg_name = pkg_entry.file_name();
                let ver_name = ver_entry.file_name();
                if fs::remove_dir_all(ver_entry.path()).is_ok() {
                    println!("  Removed {}/{}", pkg_name.to_string_lossy(), ver_name.to_string_lossy());
                    removed += 1;
                }
            }
        }
        // Remove empty package dirs
        if fs::read_dir(pkg_entry.path()).is_ok_and(|mut d| d.next().is_none()) {
            let _ = fs::remove_dir(pkg_entry.path());
        }
    }
    if removed > 0 {
        println!("Cleaned {removed} stale cache entries (older than {max_age_days} day(s))");
    }
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

        let dest = canonical_base.join(crate::platform::to_native_path(dest_dir)).join(file);
        if !dest.starts_with(&canonical_base) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Install target escapes base dir for {name}: {}", dest.display()),
            ));
        }

        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
            // Defense in depth: verify canonical path is still inside base after mkdir (catches symlink escapes).
            // Known TOCTOU race: a local attacker with write access to base_dir could swap the directory
            // between this check and File::create below. Accepted by design — such an attacker already
            // has equivalent access to overwrite installed files directly.
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

    validate_pkg_spec("dependency", name)?;
    in_stack.insert(name.to_string());

    let version = match version_override {
        Some(v) => v.to_string(),
        None => index
            .get(name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("Package {name} not found in index")))?
            .clone(),
    };
    validate_pkg_spec("version", &version)?;

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

/// Install a package and its dependencies.
///
/// # Errors
/// Returns an error if fetching, downloading, or writing files fails.
pub fn install(name: &str, version: Option<&str>, force: bool, http: &HttpClient, db: &mut Database) -> io::Result<()> {
    clean_cache(&http.config.base_dir, http.config.cache_days);
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
    clean_cache(&http.config.base_dir, http.config.cache_days);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{Config, Database, InstallReason};
    use crate::remove::remove;
    use crate::testutil::helpers::{TEST_PASS, TEST_USER, create_zip, start_tls_server};
    use std::collections::BTreeMap;
    use std::path::Path;

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

    fn test_config(port: u16, base_dir: &Path, fingerprint: &str) -> Config {
        Config {
            server_url: format!("https://localhost:{port}"),
            base_dir: base_dir.to_path_buf(),
            username: TEST_USER.to_string(),
            password: TEST_PASS.to_string(),
            server_fingerprint: fingerprint.to_string(),
            cache_days: 0,
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

        install("toolB", None, false, &http, &mut db).unwrap();
        assert_eq!(db.packages["toolA"].reason, InstallReason::Auto);

        install("toolA", None, false, &http, &mut db).unwrap();
        assert_eq!(db.packages["toolA"].reason, InstallReason::Manual);
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

        install("depC", None, false, &http, &mut db).unwrap();
        install("depD", None, false, &http, &mut db).unwrap();
        assert_eq!(db.packages.len(), 4);
        assert_eq!(db.packages["depA"].reason, InstallReason::Auto);
        assert_eq!(db.packages["depB"].reason, InstallReason::Auto);
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

        install("toolE", Some("1.0"), false, &http, &mut db).unwrap();
        assert_eq!(db.packages.len(), 1);

        update(None, &http, &mut db).unwrap();
        assert_eq!(db.packages["toolE"].version, "2.0");
        assert!(db.packages.contains_key("depA"));
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
        let db = Database::load_from(Path::new("")).unwrap();
        let result = resolve_dependencies("cycleA", "1.0", &http, &index, &db);
        assert!(result.is_err());
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

        install("toolA", None, false, &http, &mut db).unwrap();
        let cache_path = cache_zip_path_in("toolA", "1.0", install_tmp.path());
        assert!(cache_path.is_file());

        remove("toolA", false, false, false, &mut db).unwrap();
        assert!(cache_path.is_file());

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

        let result = install("missing_dep", None, false, &http, &mut db);
        assert!(result.is_err());
        assert!(db.packages.is_empty());
        assert!(!install_tmp.path().join("util").join("x.exe").exists());
    }

    #[test]
    fn extract_zip_missing_file_in_archive() {
        let tmp = tempfile::tempdir().unwrap();

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
}
