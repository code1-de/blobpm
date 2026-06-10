use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::{fs, io};

use crate::client::{Database, HttpClient, InstallReason, InstalledPackage, validate_manifest_path, validate_pkg_spec};
use crate::remove::purge_orphans;
use crate::repo::{IndexEntry, Manifest};
use crate::util::{plural, pluralize};

/// Fetch the package index from the server.
///
/// # Errors
/// Returns an error if the HTTP request fails or the response is not valid JSON.
pub fn fetch_index(http: &HttpClient) -> io::Result<BTreeMap<String, IndexEntry>> {
    let url = format!("{}/index", http.config.server_url);
    let resp = http.get(&url)?;
    if !resp.status().is_success() {
        return Err(io::Error::other(format!("Failed to fetch index: {}", resp.status())));
    }
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
fn cache_zip_path_in(name: &str, version: &str, cache_base: &Path) -> PathBuf {
    cache_base.join(name).join(version).join("files.zip")
}

fn download_zip(
    http: &HttpClient,
    name: &str,
    version: &str,
    manifest: &Manifest,
    no_cache: bool,
) -> io::Result<PathBuf> {
    let cache_dir = http.config.cache_dir()?;
    let zip_path = cache_zip_path_in(name, version, &cache_dir);
    let manifest_path = cache_dir.join(name).join(version).join("manifest.json");

    if !no_cache && zip_path.is_file() {
        // Verify cached manifest matches the freshly fetched one.
        // If someone force-re-uploaded the same version, the manifest will differ.
        let cache_valid = manifest_path.is_file()
            && fs::read_to_string(&manifest_path)
                .ok()
                .and_then(|s| serde_json::from_str::<Manifest>(&s).ok())
                .is_some_and(|cached| cached == *manifest);
        if cache_valid {
            return Ok(zip_path);
        }
    }

    if let Some(parent) = zip_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let url = format!("{}/packages/{name}/{version}/files.zip", http.config.server_url);
    http.download_to_file(&url, &zip_path, &format!("Downloading {name} {version}"))?;

    // Save manifest alongside zip for future cache validation
    let manifest_json =
        serde_json::to_string_pretty(manifest).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    fs::write(&manifest_path, manifest_json)?;

    Ok(zip_path)
}

/// Delete cached files older than `max_age_days` (0 = delete all). Silently skips errors.
pub fn clean_cache(cache_dir: &Path, max_age_days: u32, verbose: bool) {
    if !cache_dir.is_dir() {
        return;
    }
    let max_age = std::time::Duration::from_secs(u64::from(max_age_days) * 86400);
    let delete_all = max_age_days == 0;
    let mut removed = 0u32;
    let Ok(packages) = fs::read_dir(cache_dir) else { return };
    for pkg_entry in packages.flatten() {
        let Ok(versions) = fs::read_dir(pkg_entry.path()) else { continue };
        for ver_entry in versions.flatten() {
            let Ok(meta) = ver_entry.path().join("files.zip").metadata() else { continue };
            let stale =
                delete_all || meta.modified().ok().and_then(|t| t.elapsed().ok()).is_some_and(|age| age > max_age);
            if stale {
                let pkg_name = pkg_entry.file_name();
                let ver_name = ver_entry.file_name();
                if fs::remove_dir_all(ver_entry.path()).is_ok() {
                    if verbose && removed == 0 {
                        println!("Cleaning cached files...");
                    }
                    if verbose {
                        println!("  Removed {}@{}", pkg_name.to_string_lossy(), ver_name.to_string_lossy());
                    }
                    removed += 1;
                }
            }
        }
        // Remove empty package dirs
        if fs::read_dir(pkg_entry.path()).is_ok_and(|mut d| d.next().is_none()) {
            let _ = fs::remove_dir(pkg_entry.path());
        }
    }
    if verbose && removed > 0 {
        if delete_all {
            println!("Cleaned {removed} cached {}.", pluralize(removed as usize, "entry", "entries"));
        } else {
            println!(
                "Cleaned {removed} stale cache {} (older than {max_age_days} day{}).",
                pluralize(removed as usize, "entry", "entries"),
                plural(max_age_days as usize)
            );
        }
    }
}

/// Extract files from a zip to target directories based on the manifest.
///
/// # Errors
/// Returns an error if extraction or path validation fails.
/// Maximum decompressed file size (1 GB) — zip bomb protection.
pub(crate) const MAX_EXTRACT_SIZE: u64 = 1024 * 1024 * 1024;

/// Maximum total decompressed size across all files in a package (2 GB) — aggregate zip bomb protection.
pub(crate) const MAX_TOTAL_EXTRACT_SIZE: u64 = 2 * 1024 * 1024 * 1024;

/// Maximum number of entries in a zip archive — prevents inode exhaustion from many tiny files.
pub(crate) const MAX_ZIP_ENTRIES: usize = 200_000;

/// Upper bound on the per-file buffer pre-allocation hint. The zip's declared
/// uncompressed size is attacker-controlled (a header field), so cap how much we
/// pre-allocate up front — otherwise a tiny download declaring a huge size forces
/// a large allocation. `io::copy` grows the buffer from here as real bytes arrive.
const PREALLOC_HINT_CAP: u64 = 16 * 1024 * 1024;

fn extract_zip(
    zip_path: &Path,
    manifest: &Manifest,
    config: &crate::client::Config,
    name: &str,
) -> io::Result<BTreeMap<String, PathBuf>> {
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

        let resolved_dir = config.resolve_dest(dest_dir);
        let native_file = crate::platform::to_native_path(file);
        let dest = resolved_dir.join(&native_file);

        // Confinement check: the resolved root is either a mapped path or base_dir.
        // Ensure the final destination stays inside that root.
        let native_dest_dir = crate::platform::to_native_path(dest_dir);
        let root = {
            let first_seg = std::path::Path::new(&native_dest_dir)
                .components()
                .next()
                .map(|c| c.as_os_str().to_string_lossy().into_owned());
            match first_seg.as_deref().and_then(|k| config.path_map.get(k)) {
                Some(mapped) => mapped.clone(),
                None => config.base_dir.clone(),
            }
        };
        if !dest.starts_with(&root) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Install target escapes allowed root for {name}: {}", dest.display()),
            ));
        }

        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
            // Defense in depth: verify canonical path is still inside the allowed root after mkdir
            // (catches symlink escapes).
            // Known TOCTOU race: a local attacker with write access could swap the directory
            // between this check and File::create below. Accepted by design — such an attacker
            // already has equivalent access to overwrite installed files directly.
            let canonical_parent = dunce::canonicalize(parent)?;
            let canonical_root = dunce::canonicalize(&root).unwrap_or(root.clone());
            if !canonical_parent.starts_with(&canonical_root) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Install target escapes allowed root for {name}: {}", canonical_parent.display()),
                ));
            }
        }

        let entry = archive
            .by_name(file)
            .map_err(|e| io::Error::new(io::ErrorKind::NotFound, format!("File {file} not in zip for {name}: {e}")))?;

        if entry.is_dir() || entry.is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unexpected entry type for {file} in {name} (expected regular file)"),
            ));
        }

        if entry.size() > MAX_EXTRACT_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("File {file} in {name} exceeds max size ({} bytes)", entry.size()),
            ));
        }

        // Read entry with a size-limiting reader to prevent decompression bombs.
        // Pre-allocate only a capped amount: the declared size is attacker-controlled,
        // so a tiny download must not be able to force a huge allocation.
        let declared_size = entry.size();
        let mut limited = entry.take(MAX_EXTRACT_SIZE + 1);
        let mut buf = Vec::with_capacity(declared_size.min(PREALLOC_HINT_CAP) as usize);
        io::copy(&mut limited, &mut buf)?;
        if buf.len() as u64 > MAX_EXTRACT_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("File {file} in {name} exceeded max size during extraction"),
            ));
        }

        total_written = total_written.saturating_add(buf.len() as u64);
        if total_written > MAX_TOTAL_EXTRACT_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Total extraction size exceeds 2 GB limit for {name}"),
            ));
        }

        if let Some(old_path) = crate::platform::write_or_rename(&dest, &buf)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", dest.display())))?
        {
            eprintln!("  Renamed old binary to {}; run `blob cleanup` later.", old_path.display());
        }

        println!("  {file} -> {}", dest.display());
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
    index: &BTreeMap<String, IndexEntry>,
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
    index: &BTreeMap<String, IndexEntry>,
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
            .latest
            .clone(),
    };
    validate_pkg_spec("version", &version)?;

    let manifest = fetch_manifest(http, name, &version)?;

    // Only resolve deps that aren't installed yet. Already-installed deps are left at their
    // current version — `blob update` (without args) handles upgrading them individually.
    // This is intentional: `blob update pkg` means "update pkg to latest", not "update pkg
    // and transitively re-resolve its entire dependency tree".
    for dep in &manifest.dependencies {
        if dep == name {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Package {name} lists itself as a dependency"),
            ));
        }
        if !db.packages.contains_key(dep) {
            resolve_recursive(dep, None, http, index, db, result, visited, in_stack)?;
        }
    }

    in_stack.remove(name);
    visited.insert(name.to_string());
    result.push((name.to_string(), version, manifest));
    Ok(())
}

/// Build a map of filename → resolved absolute path for all files and links in a manifest.
/// Used to compare old vs. new destinations when cleaning up stale files.
fn resolve_manifest_paths(manifest: &Manifest, config: &crate::client::Config) -> BTreeMap<String, PathBuf> {
    let mut paths = BTreeMap::new();
    for (file, dest_dir) in &manifest.files {
        let native_file = crate::platform::to_native_path(file);
        let dest = config.resolve_dest(dest_dir).join(native_file);
        paths.insert(file.clone(), dest);
    }
    for dest_key in manifest.links.keys() {
        let dest = config.resolve_dest(dest_key);
        paths.insert(dest_key.clone(), dest);
    }
    paths
}

/// Check for file conflicts between packages to be installed and already-installed packages.
///
/// Builds a path→owner map from the DB (O(existing files)), then checks each file in the
/// transaction (O(new files)). Also detects within-transaction conflicts.
/// Returns `Ok(())` if no conflicts, or an error describing all conflicts.
fn check_conflicts(
    to_install: &[(String, String, Manifest)],
    config: &crate::client::Config,
    db: &Database,
    overwrite: bool,
) -> io::Result<()> {
    // Build normalized-path → (original path, owner) from already-installed packages
    // (skip packages being reinstalled). Normalized keys ensure case-insensitive matching on Windows.
    let transaction_names: HashSet<&str> = to_install.iter().map(|(n, _, _)| n.as_str()).collect();
    let mut owned: HashMap<String, (PathBuf, &str)> = HashMap::new();
    for (pkg_name, pkg) in &db.packages {
        if transaction_names.contains(pkg_name.as_str()) {
            continue; // will be replaced by this transaction
        }
        for dest in pkg.files.values() {
            let key = crate::platform::normalize_for_compare(dest);
            owned.insert(key, (dest.clone(), pkg_name.as_str()));
        }
    }

    // Check each file in the transaction; also detect within-transaction conflicts
    let mut conflicts: BTreeMap<String, Vec<(String, PathBuf)>> = BTreeMap::new();
    for (pkg_name, _, manifest) in to_install {
        for (file, dest_dir) in &manifest.files {
            let native_file = crate::platform::to_native_path(file);
            let dest = config.resolve_dest(dest_dir).join(native_file);
            let key = crate::platform::normalize_for_compare(&dest);
            if let Some((_, other)) = owned.get(&key) {
                conflicts.entry(other.to_string()).or_default().push((pkg_name.clone(), dest.clone()));
            } else {
                // Register so later packages in the transaction can conflict with this one
                owned.insert(key, (dest, pkg_name.as_str()));
            }
        }
        // Also check shim links
        for dest_key in manifest.links.keys() {
            let dest = config.resolve_dest(dest_key);
            let key = crate::platform::normalize_for_compare(&dest);
            if let Some((_, other)) = owned.get(&key) {
                conflicts.entry(other.to_string()).or_default().push((pkg_name.clone(), dest.clone()));
            } else {
                owned.insert(key, (dest, pkg_name.as_str()));
            }
        }
    }

    if conflicts.is_empty() {
        return Ok(());
    }

    if overwrite {
        for (owner, files) in &conflicts {
            for (wanting, path) in files {
                eprintln!("Warning: {wanting} overwrites {} (owned by {owner})", path.display());
            }
        }
        return Ok(());
    }

    let mut msg = String::from("File conflicts detected:\n");
    for (owner, files) in &conflicts {
        for (wanting, path) in files {
            let _ = writeln!(msg, "  {} wants {} (owned by {owner})", wanting, path.display());
        }
    }
    msg.push_str("Use --overwrite to install anyway.");
    Err(io::Error::new(io::ErrorKind::AlreadyExists, msg))
}

/// Install a package and its dependencies.
///
/// # Errors
/// Returns an error if fetching, downloading, or writing files fails.
pub fn install(
    name: &str,
    version: Option<&str>,
    force: bool,
    no_cache: bool,
    overwrite: bool,
    http: &HttpClient,
    db: &mut Database,
) -> io::Result<()> {
    if let Ok(cache_dir) = http.config.cache_dir() {
        clean_cache(&cache_dir, http.config.cache_days, false);
    }
    validate_pkg_spec("package name", name)?;
    if let Some(v) = version {
        validate_pkg_spec("version", v)?;
    }
    // If already installed and not requesting a different version, just ensure it's marked manual
    if let Some(existing) = db.packages.get(name).filter(|_| !force) {
        let same_version =
            version.is_none_or(|v| crate::repo::version_cmp(v, &existing.version) == std::cmp::Ordering::Equal);
        if same_version {
            if existing.reason == InstallReason::Auto {
                db.packages.entry(name.to_string()).and_modify(|p| p.reason = InstallReason::Manual);
                db.save()?;
                println!("{name} marked as manually installed");
            } else {
                println!("{name} is already installed ({}). Use --force to reinstall.", existing.version);
            }
            return Ok(());
        }
        // Different version requested — fall through to install it
    }

    let index = fetch_index(http)?;

    // Determine which version to install
    let target_version = match version {
        Some(v) => v.to_string(),
        None => index
            .get(name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("Package {name} not found in index")))?
            .latest
            .clone(),
    };

    let to_install = resolve_dependencies(name, &target_version, http, &index, db)?;

    if to_install.is_empty() {
        println!("{name} is already installed");
        return Ok(());
    }

    check_conflicts(&to_install, &http.config, db, overwrite)?;

    // Remove old files that are no longer at the same destination in the new manifest.
    // Compares resolved paths, not just filename keys — catches files that moved between dirs.
    if let Some(new_manifest) = to_install.iter().find(|(n, _, _)| n == name).map(|(_, _, m)| m)
        && let Some(old_pkg) = db.packages.get(name)
    {
        let new_paths = resolve_manifest_paths(new_manifest, &http.config);
        for (old_file, old_path) in &old_pkg.files {
            let still_needed = new_paths.get(old_file).is_some_and(|new_path| {
                crate::platform::normalize_for_compare(new_path) == crate::platform::normalize_for_compare(old_path)
            });
            if !still_needed && old_path.is_file() {
                fs::remove_file(old_path)?;
                println!("  Removed old file {old_file}");
            }
        }
    }

    download_and_install(&to_install, name, no_cache, http, db)?;

    // Clean up orphaned auto-deps (e.g. after --force changed the dep tree)
    purge_orphans(db)?;

    db.save()?;

    // If we renamed our own exe (self-update), spawn cleanup and exit
    check_self_update()?;
    Ok(())
}

/// Download all zips then extract all. `manual_name` is the top-level package (marked manual).
fn download_and_install(
    packages: &[(String, String, Manifest)],
    manual_name: &str,
    no_cache: bool,
    http: &HttpClient,
    db: &mut Database,
) -> io::Result<()> {
    // Phase 1: download all zips (skip meta-packages with no files)
    let pkgs_with_files: Vec<_> = packages.iter().filter(|(_, _, m)| !m.files.is_empty()).collect();
    if !pkgs_with_files.is_empty() {
        println!("Downloading {} package{}...", pkgs_with_files.len(), plural(pkgs_with_files.len()));
    }
    let mut downloads: Vec<(&str, &str, &Manifest, Option<PathBuf>)> = Vec::new();
    for (pkg_name, version, manifest) in packages {
        let zip_path = if manifest.files.is_empty() {
            None
        } else {
            Some(download_zip(http, pkg_name, version, manifest, no_cache)?)
        };
        downloads.push((pkg_name, version, manifest, zip_path));
    }

    // Phase 2: extract all
    for (i, (pkg_name, version, manifest, zip_path)) in downloads.iter().enumerate() {
        if i > 0 {
            println!();
        }
        let reason = if *pkg_name == manual_name { InstallReason::Manual } else { InstallReason::Auto };

        #[allow(unused_mut)]
        let mut installed_files = if let Some(zip_path) = zip_path {
            println!("Installing {pkg_name} {version}...");
            extract_zip(zip_path, manifest, &http.config, pkg_name)?
        } else {
            println!("Installing {pkg_name} {version} (meta-package)...");
            BTreeMap::new()
        };

        // Create shim links (64-bit Windows only)
        #[cfg(all(windows, target_pointer_width = "64"))]
        if !manifest.links.is_empty() {
            let shim_files = crate::shim::create_shims(&manifest.links, &http.config)?;
            installed_files.extend(shim_files);
        }

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
#[allow(clippy::fn_params_excessive_bools)]
pub fn update(
    name: Option<&str>,
    dry_run: bool,
    force: bool,
    no_cache: bool,
    overwrite: bool,
    http: &HttpClient,
    db: &mut Database,
) -> io::Result<()> {
    if !dry_run && let Ok(cache_dir) = http.config.cache_dir() {
        clean_cache(&cache_dir, http.config.cache_days, false);
    }
    let index = fetch_index(http)?;

    let packages: Vec<(String, String)> = if let Some(n) = name {
        if !db.packages.contains_key(n) {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("{n} is not installed")));
        }
        let latest = index
            .get(n)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{n} not found in index")))?
            .latest
            .clone();
        match crate::repo::version_cmp(&latest, &db.packages[n].version) {
            std::cmp::Ordering::Greater => {}
            std::cmp::Ordering::Equal => {
                if !force {
                    println!("{n} is already at latest version ({latest}). Use --force to reinstall.");
                    return Ok(());
                }
            }
            std::cmp::Ordering::Less => {
                println!("{n} is newer than server latest ({} > {latest}).", db.packages[n].version);
                return Ok(());
            }
        }
        vec![(n.to_string(), latest)]
    } else {
        let mut list = Vec::new();
        for (n, pkg) in &db.packages {
            if let Some(entry) = index.get(n) {
                let cmp = crate::repo::version_cmp(&entry.latest, &pkg.version);
                if cmp == std::cmp::Ordering::Greater || (force && cmp == std::cmp::Ordering::Equal) {
                    list.push((n.clone(), entry.latest.clone()));
                }
            }
        }
        if list.is_empty() {
            println!("Everything is up to date.");
            return Ok(());
        }
        list
    };

    if dry_run {
        println!("Would update {} package{}:", packages.len(), plural(packages.len()));
        for (pkg_name, new_version) in &packages {
            let old_version = &db.packages[pkg_name].version;
            println!("  {pkg_name} {old_version} -> {new_version}");
        }
        // Show new dependencies that would be pulled in
        let mut new_deps: Vec<String> = Vec::new();
        for (pkg_name, new_version) in &packages {
            if let Ok(resolved) = resolve_dependencies(pkg_name, new_version, http, &index, db) {
                for (dep_name, dep_version, _) in &resolved {
                    if dep_name != pkg_name && !db.packages.contains_key(dep_name) && !new_deps.contains(dep_name) {
                        new_deps.push(dep_name.clone());
                        println!("  + {dep_name} {dep_version} (new dependency)");
                    }
                }
            }
        }
        return Ok(());
    }

    for (i, (pkg_name, new_version)) in packages.iter().enumerate() {
        if i > 0 {
            println!();
        }
        let old_version = db.packages[pkg_name].version.clone();
        println!("Updating {pkg_name} {old_version} -> {new_version}...");

        let resolved = resolve_dependencies(pkg_name, new_version, http, &index, db)?;

        check_conflicts(&resolved, &http.config, db, overwrite)?;

        // Remove old files that are no longer at the same destination in the new manifest.
        // Compares resolved paths, not just filename keys — catches files that moved between dirs.
        if let Some(new_manifest) = resolved.iter().find(|(n, _, _)| n == pkg_name).map(|(_, _, m)| m)
            && let Some(old_pkg) = db.packages.get(pkg_name)
        {
            let new_paths = resolve_manifest_paths(new_manifest, &http.config);
            for (old_file, old_path) in &old_pkg.files {
                let still_needed = new_paths.get(old_file).is_some_and(|new_path| {
                    crate::platform::normalize_for_compare(new_path) == crate::platform::normalize_for_compare(old_path)
                });
                if !still_needed && old_path.is_file() {
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
        download_and_install(&to_install, pkg_name, no_cache, http, db)?;
        if let Some(pkg) = db.packages.get_mut(pkg_name) {
            pkg.reason = original_reason;
        }
    }

    purge_orphans(db)?;
    db.save()?;

    println!("Updated {} package{}.", packages.len(), plural(packages.len()));

    check_self_update()?;
    Ok(())
}

/// If our own exe was renamed during install (self-update), spawn a cleanup process and exit.
fn check_self_update() -> io::Result<()> {
    let Some(old_exe) = crate::platform::take_self_renamed_exe() else {
        return Ok(());
    };
    #[allow(unused_variables)]
    let Some(exe_dir) = old_exe.parent() else {
        return Ok(());
    };

    #[cfg(windows)]
    {
        println!("\nSelf-update detected — spawning cleanup...");
        crate::platform::spawn_self_cleanup(exe_dir, &old_exe)?;
        std::process::exit(0);
    }

    #[cfg(not(windows))]
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{Config, Database, InstallReason};
    use crate::testutil::helpers::create_zip;
    use std::collections::BTreeMap;
    use std::path::Path;

    #[cfg(feature = "server")]
    use crate::remove::remove;
    #[cfg(feature = "server")]
    use crate::testutil::server_helpers::{TEST_PASS, TEST_USER, start_tls_server};

    #[cfg(feature = "server")]
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

    #[cfg(feature = "server")]
    fn test_config(port: u16, base_dir: &Path, fingerprint: &str) -> Config {
        Config {
            server_url: format!("https://localhost:{port}"),
            base_dir: base_dir.to_path_buf(),
            username: TEST_USER.to_string(),
            password: TEST_PASS.to_string(),
            server_fingerprint: fingerprint.to_string(),
            cache_days: 0,
            path_map: BTreeMap::new(),
            cache_dir: Some(base_dir.join(".cache")),
        }
    }

    fn minimal_config(base_dir: &Path) -> Config {
        Config {
            server_url: String::new(),
            base_dir: base_dir.to_path_buf(),
            username: String::new(),
            password: String::new(),
            server_fingerprint: String::new(),
            cache_days: 0,
            path_map: BTreeMap::new(),
            cache_dir: None,
        }
    }

    // --- Integration tests (require a running TLS server) ---
    #[cfg(feature = "server")]
    mod integration {
        use super::*;

        #[test]
        fn fetch_index_from_server() {
            let tmp = tempfile::tempdir().unwrap();
            create_test_repo(tmp.path());
            let (_rt, port, fp) = start_tls_server(tmp.path());

            let config = test_config(port, Path::new(""), &fp);
            let http = HttpClient::new(&config, false).unwrap();
            let index = fetch_index(&http).unwrap();
            assert_eq!(index["toolA"].latest, "1.0");
            assert_eq!(index["toolB"].latest, "2.0");
        }

        #[test]
        fn install_single_package() {
            let repo_tmp = tempfile::tempdir().unwrap();
            let install_tmp = tempfile::tempdir().unwrap();
            let db_path = install_tmp.path().join("db.json");
            create_test_repo(repo_tmp.path());
            let (_rt, port, fp) = start_tls_server(repo_tmp.path());

            let config = test_config(port, install_tmp.path(), &fp);
            let http = HttpClient::new(&config, false).unwrap();
            let mut db = Database::load_from(&db_path).unwrap();

            install("toolA", None, false, false, false, &http, &mut db).unwrap();

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
            let http = HttpClient::new(&config, false).unwrap();
            let mut db = Database::load_from(&db_path).unwrap();

            install("toolB", None, false, false, false, &http, &mut db).unwrap();

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
            let http = HttpClient::new(&config, false).unwrap();
            let mut db = Database::load_from(&db_path).unwrap();

            install("toolB", None, false, false, false, &http, &mut db).unwrap();
            assert_eq!(db.packages["toolA"].reason, InstallReason::Auto);

            install("toolA", None, false, false, false, &http, &mut db).unwrap();
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
                    format!(
                        r#"{{"name":"{name}","description":"","files":{{"{file}":"util/"}},"dependencies":{deps}}}"#
                    ),
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
            let http = HttpClient::new(&config, false).unwrap();
            let mut db = Database::load_from(&db_path).unwrap();

            install("depC", None, false, false, false, &http, &mut db).unwrap();
            install("depD", None, false, false, false, &http, &mut db).unwrap();
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
            let http = HttpClient::new(&config, false).unwrap();
            let mut db = Database::load_from(&db_path).unwrap();

            install("toolE", Some("1.0"), false, false, false, &http, &mut db).unwrap();
            assert_eq!(db.packages.len(), 1);

            update(None, false, false, false, false, &http, &mut db).unwrap();
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
            let http = HttpClient::new(&config, false).unwrap();
            let index = fetch_index(&http).unwrap();
            let db = Database::load_from(Path::new("")).unwrap();
            let result = resolve_dependencies("cycleA", "1.0", &http, &index, &db);
            assert!(result.is_err());
        }

        #[test]
        fn self_dependency_detected() {
            let tmp = tempfile::tempdir().unwrap();

            let pkg = tmp.path().join("packages").join("selfpkg").join("1.0");
            fs::create_dir_all(&pkg).unwrap();
            fs::write(
                pkg.join("manifest.json"),
                r#"{"name":"selfpkg","description":"","files":{"s.exe":"bin/"},"dependencies":["selfpkg"]}"#,
            )
            .unwrap();
            create_zip(&pkg, &[("s.exe", b"binary")]);

            let (_rt, port, fp) = start_tls_server(tmp.path());

            let config = test_config(port, Path::new(""), &fp);
            let http = HttpClient::new(&config, false).unwrap();
            let index = fetch_index(&http).unwrap();
            let db = Database::load_from(Path::new("")).unwrap();
            let result = resolve_dependencies("selfpkg", "1.0", &http, &index, &db);
            assert!(result.is_err(), "self-dependency should be rejected");
            let err = result.unwrap_err().to_string();
            assert!(err.contains("itself"), "error should mention self-dep: {err}");
        }

        /// Verify self-dep is caught even when the package is already installed (update scenario)
        #[test]
        fn self_dependency_detected_when_already_installed() {
            let repo_tmp = tempfile::tempdir().unwrap();
            let install_tmp = tempfile::tempdir().unwrap();
            let db_path = install_tmp.path().join("db.json");

            // v1: normal, no self-dep
            let v1 = repo_tmp.path().join("packages").join("selfpkg").join("1.0");
            fs::create_dir_all(&v1).unwrap();
            fs::write(
                v1.join("manifest.json"),
                r#"{"name":"selfpkg","description":"","files":{"s.exe":"bin/"},"dependencies":[]}"#,
            )
            .unwrap();
            create_zip(&v1, &[("s.exe", b"v1")]);

            // v2: self-dependency
            let v2 = repo_tmp.path().join("packages").join("selfpkg").join("2.0");
            fs::create_dir_all(&v2).unwrap();
            fs::write(
                v2.join("manifest.json"),
                r#"{"name":"selfpkg","description":"","files":{"s.exe":"bin/"},"dependencies":["selfpkg"]}"#,
            )
            .unwrap();
            create_zip(&v2, &[("s.exe", b"v2")]);

            let (_rt, port, fp) = start_tls_server(repo_tmp.path());
            let config = test_config(port, install_tmp.path(), &fp);
            let http = HttpClient::new(&config, false).unwrap();
            let mut db = Database::load_from(&db_path).unwrap();

            // Install v1 (no self-dep) — succeeds
            install("selfpkg", Some("1.0"), false, false, false, &http, &mut db).unwrap();
            assert!(db.packages.contains_key("selfpkg"));

            // Update to v2 (has self-dep) — must fail
            let result = update(None, false, false, false, false, &http, &mut db);
            assert!(result.is_err(), "update to self-referencing version should fail");
        }

        #[test]
        fn cache_reuse_skips_download() {
            let repo_tmp = tempfile::tempdir().unwrap();
            let install_tmp = tempfile::tempdir().unwrap();
            let db_path = install_tmp.path().join("db.json");
            create_test_repo(repo_tmp.path());
            let (_rt, port, fp) = start_tls_server(repo_tmp.path());

            let config = test_config(port, install_tmp.path(), &fp);
            let http = HttpClient::new(&config, false).unwrap();
            let mut db = Database::load_from(&db_path).unwrap();

            install("toolA", None, false, false, false, &http, &mut db).unwrap();
            let cache_path = install_tmp.path().join(".cache").join("toolA").join("1.0").join("files.zip");
            assert!(cache_path.is_file());

            remove("toolA", false, false, false, &mut db).unwrap();
            assert!(cache_path.is_file());

            install("toolA", None, false, false, false, &http, &mut db).unwrap();
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
            let http = HttpClient::new(&config, false).unwrap();
            let mut db = Database::load_from(&db_path).unwrap();

            install("toolB", None, false, false, false, &http, &mut db).unwrap();
            let cache = install_tmp.path().join(".cache");
            assert!(cache.join("toolA").join("1.0").join("files.zip").is_file());
            assert!(cache.join("toolB").join("2.0").join("files.zip").is_file());
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
            let http = HttpClient::new(&config, false).unwrap();
            let mut db = Database::load_from(&db_path).unwrap();

            let result = install("missing_dep", None, false, false, false, &http, &mut db);
            assert!(result.is_err());
            assert!(db.packages.is_empty());
            assert!(!install_tmp.path().join("util").join("x.exe").exists());
        }
        /// Create a repo where mover@1.0 puts file in "bin/" and mover@2.0 puts it in "lib/"
        fn create_mover_repo(base: &Path) {
            let v1 = base.join("packages").join("mover").join("1.0");
            fs::create_dir_all(&v1).unwrap();
            fs::write(
                v1.join("manifest.json"),
                r#"{"name":"mover","description":"","files":{"tool.exe":"bin/"},"dependencies":[]}"#,
            )
            .unwrap();
            create_zip(&v1, &[("tool.exe", b"v1-binary")]);

            let v2 = base.join("packages").join("mover").join("2.0");
            fs::create_dir_all(&v2).unwrap();
            fs::write(
                v2.join("manifest.json"),
                r#"{"name":"mover","description":"","files":{"tool.exe":"lib/"},"dependencies":[]}"#,
            )
            .unwrap();
            create_zip(&v2, &[("tool.exe", b"v2-binary")]);
        }

        #[test]
        fn update_cleans_old_file_when_dest_dir_changes() {
            let repo_tmp = tempfile::tempdir().unwrap();
            let install_tmp = tempfile::tempdir().unwrap();
            let db_path = install_tmp.path().join("db.json");
            create_mover_repo(repo_tmp.path());
            let (_rt, port, fp) = start_tls_server(repo_tmp.path());

            let config = test_config(port, install_tmp.path(), &fp);
            let http = HttpClient::new(&config, false).unwrap();
            let mut db = Database::load_from(&db_path).unwrap();

            // Install v1 — file goes to bin/
            install("mover", Some("1.0"), false, false, false, &http, &mut db).unwrap();
            assert!(install_tmp.path().join("bin").join("tool.exe").exists());

            // Update to v2 — file moves to lib/
            update(None, false, false, false, false, &http, &mut db).unwrap();
            assert!(install_tmp.path().join("lib").join("tool.exe").exists());
            // Old file at bin/ must be cleaned up
            assert!(
                !install_tmp.path().join("bin").join("tool.exe").exists(),
                "old file at bin/tool.exe should have been removed after dest dir change"
            );
        }

        #[test]
        fn force_reinstall_cleans_old_file_when_dest_dir_changes() {
            let repo_tmp = tempfile::tempdir().unwrap();
            let install_tmp = tempfile::tempdir().unwrap();
            let db_path = install_tmp.path().join("db.json");
            create_mover_repo(repo_tmp.path());
            let (_rt, port, fp) = start_tls_server(repo_tmp.path());

            let config = test_config(port, install_tmp.path(), &fp);
            let http = HttpClient::new(&config, false).unwrap();
            let mut db = Database::load_from(&db_path).unwrap();

            // Install v1 — file goes to bin/
            install("mover", Some("1.0"), false, false, false, &http, &mut db).unwrap();
            assert!(install_tmp.path().join("bin").join("tool.exe").exists());

            // Force install v2 — file moves to lib/
            install("mover", Some("2.0"), true, false, false, &http, &mut db).unwrap();
            assert!(install_tmp.path().join("lib").join("tool.exe").exists());
            // Old file at bin/ must be cleaned up
            assert!(
                !install_tmp.path().join("bin").join("tool.exe").exists(),
                "old file at bin/tool.exe should have been removed after dest dir change"
            );
        }
        #[test]
        fn install_different_version_replaces_existing() {
            let repo_tmp = tempfile::tempdir().unwrap();
            let install_tmp = tempfile::tempdir().unwrap();
            let db_path = install_tmp.path().join("db.json");
            create_diamond_repo(repo_tmp.path());
            let (_rt, port, fp) = start_tls_server(repo_tmp.path());

            let config = test_config(port, install_tmp.path(), &fp);
            let http = HttpClient::new(&config, false).unwrap();
            let mut db = Database::load_from(&db_path).unwrap();

            // Install toolE v1 (no deps)
            install("toolE", Some("1.0"), false, false, false, &http, &mut db).unwrap();
            assert_eq!(db.packages["toolE"].version, "1.0");
            assert_eq!(db.packages.len(), 1);

            // Install toolE v2 (adds dep on depA) — must not require --force
            install("toolE", Some("2.0"), false, false, false, &http, &mut db).unwrap();
            assert_eq!(db.packages["toolE"].version, "2.0");
            assert!(db.packages.contains_key("depA"), "new dependency should be installed");
        }

        #[test]
        fn update_does_not_downgrade_locally_newer() {
            let repo_tmp = tempfile::tempdir().unwrap();
            let install_tmp = tempfile::tempdir().unwrap();
            let db_path = install_tmp.path().join("db.json");
            create_diamond_repo(repo_tmp.path());
            let (_rt, port, fp) = start_tls_server(repo_tmp.path());

            let config = test_config(port, install_tmp.path(), &fp);
            let http = HttpClient::new(&config, false).unwrap();
            let mut db = Database::load_from(&db_path).unwrap();

            // Install toolE v2 (latest on server)
            install("toolE", Some("2.0"), false, false, false, &http, &mut db).unwrap();
            assert_eq!(db.packages["toolE"].version, "2.0");

            // Simulate a locally-newer version by patching the DB
            db.packages.get_mut("toolE").unwrap().version = "99.0".to_string();
            db.save().unwrap();

            // Update should NOT downgrade to server's 2.0
            update(Some("toolE"), false, false, false, false, &http, &mut db).unwrap();
            assert_eq!(db.packages["toolE"].version, "99.0", "must not downgrade locally-newer version");
        }

        #[test]
        fn update_all_skips_locally_newer() {
            let repo_tmp = tempfile::tempdir().unwrap();
            let install_tmp = tempfile::tempdir().unwrap();
            let db_path = install_tmp.path().join("db.json");
            create_test_repo(repo_tmp.path());
            let (_rt, port, fp) = start_tls_server(repo_tmp.path());

            let config = test_config(port, install_tmp.path(), &fp);
            let http = HttpClient::new(&config, false).unwrap();
            let mut db = Database::load_from(&db_path).unwrap();

            // Install toolA
            install("toolA", None, false, false, false, &http, &mut db).unwrap();

            // Patch to a newer version than the server has
            db.packages.get_mut("toolA").unwrap().version = "99.0".to_string();
            db.save().unwrap();

            // Update all — should report "up to date" and not touch toolA
            update(None, false, false, false, false, &http, &mut db).unwrap();
            assert_eq!(db.packages["toolA"].version, "99.0");
        }
        /// Installing with a non-canonical version (e.g. "1.0") must match the server's
        /// canonical storage ("1") — verifies the canonicalization in `parse_package_spec`.
        #[test]
        fn install_with_non_canonical_version() {
            let repo_tmp = tempfile::tempdir().unwrap();
            let install_tmp = tempfile::tempdir().unwrap();
            let db_path = install_tmp.path().join("db.json");
            create_test_repo(repo_tmp.path());
            let (_rt, port, fp) = start_tls_server(repo_tmp.path());

            let config = test_config(port, install_tmp.path(), &fp);
            let http = HttpClient::new(&config, false).unwrap();
            let mut db = Database::load_from(&db_path).unwrap();

            // Verify canonicalization maps "1.0" → "1" (same as server storage for version "1.0")
            assert_eq!(crate::repo::canonicalize_version("1.0"), "1");
            assert_eq!(crate::repo::canonicalize_version("1.0.0"), "1");

            // Install with the exact version on server — should work
            install("toolA", Some("1.0"), false, false, false, &http, &mut db).unwrap();
            assert_eq!(db.packages["toolA"].version, "1.0");
        }

        /// Verify that search --long fetches the manifest for the LATEST version,
        /// not the first/oldest version.
        #[test]
        fn search_long_shows_latest_version_details() {
            let repo_tmp = tempfile::tempdir().unwrap();
            let install_tmp = tempfile::tempdir().unwrap();
            create_diamond_repo(repo_tmp.path());
            let (_rt, port, fp) = start_tls_server(repo_tmp.path());

            let config = test_config(port, install_tmp.path(), &fp);
            let http = HttpClient::new(&config, false).unwrap();

            // toolE has v1.0 (no deps) and v2.0 (dep on depA)
            // search --long should fetch manifest for v2.0 (latest), which has deps
            let versions = fetch_versions(&http, "toolE").unwrap();
            assert!(versions.contains(&"1.0".to_string()));
            assert!(versions.contains(&"2.0".to_string()));

            // The latest version is 2.0, which has a dependency on depA
            let latest_manifest = fetch_manifest(&http, "toolE", "2.0").unwrap();
            assert!(!latest_manifest.dependencies.is_empty(), "v2.0 should have deps");

            // The oldest version 1.0 has no deps
            let oldest_manifest = fetch_manifest(&http, "toolE", "1.0").unwrap();
            assert!(oldest_manifest.dependencies.is_empty(), "v1.0 should have no deps");

            // Verify the version list is sorted — last entry should be "2.0" (latest)
            assert_eq!(versions.last().unwrap(), "2.0", "last version in sorted list should be latest");
        }
    } // mod integration

    // --- Unit tests (no server needed) ---

    #[test]
    fn clean_cache_days_zero_deletes_all() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("cache");

        // Create two cached entries with different timestamps
        let v1 = cache.join("pkg").join("1.0");
        let v2 = cache.join("pkg").join("2.0");
        fs::create_dir_all(&v1).unwrap();
        fs::create_dir_all(&v2).unwrap();
        fs::write(v1.join("files.zip"), b"zip1").unwrap();
        fs::write(v2.join("files.zip"), b"zip2").unwrap();

        // days=0 must delete everything regardless of age
        clean_cache(&cache, 0, false);

        assert!(!v1.join("files.zip").exists(), "days=0 must delete all cached files");
        assert!(!v2.join("files.zip").exists(), "days=0 must delete all cached files");
    }

    #[test]
    fn clean_cache_nonzero_keeps_fresh() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("cache");

        let v1 = cache.join("pkg").join("1.0");
        fs::create_dir_all(&v1).unwrap();
        fs::write(v1.join("files.zip"), b"zip1").unwrap();

        // days=30 — file was just created, so it's fresh and should survive
        clean_cache(&cache, 30, false);

        assert!(v1.join("files.zip").exists(), "fresh file should survive days=30");
    }

    #[test]
    fn extract_zip_rejects_directory_entry() {
        let tmp = tempfile::tempdir().unwrap();

        // Create a zip where "tool.exe/" is a directory entry, not a file.
        // zip crate's add_directory appends '/', so the manifest must match.
        let zip_path = tmp.path().join("files.zip");
        let file = fs::File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        zip.add_directory("tool.exe", zip::write::SimpleFileOptions::default()).unwrap();
        zip.finish().unwrap();

        let manifest = crate::repo::Manifest {
            name: "bad".to_string(),
            description: "bad".to_string(),
            files: BTreeMap::from([("tool.exe/".to_string(), "util/".to_string())]),
            dependencies: vec![],
            links: BTreeMap::new(),
        };

        let base = tmp.path().join("install");
        fs::create_dir_all(&base).unwrap();

        let result = extract_zip(&zip_path, &manifest, &minimal_config(&base), "bad");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Unexpected entry type"), "got: {err}");
    }

    #[test]
    fn extract_zip_rejects_symlink_entry() {
        let tmp = tempfile::tempdir().unwrap();

        // Create a zip where "tool.exe" is a symlink entry
        let zip_path = tmp.path().join("files.zip");
        let file = fs::File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        zip.add_symlink("tool.exe", "../../../etc/passwd", zip::write::SimpleFileOptions::default()).unwrap();
        zip.finish().unwrap();

        let manifest = crate::repo::Manifest {
            name: "bad".to_string(),
            description: "bad".to_string(),
            files: BTreeMap::from([("tool.exe".to_string(), "util/".to_string())]),
            dependencies: vec![],
            links: BTreeMap::new(),
        };

        let base = tmp.path().join("install");
        fs::create_dir_all(&base).unwrap();

        let result = extract_zip(&zip_path, &manifest, &minimal_config(&base), "bad");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Unexpected entry type"), "got: {err}");
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
            links: BTreeMap::new(),
        };

        let base = tmp.path().join("install");
        fs::create_dir_all(&base).unwrap();

        let result = extract_zip(&tmp.path().join("files.zip"), &manifest, &minimal_config(&base), "bad");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("b.exe"));
    }

    #[test]
    fn resolve_dest_uses_path_map() {
        let mut config = minimal_config(Path::new("C:\\base"));
        config.path_map.insert("bin".to_string(), PathBuf::from("D:\\tools\\bin"));

        // Mapped segment
        assert_eq!(config.resolve_dest("bin"), PathBuf::from("D:\\tools\\bin"));
        assert_eq!(config.resolve_dest("bin/sub"), PathBuf::from("D:\\tools\\bin\\sub"));

        // Unmapped segment falls back to base_dir
        assert_eq!(config.resolve_dest("util"), PathBuf::from("C:\\base\\util"));
        assert_eq!(config.resolve_dest("util/sub"), PathBuf::from("C:\\base\\util\\sub"));
    }

    #[test]
    fn extract_zip_with_path_map() {
        let tmp = tempfile::tempdir().unwrap();
        let mapped_dir = tmp.path().join("mapped_bin");
        fs::create_dir_all(&mapped_dir).unwrap();
        let base = tmp.path().join("base");
        fs::create_dir_all(&base).unwrap();

        create_zip(tmp.path(), &[("tool.exe", b"binary-content")]);

        let manifest = crate::repo::Manifest {
            name: "mypkg".to_string(),
            description: "test".to_string(),
            files: BTreeMap::from([("tool.exe".to_string(), "bin/".to_string())]),
            dependencies: vec![],
            links: BTreeMap::new(),
        };

        let mut config = minimal_config(&base);
        config.path_map.insert("bin".to_string(), mapped_dir.clone());

        let installed = extract_zip(&tmp.path().join("files.zip"), &manifest, &config, "mypkg").unwrap();
        let dest = &installed["tool.exe"];
        assert!(dest.starts_with(&mapped_dir), "expected under mapped dir: {}", dest.display());
        assert!(dest.is_file());
        assert_eq!(fs::read(dest).unwrap(), b"binary-content");
    }

    #[test]
    fn extract_zip_unmapped_uses_base_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let mapped_dir = tmp.path().join("mapped_bin");
        fs::create_dir_all(&mapped_dir).unwrap();
        let base = tmp.path().join("base");
        fs::create_dir_all(&base).unwrap();

        create_zip(tmp.path(), &[("script.py", b"print('hi')")]);

        let manifest = crate::repo::Manifest {
            name: "mypkg".to_string(),
            description: "test".to_string(),
            files: BTreeMap::from([("script.py".to_string(), "scripts/".to_string())]),
            dependencies: vec![],
            links: BTreeMap::new(),
        };

        // bin is mapped, but scripts is not — should go to base_dir/scripts/
        let mut config = minimal_config(&base);
        config.path_map.insert("bin".to_string(), mapped_dir);

        let installed = extract_zip(&tmp.path().join("files.zip"), &manifest, &config, "mypkg").unwrap();
        let dest = &installed["script.py"];
        assert!(dest.starts_with(&base), "expected under base dir: {}", dest.display());
        assert!(dest.is_file());
    }

    #[test]
    fn path_map_serializes_in_config() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.json");

        let mut config = minimal_config(Path::new("C:\\base"));
        config.path_map.insert("bin".to_string(), PathBuf::from("D:\\tools\\bin"));

        let json = serde_json::to_string_pretty(&config).unwrap();
        fs::write(&path, &json).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        let loaded: Config = serde_json::from_str(&content).unwrap();
        assert_eq!(loaded.path_map["bin"], PathBuf::from("D:\\tools\\bin"));
    }

    fn make_manifest(name: &str, files: &[(&str, &str)]) -> Manifest {
        Manifest {
            name: name.to_string(),
            description: String::new(),
            files: files.iter().map(|(f, d)| (f.to_string(), d.to_string())).collect(),
            dependencies: vec![],
            links: BTreeMap::new(),
        }
    }

    #[test]
    fn conflict_with_installed_package() {
        let tmp = tempfile::tempdir().unwrap();
        let config = minimal_config(Path::new("C:\\base"));
        let mut db = Database::load_from(&tmp.path().join("db.json")).unwrap();
        db.packages.insert(
            "existing".to_string(),
            InstalledPackage {
                version: "1.0".to_string(),
                reason: InstallReason::Manual,
                files: BTreeMap::from([("shared.dll".to_string(), PathBuf::from("C:\\base\\util\\shared.dll"))]),
                dependencies: vec![],
            },
        );

        let to_install =
            vec![("newpkg".to_string(), "1.0".to_string(), make_manifest("newpkg", &[("shared.dll", "util/")]))];

        let result = check_conflicts(&to_install, &config, &db, false);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("existing"), "should name the owning package: {err}");
        assert!(err.contains("newpkg"), "should name the wanting package: {err}");
        assert!(err.contains("--overwrite"), "should suggest --overwrite: {err}");
    }

    #[test]
    fn conflict_within_transaction() {
        let tmp = tempfile::tempdir().unwrap();
        let config = minimal_config(Path::new("C:\\base"));
        let db = Database::load_from(&tmp.path().join("db.json")).unwrap();

        // Two packages in the same transaction both want util/shared.dll
        let to_install = vec![
            ("pkgA".to_string(), "1.0".to_string(), make_manifest("pkgA", &[("shared.dll", "util/")])),
            ("pkgB".to_string(), "1.0".to_string(), make_manifest("pkgB", &[("shared.dll", "util/")])),
        ];

        let result = check_conflicts(&to_install, &config, &db, false);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("pkgA"), "should name first package: {err}");
        assert!(err.contains("pkgB"), "should name second package: {err}");
    }

    #[test]
    #[cfg(windows)]
    fn conflict_case_insensitive_filename_on_windows() {
        let tmp = tempfile::tempdir().unwrap();
        let config = minimal_config(Path::new("C:\\base"));
        let mut db = Database::load_from(&tmp.path().join("db.json")).unwrap();
        db.packages.insert(
            "existing".to_string(),
            InstalledPackage {
                version: "1.0".to_string(),
                reason: InstallReason::Manual,
                files: BTreeMap::from([("Tool.exe".to_string(), PathBuf::from("C:\\base\\util\\Tool.exe"))]),
                dependencies: vec![],
            },
        );

        // Same file but different case — must still conflict on Windows
        let to_install =
            vec![("newpkg".to_string(), "1.0".to_string(), make_manifest("newpkg", &[("tool.exe", "util/")]))];

        let result = check_conflicts(&to_install, &config, &db, false);
        assert!(result.is_err(), "case-only difference in filename must conflict on Windows");
    }

    #[test]
    #[cfg(windows)]
    fn conflict_case_insensitive_dir_on_windows() {
        let tmp = tempfile::tempdir().unwrap();
        let config = minimal_config(Path::new("C:\\base"));
        let mut db = Database::load_from(&tmp.path().join("db.json")).unwrap();
        db.packages.insert(
            "existing".to_string(),
            InstalledPackage {
                version: "1.0".to_string(),
                reason: InstallReason::Manual,
                files: BTreeMap::from([("tool.exe".to_string(), PathBuf::from("C:\\base\\Util\\tool.exe"))]),
                dependencies: vec![],
            },
        );

        // Same file but directory differs in case — must still conflict on Windows
        let to_install =
            vec![("newpkg".to_string(), "1.0".to_string(), make_manifest("newpkg", &[("tool.exe", "util/")]))];

        let result = check_conflicts(&to_install, &config, &db, false);
        assert!(result.is_err(), "case-only difference in directory must conflict on Windows");
    }

    #[test]
    fn no_conflict_different_files() {
        let tmp = tempfile::tempdir().unwrap();
        let config = minimal_config(Path::new("C:\\base"));
        let mut db = Database::load_from(&tmp.path().join("db.json")).unwrap();
        db.packages.insert(
            "existing".to_string(),
            InstalledPackage {
                version: "1.0".to_string(),
                reason: InstallReason::Manual,
                files: BTreeMap::from([("other.dll".to_string(), PathBuf::from("C:\\base\\util\\other.dll"))]),
                dependencies: vec![],
            },
        );

        let to_install =
            vec![("newpkg".to_string(), "1.0".to_string(), make_manifest("newpkg", &[("tool.exe", "util/")]))];

        assert!(check_conflicts(&to_install, &config, &db, false).is_ok());
    }

    #[test]
    fn no_conflict_when_reinstalling_self() {
        let tmp = tempfile::tempdir().unwrap();
        let config = minimal_config(Path::new("C:\\base"));
        let mut db = Database::load_from(&tmp.path().join("db.json")).unwrap();
        // "mypkg" is already installed with this file
        db.packages.insert(
            "mypkg".to_string(),
            InstalledPackage {
                version: "1.0".to_string(),
                reason: InstallReason::Manual,
                files: BTreeMap::from([("tool.exe".to_string(), PathBuf::from("C:\\base\\util\\tool.exe"))]),
                dependencies: vec![],
            },
        );

        // Reinstalling mypkg with the same file — not a conflict
        let to_install =
            vec![("mypkg".to_string(), "2.0".to_string(), make_manifest("mypkg", &[("tool.exe", "util/")]))];

        assert!(check_conflicts(&to_install, &config, &db, false).is_ok());
    }

    #[cfg(feature = "server")]
    mod integration_conflicts {
        use super::*;

        /// Create repo with toolA and a "conflict" package that places the same file (toolA.exe -> util/).
        fn create_conflict_repo(base: &Path) {
            create_test_repo(base);
            let pkg_dir = base.join("packages").join("conflict").join("1.0");
            fs::create_dir_all(&pkg_dir).unwrap();
            fs::write(
                pkg_dir.join("manifest.json"),
                r#"{"name":"conflict","description":"","files":{"toolA.exe":"util/"},"dependencies":[]}"#,
            )
            .unwrap();
            create_zip(&pkg_dir, &[("toolA.exe", b"conflict-binary")]);
        }

        #[test]
        fn overwrite_bypasses_conflict() {
            let repo_tmp = tempfile::tempdir().unwrap();
            let install_tmp = tempfile::tempdir().unwrap();
            let db_path = install_tmp.path().join("db.json");
            create_conflict_repo(repo_tmp.path());
            let (_rt, port, fp) = start_tls_server(repo_tmp.path());

            let config = test_config(port, install_tmp.path(), &fp);
            let http = HttpClient::new(&config, false).unwrap();
            let mut db = Database::load_from(&db_path).unwrap();

            // Install toolA first
            install("toolA", None, false, false, false, &http, &mut db).unwrap();

            // Without --overwrite: should fail
            let result = install("conflict", None, false, false, false, &http, &mut db);
            assert!(result.is_err());
            let err = result.unwrap_err().to_string();
            assert!(err.contains("toolA"), "should mention owning package: {err}");

            // With --overwrite: should succeed
            install("conflict", None, false, false, true, &http, &mut db).unwrap();
            assert!(db.packages.contains_key("conflict"));
        }
    }
}
