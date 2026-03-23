use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::{fs, io};

use crate::client::{validate_pkg_spec, HttpClient};
use crate::install::{fetch_index, fetch_versions};
use crate::repo::Manifest;

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
                crate::platform::to_manifest_path(
                    &path
                        .strip_prefix(base)
                        .map_err(|e| io::Error::other(format!("Path error: {e}")))?
                        .to_string_lossy(),
                )
            };
            if !files.contains_key(&name) {
                files.insert(name.clone(), crate::platform::to_manifest_path(dest));
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

    let manifest = Manifest {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{Config, Database};
    use crate::install::{fetch_index, install};
    use crate::testutil::helpers::{TEST_PASS, TEST_USER, start_tls_server};
    use std::path::Path;

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
    fn upload_and_install_roundtrip() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let install_tmp = tempfile::tempdir().unwrap();
        let src_tmp = tempfile::tempdir().unwrap();
        let db_path = install_tmp.path().join("db.json");

        fs::create_dir_all(repo_tmp.path().join("packages")).unwrap();
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());
        let config = test_config(port, install_tmp.path(), &fp);
        let http = HttpClient::new(&config).unwrap();

        fs::write(src_tmp.path().join("tool.exe"), b"tool-binary").unwrap();

        upload("newtool", "1.0", src_tmp.path(), &["*.exe:util/".to_string()], &[], "A new tool", false, &http)
            .unwrap();

        let index = fetch_index(&http).unwrap();
        assert_eq!(index["newtool"], "1.0");

        let mut db = Database::load_from(&db_path).unwrap();
        install("newtool", None, false, &http, &mut db).unwrap();
        assert!(install_tmp.path().join("util").join("tool.exe").exists());
    }

    #[test]
    fn manifest_dest_normalized_to_forward_slashes() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let src_tmp = tempfile::tempdir().unwrap();

        fs::create_dir_all(repo_tmp.path().join("packages")).unwrap();
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());
        let config = test_config(port, src_tmp.path(), &fp);
        let http = HttpClient::new(&config).unwrap();

        fs::write(src_tmp.path().join("tool.exe"), b"tool-binary").unwrap();

        // Upload with backslash dest — manifest should store forward slashes
        upload(
            "slashtest",
            "1.0",
            src_tmp.path(),
            &["*.exe:sub\\dir\\".to_string()],
            &[],
            "",
            false,
            &http,
        )
        .unwrap();

        // Read the manifest back and verify forward slashes
        let manifest = crate::install::fetch_manifest(&http, "slashtest", "1.0").unwrap();
        let dest = manifest.files.get("tool.exe").unwrap();
        assert!(!dest.contains('\\'), "manifest dest should use / not \\: {dest}");
        assert_eq!(dest, "sub/dir/");
    }

    #[test]
    fn upload_with_forward_slash_dest_unchanged() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let src_tmp = tempfile::tempdir().unwrap();

        fs::create_dir_all(repo_tmp.path().join("packages")).unwrap();
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());
        let config = test_config(port, src_tmp.path(), &fp);
        let http = HttpClient::new(&config).unwrap();

        fs::write(src_tmp.path().join("lib.dll"), b"lib-binary").unwrap();

        upload(
            "fwdtest",
            "1.0",
            src_tmp.path(),
            &["*.dll:lib/native/".to_string()],
            &[],
            "",
            false,
            &http,
        )
        .unwrap();

        let manifest = crate::install::fetch_manifest(&http, "fwdtest", "1.0").unwrap();
        let dest = manifest.files.get("lib.dll").unwrap();
        assert_eq!(dest, "lib/native/");
    }
}
