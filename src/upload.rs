use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::{fs, io};

use crate::client::{HttpClient, validate_pkg_spec};
use crate::install::{fetch_index, fetch_versions};
use crate::repo::IndexEntry;
use crate::repo::Manifest;

/// Extract the non-glob base directory from a glob pattern.
/// E.g. `C:\bin\git64\**` → `C:\bin\git64`, `C:\tools\*.exe` → `C:\tools`.
fn glob_base_dir(pattern: &str) -> PathBuf {
    let first_glob = pattern.find(['*', '?', '[']).unwrap_or(pattern.len());
    let base = &pattern[..first_glob];
    // Find the last path separator before the glob
    let last_sep = base.rfind(['/', '\\']).map_or(0, |i| i + 1);
    PathBuf::from(&pattern[..last_sep])
}

pub fn search(
    pattern: &str,
    show_versions: bool,
    search_desc: bool,
    show_long: bool,
    http: &HttpClient,
) -> io::Result<()> {
    if pattern.len() > 1024 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Regex pattern too long (max 1024 bytes)"));
    }
    let re = regex::RegexBuilder::new(pattern)
        .case_insensitive(true)
        .build()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid regex: {e}")))?;

    let index = fetch_index(http)?;
    let mut rows: Vec<(String, String, String)> = Vec::new();

    for (name, IndexEntry { latest, description }) in &index {
        if re.is_match(name) || (search_desc && re.is_match(description)) {
            let version_str =
                if show_versions { fetch_versions(http, name).unwrap_or_default().join(", ") } else { latest.clone() };
            rows.push((name.clone(), version_str, description.clone()));
        }
    }

    if rows.is_empty() {
        println!("No packages matching '{pattern}'");
        return Ok(());
    }

    let w0 = rows.iter().map(|(n, _, _)| n.len()).max().unwrap_or(0);
    let w1 = rows.iter().map(|(_, v, _)| v.len()).max().unwrap_or(0);

    for (name, version, desc) in &rows {
        if desc.is_empty() {
            println!("{name:<w0$}  {version}");
        } else {
            println!("{name:<w0$}  {version:<w1$}  {desc}");
        }
        if show_long
            && let Ok(manifest) =
                crate::install::fetch_manifest(http, name, version.split(',').next().unwrap_or(version).trim())
        {
            if !manifest.dependencies.is_empty() {
                println!("  deps: {}", manifest.dependencies.join(", "));
            }
            if manifest.files.is_empty() {
                println!("  (meta-package)");
            }
        }
    }

    Ok(())
}

/// Parse mapping rules ("`glob:dest_dir`/") and match files.
/// Absolute globs use basename as filename. Relative globs use path relative to `from`.
/// Returns a map of (filename → `dest_dir`) and a map of (filename → absolute source path).
fn resolve_mappings(
    from: &Path,
    mappings: &[String],
    lowercase: bool,
) -> io::Result<(BTreeMap<String, String>, BTreeMap<String, PathBuf>)> {
    let mut files = BTreeMap::new();
    let mut sources = BTreeMap::new();
    let mut from_cache: Option<PathBuf> = None;

    for mapping in mappings {
        let (patterns_str, dest) = mapping.rsplit_once(':').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid mapping (missing ':'): {mapping}"))
        })?;

        // Support "a.exe;b.dll:bin" — semicolon-separated files sharing the same dest
        for pattern in patterns_str.split(';') {
            let is_absolute = Path::new(pattern).is_absolute() || (pattern.len() >= 2 && pattern.as_bytes()[1] == b':');

            let (full_pattern, strip_base) = if is_absolute {
                let glob_base = glob_base_dir(pattern);
                (pattern.to_string(), Some(glob_base))
            } else {
                let base = if let Some(p) = &from_cache {
                    p.clone()
                } else {
                    let p = dunce::canonicalize(from)?;
                    from_cache = Some(p.clone());
                    p
                };
                (base.join(pattern).to_string_lossy().to_string(), None)
            };

            // glob crate treats \ as escape on all platforms — normalize to / for reliable matching.
            // Also: "dir/**" only matches directories in the glob crate; append "/*" for files.
            let mut glob_pattern = full_pattern.replace('\\', "/");
            if glob_pattern.ends_with("/**") || glob_pattern.ends_with("**") && !glob_pattern.ends_with("**/*") {
                glob_pattern.push_str("/*");
            }
            let matched = glob::glob(&glob_pattern)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid glob '{pattern}': {e}")))?;

            let mut match_count = 0u32;
            for entry in matched {
                let path = entry.map_err(|e| io::Error::other(format!("Glob error: {e}")))?;
                if !path.is_file() {
                    continue;
                }
                match_count += 1;
                let base =
                    strip_base.as_deref().or(from_cache.as_deref()).ok_or_else(|| io::Error::other("No base path"))?;
                let mut name = crate::platform::to_manifest_path(
                    &path
                        .strip_prefix(base)
                        .map_err(|e| io::Error::other(format!("Path error: {e}")))?
                        .to_string_lossy(),
                );
                if lowercase {
                    name = name.to_lowercase();
                }
                if !files.contains_key(&name) {
                    files.insert(name.clone(), crate::platform::to_manifest_path(dest));
                    sources.insert(name, path);
                }
            }
            if match_count == 0 {
                eprintln!("Warning: no files matched pattern '{pattern}'");
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
        let pb = indicatif::ProgressBar::new(sources.len() as u64);
        pb.set_style(
            indicatif::ProgressStyle::with_template("Zipping [{bar:40}] {pos}/{len} files")
                .expect("hardcoded progress template")
                .progress_chars("=>-"),
        );
        for (zip_name, src_path) in sources {
            let content = fs::read(src_path)?;
            zip.start_file(zip_name, options).map_err(|e| io::Error::other(format!("Zip error: {e}")))?;
            io::Write::write_all(&mut zip, &content)?;
            pb.inc(1);
        }
        zip.finish().map_err(|e| io::Error::other(format!("Zip error: {e}")))?;
        pb.finish_and_clear();
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
    links: &[String],
    description: &str,
    force: bool,
    lowercase: bool,
    http: &HttpClient,
) -> io::Result<()> {
    validate_pkg_spec("package name", name)?;
    validate_pkg_spec("version", version)?;
    for dep in deps {
        validate_pkg_spec("dependency", dep)?;
    }
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

    let (files, sources) = if mappings.is_empty() {
        (BTreeMap::new(), BTreeMap::new())
    } else {
        resolve_mappings(from, mappings, lowercase)?
    };

    let is_meta = files.is_empty();
    println!("Package: {name}@{version}{}", if is_meta { " (meta-package)" } else { "" });
    if !files.is_empty() {
        println!("Files: {}", files.len());
        for (file, dest) in &files {
            println!("  {file} -> {dest}");
        }
    }
    if !deps.is_empty() {
        println!("Dependencies: {}", deps.join(", "));
    }

    // Parse --link args: "dest:target"
    let mut link_map = BTreeMap::new();
    for l in links {
        let (dest, target) = l
            .split_once(':')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid link (missing ':'): {l}")))?;
        link_map
            .insert(crate::platform::to_manifest_path(dest.trim()), crate::platform::to_manifest_path(target.trim()));
    }
    if !link_map.is_empty() {
        println!("Links: {}", link_map.len());
        for (dest, target) in &link_map {
            println!("  {dest} -> {target}");
        }
    }

    let manifest = Manifest {
        name: name.to_string(),
        description: description.to_string(),
        files,
        dependencies: deps.to_vec(),
        links: link_map,
    };

    let manifest_json =
        serde_json::to_string_pretty(&manifest).map_err(|e| io::Error::other(format!("JSON error: {e}")))?;

    // Upload zip first (if any), then manifest (server updates index on manifest upload)
    if !is_meta {
        let zip_data = create_package_zip(&sources)?;
        let url = format!("{}/upload/{name}/{version}/files.zip", http.config.server_url);
        let resp = http.post_with_progress(&url, zip_data, &format!("Uploading {name}@{version}"))?;
        if !resp.status().is_success() {
            return Err(io::Error::other(format!("Failed to upload zip: {}", resp.status())));
        }
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
    existing_links: &[String],
    existing_desc: &str,
    force: bool,
    lowercase: bool,
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

    upload(name, version, from, &mappings, &deps, existing_links, &description, force, lowercase, http)
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
            path_map: std::collections::BTreeMap::new(),
            cache_dir: Some(base_dir.join(".cache")),
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
        let http = HttpClient::new(&config, false).unwrap();

        fs::write(src_tmp.path().join("tool.exe"), b"tool-binary").unwrap();

        upload(
            "newtool",
            "1.0",
            src_tmp.path(),
            &["*.exe:util/".to_string()],
            &[],
            &[],
            "A new tool",
            false,
            false,
            &http,
        )
        .unwrap();

        let index = fetch_index(&http).unwrap();
        assert_eq!(index["newtool"].latest, "1.0");

        let mut db = Database::load_from(&db_path).unwrap();
        install("newtool", None, false, false, &http, &mut db).unwrap();
        assert!(install_tmp.path().join("util").join("tool.exe").exists());
    }

    #[test]
    fn upload_semicolon_grouped_mappings() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let install_tmp = tempfile::tempdir().unwrap();
        let src_tmp = tempfile::tempdir().unwrap();

        fs::create_dir_all(repo_tmp.path().join("packages")).unwrap();
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());
        let config = test_config(port, install_tmp.path(), &fp);
        let http = HttpClient::new(&config, false).unwrap();

        fs::write(src_tmp.path().join("a.exe"), b"aaa").unwrap();
        fs::write(src_tmp.path().join("b.dll"), b"bbb").unwrap();
        fs::write(src_tmp.path().join("c.txt"), b"ccc").unwrap();

        // "a.exe;b.dll:bin" means both go to bin/, "c.txt:doc" separately
        upload(
            "grouped",
            "1.0",
            src_tmp.path(),
            &["a.exe;b.dll:bin".to_string(), "c.txt:doc".to_string()],
            &[],
            &[],
            "",
            false,
            false,
            &http,
        )
        .unwrap();

        let manifest = crate::install::fetch_manifest(&http, "grouped", "1.0").unwrap();
        assert_eq!(manifest.files["a.exe"], "bin");
        assert_eq!(manifest.files["b.dll"], "bin");
        assert_eq!(manifest.files["c.txt"], "doc");
    }

    #[test]
    fn upload_lowercase_literal_filename() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let src_tmp = tempfile::tempdir().unwrap();

        fs::create_dir_all(repo_tmp.path().join("packages")).unwrap();
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());
        let config = test_config(port, src_tmp.path(), &fp);
        let http = HttpClient::new(&config, false).unwrap();

        fs::write(src_tmp.path().join("MyTool.EXE"), b"binary").unwrap();

        // Literal filename with --lowercase
        upload("lc-literal", "1.0", src_tmp.path(), &["MyTool.EXE:bin".to_string()], &[], &[], "", false, true, &http)
            .unwrap();

        let manifest = crate::install::fetch_manifest(&http, "lc-literal", "1.0").unwrap();
        assert!(
            manifest.files.contains_key("mytool.exe"),
            "expected lowercase: {:?}",
            manifest.files.keys().collect::<Vec<_>>()
        );
        assert!(!manifest.files.contains_key("MyTool.EXE"));
    }

    #[test]
    fn upload_lowercase_glob_pattern() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let src_tmp = tempfile::tempdir().unwrap();

        fs::create_dir_all(repo_tmp.path().join("packages")).unwrap();
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());
        let config = test_config(port, src_tmp.path(), &fp);
        let http = HttpClient::new(&config, false).unwrap();

        fs::write(src_tmp.path().join("Helper.DLL"), b"lib").unwrap();
        fs::write(src_tmp.path().join("MAIN.EXE"), b"exe").unwrap();

        // Glob pattern with --lowercase
        upload(
            "lc-glob",
            "1.0",
            src_tmp.path(),
            &["*.DLL:lib".to_string(), "*.EXE:bin".to_string()],
            &[],
            &[],
            "",
            false,
            true,
            &http,
        )
        .unwrap();

        let manifest = crate::install::fetch_manifest(&http, "lc-glob", "1.0").unwrap();
        assert!(
            manifest.files.contains_key("helper.dll"),
            "expected lowercase: {:?}",
            manifest.files.keys().collect::<Vec<_>>()
        );
        assert!(
            manifest.files.contains_key("main.exe"),
            "expected lowercase: {:?}",
            manifest.files.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn manifest_dest_normalized_to_forward_slashes() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let src_tmp = tempfile::tempdir().unwrap();

        fs::create_dir_all(repo_tmp.path().join("packages")).unwrap();
        let (_rt, port, fp) = start_tls_server(repo_tmp.path());
        let config = test_config(port, src_tmp.path(), &fp);
        let http = HttpClient::new(&config, false).unwrap();

        fs::write(src_tmp.path().join("tool.exe"), b"tool-binary").unwrap();

        // Upload with backslash dest — manifest should store forward slashes
        upload(
            "slashtest",
            "1.0",
            src_tmp.path(),
            &["*.exe:sub\\dir\\".to_string()],
            &[],
            &[],
            "",
            false,
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
        let http = HttpClient::new(&config, false).unwrap();

        fs::write(src_tmp.path().join("lib.dll"), b"lib-binary").unwrap();

        upload("fwdtest", "1.0", src_tmp.path(), &["*.dll:lib/native/".to_string()], &[], &[], "", false, false, &http)
            .unwrap();

        let manifest = crate::install::fetch_manifest(&http, "fwdtest", "1.0").unwrap();
        let dest = manifest.files.get("lib.dll").unwrap();
        assert_eq!(dest, "lib/native/");
    }
}
