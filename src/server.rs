use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use base64::Engine;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use crate::repo::{Manifest, RepoIndex};

/// Maximum failed auth attempts per IP before lockout.
const MAX_AUTH_FAILURES: u32 = 5;
/// Lockout duration after exceeding `MAX_AUTH_FAILURES`.
const AUTH_LOCKOUT_SECS: u64 = 30;

pub struct AppState {
    pub index: std::sync::RwLock<RepoIndex>,
    pub auth: (String, String),
    pub repo_path: PathBuf,
    pub auth_failures: std::sync::Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/index", get(get_index))
        .route("/packages/{name}", get(get_versions))
        .route("/packages/{name}/{version}/{filename}", get(get_file))
        // TODO: Security: consider per-IP rate limiting on uploads to prevent disk exhaustion
        .route(
            "/upload/{name}/{version}/{filename}",
            axum::routing::post(post_upload).layer(axum::extract::DefaultBodyLimit::max(512 * 1024 * 1024)),
        )
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .layer(middleware::map_response(add_security_headers))
        .layer(tower::limit::ConcurrencyLimitLayer::new(5))
        .with_state(state)
}

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let ip = addr.ip();

    // Check rate limit before processing auth
    if let Ok(failures) = state.auth_failures.lock()
        && let Some((count, last)) = failures.get(&ip)
        && *count >= MAX_AUTH_FAILURES
        && last.elapsed().as_secs() < AUTH_LOCKOUT_SECS
    {
        eprintln!("Auth rate-limited: {ip} (locked out for {AUTH_LOCKOUT_SECS}s)");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::WWW_AUTHENTICATE, "Basic realm=\"blob\"")],
            "Too many failed attempts. Try again later.",
        )
            .into_response();
    }

    let (expected_user, expected_pass) = &state.auth;

    let authorized = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .is_some_and(|creds| {
            creds.split_once(':').is_some_and(|(u, p)| {
                let u_ok = constant_time_eq::constant_time_eq(u.as_bytes(), expected_user.as_bytes());
                let p_ok = constant_time_eq::constant_time_eq(p.as_bytes(), expected_pass.as_bytes());
                u_ok & p_ok
            })
        });

    if authorized {
        // Clear failures on successful auth
        if let Ok(mut failures) = state.auth_failures.lock() {
            failures.remove(&ip);
        }
        next.run(req).await
    } else {
        if let Ok(mut failures) = state.auth_failures.lock() {
            let entry = failures.entry(ip).or_insert((0, Instant::now()));
            // Reset counter if lockout period has passed
            if entry.1.elapsed().as_secs() >= AUTH_LOCKOUT_SECS {
                *entry = (0, Instant::now());
            }
            entry.0 += 1;
            entry.1 = Instant::now();
            eprintln!("Auth failed from {ip} ({}/{MAX_AUTH_FAILURES})", entry.0);
        }
        (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Basic realm=\"blob\"")],
            "Unauthorized",
        )
            .into_response()
    }
}

/// Start the server on the given port.
///
/// # Errors
/// Returns an error if the server fails to bind or run.
pub async fn run(repo_path: PathBuf, bind: &str, port: u16, auth: (String, String)) -> std::io::Result<()> {
    if auth.0.is_empty() || auth.1.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Username and password must not be empty. Set via --username/--password or BLOB_USERNAME/BLOB_PASSWORD.",
        ));
    }

    let index = RepoIndex::scan(&repo_path)?;
    let pkg_count = index.packages.len();

    let bind_addr: std::net::IpAddr = bind
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Invalid bind address: {e}")))?;

    println!("Serving repo {} on https://{bind}:{port}", repo_path.display());

    let state = Arc::new(AppState {
        index: std::sync::RwLock::new(index),
        auth,
        repo_path,
        auth_failures: std::sync::Mutex::new(HashMap::new()),
    });
    let app = build_router(state);

    let (cert_path, key_path) = crate::tls::ensure_certs()?;
    let fingerprint = crate::tls::current_fingerprint()?;
    let tls_config = RustlsConfig::from_pem_file(&cert_path, &key_path).await.map_err(std::io::Error::other)?;

    let addr = SocketAddr::from((bind_addr, port));
    println!("{pkg_count} packages available");
    println!("Fingerprint: {fingerprint}");
    // TODO: add structured logging with timestamps and audit trail for uploads/downloads
    println!("Basic Auth: enabled");

    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .map_err(std::io::Error::other)
}

async fn get_index(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let value = {
        let Ok(index) = state.index.read() else {
            return Json(serde_json::Value::Object(serde_json::Map::default()));
        };
        serde_json::to_value(index.index_summary()).unwrap_or_default()
    };
    let size = serde_json::to_string(&value).map_or(0, |s| s.len());
    println!("GET /index ({size} bytes)");
    Json(value)
}

async fn get_versions(State(state): State<Arc<AppState>>, Path(name): Path<String>) -> impl IntoResponse {
    if !is_safe_segment(&name) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let value = {
        let Ok(index) = state.index.read() else {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        };
        let Some(pkg) = index.packages.get(&name) else {
            return Err(StatusCode::NOT_FOUND);
        };
        serde_json::json!({
            "name": name,
            "latest": pkg.latest,
            "versions": pkg.versions,
        })
    };
    Ok(Json(value))
}

/// Check that a URL path segment contains only safe printable ASCII,
/// no traversal, no Windows-reserved names, no dangerous special characters.
fn is_safe_segment(s: &str) -> bool {
    if s.is_empty() || s.starts_with('.') || s.ends_with('.') || s.ends_with(' ') {
        return false;
    }
    // Only printable ASCII 33–126, excluding dangerous characters
    if !s.bytes().all(crate::client::is_safe_spec_char) {
        return false;
    }
    // Reject Windows reserved device names (CON, PRN, NUL, COM1, etc.)
    let stem = s.split('.').next().unwrap_or(s);
    !crate::client::WINDOWS_RESERVED.iter().any(|r| r.eq_ignore_ascii_case(stem))
}

async fn add_security_headers(mut resp: Response) -> Response {
    resp.headers_mut().insert(
        header::STRICT_TRANSPORT_SECURITY,
        "max-age=63072000; includeSubDomains".parse().unwrap(),
    );
    resp
}

async fn get_file(
    State(state): State<Arc<AppState>>,
    Path((name, version, filename)): Path<(String, String, String)>,
) -> impl IntoResponse {
    if !is_safe_segment(&name) || !is_safe_segment(&version) || !is_safe_segment(&filename) {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check index (lock scope limited to avoid holding across await)
    {
        let Ok(index) = state.index.read() else {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        };
        let Some(pkg) = index.packages.get(&name) else {
            return Err(StatusCode::NOT_FOUND);
        };
        if !pkg.versions.contains(&version) {
            return Err(StatusCode::NOT_FOUND);
        }
    }

    let path = state.repo_path.join("packages").join(&name).join(&version).join(&filename);

    // Verify resolved path is inside the repo
    let Ok(canonical) = tokio::fs::canonicalize(&path).await else {
        return Err(StatusCode::NOT_FOUND);
    };
    let Ok(repo_base) = tokio::fs::canonicalize(state.repo_path.join("packages").join(&name).join(&version)).await
    else {
        return Err(StatusCode::NOT_FOUND);
    };
    if !canonical.starts_with(&repo_base) {
        return Err(StatusCode::BAD_REQUEST);
    }
    match tokio::fs::read(&canonical).await {
        Ok(bytes) => {
            println!("GET /packages/{name}/{version}/{filename} ({} bytes)", bytes.len());
            let content_type = if std::path::Path::new(&filename)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
            {
                "application/json"
            } else {
                "application/octet-stream"
            };
            Ok((
                [
                    (header::CONTENT_TYPE, content_type),
                    (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
                ],
                bytes,
            ))
        }
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

/// Verify that a zip file contains all files listed in the manifest (and no extras).
fn validate_zip_against_manifest(manifest_path: &std::path::Path, zip_path: &std::path::Path) -> Result<(), String> {
    let manifest_data = std::fs::read(manifest_path).map_err(|e| format!("read manifest: {e}"))?;
    let manifest: Manifest = serde_json::from_slice(&manifest_data).map_err(|e| format!("parse manifest: {e}"))?;
    let zip_file = std::fs::File::open(zip_path).map_err(|e| format!("open zip: {e}"))?;
    let archive = zip::ZipArchive::new(zip_file).map_err(|e| format!("parse zip: {e}"))?;

    let zip_names: std::collections::HashSet<String> = (0..archive.len())
        .filter_map(|i| archive.name_for_index(i).map(String::from))
        .collect();
    let manifest_names: std::collections::HashSet<&String> = manifest.files.keys().collect();

    let missing: Vec<_> = manifest_names.iter().filter(|f| !zip_names.contains(**f)).collect();
    if !missing.is_empty() {
        return Err(format!("files in manifest but missing from zip: {missing:?}"));
    }
    let extra: Vec<_> = zip_names.iter().filter(|f| !manifest_names.contains(f)).collect();
    if !extra.is_empty() {
        return Err(format!("files in zip but not in manifest: {extra:?}"));
    }
    Ok(())
}

async fn post_upload(
    State(state): State<Arc<AppState>>,
    Path((name, version, filename)): Path<(String, String, String)>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    if !is_safe_segment(&name) || !is_safe_segment(&version) || !is_safe_segment(&filename) {
        return Err(StatusCode::BAD_REQUEST);
    }
    // Only allow manifest.json and files.zip
    if filename != "manifest.json" && filename != "files.zip" {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate manifest content before writing to disk
    if filename == "manifest.json" {
        let manifest: Manifest = serde_json::from_slice(&body).map_err(|e| {
            eprintln!("Invalid manifest JSON for {name}/{version}: {e}");
            StatusCode::BAD_REQUEST
        })?;
        if manifest.name != name {
            eprintln!("Manifest name mismatch: URL={name}, manifest={}", manifest.name);
            return Err(StatusCode::BAD_REQUEST);
        }
        for (file, dest_dir) in &manifest.files {
            if crate::client::validate_manifest_path(file, dest_dir, &name).is_err() {
                eprintln!("Unsafe path in manifest for {name}/{version}: {file} -> {dest_dir}");
                return Err(StatusCode::BAD_REQUEST);
            }
        }
    }

    let dir = state.repo_path.join("packages").join(&name).join(&version);
    if let Err(e) = tokio::fs::create_dir_all(&dir).await {
        eprintln!("Failed to create dir {}: {e}", dir.display());
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // Defense in depth: verify resolved path stays inside repo
    let Ok(canonical_dir) = tokio::fs::canonicalize(&dir).await else {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let Ok(canonical_packages) = tokio::fs::canonicalize(state.repo_path.join("packages")).await else {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };
    if !canonical_dir.starts_with(&canonical_packages) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let path = canonical_dir.join(&filename);
    if let Err(e) = tokio::fs::write(&path, &body).await {
        eprintln!("Failed to write {}: {e}", path.display());
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    println!("POST /upload/{name}/{version}/{filename} ({} bytes)", body.len());

    // Cross-validate: when both manifest.json and files.zip exist, check zip contains all manifest files
    let manifest_path = canonical_dir.join("manifest.json");
    let zip_path = canonical_dir.join("files.zip");
    if manifest_path.is_file()
        && zip_path.is_file()
        && let Err(e) = validate_zip_against_manifest(&manifest_path, &zip_path)
    {
        eprintln!("Zip/manifest mismatch for {name}/{version}: {e}");
        // Remove the just-uploaded file so we don't leave inconsistent state
        let _ = tokio::fs::remove_file(&path).await;
        return Err(StatusCode::BAD_REQUEST);
    }

    // TODO: incremental index update instead of full rescan (scales poorly for large repos)
    if filename == "manifest.json"
        && let Ok(new_index) = RepoIndex::scan(&state.repo_path)
        && let Ok(mut index) = state.index.write()
    {
        *index = new_index;
    }

    Ok(StatusCode::CREATED)
}

#[cfg(test)]
mod tests {
    use crate::testutil::helpers::{TEST_PASS, TEST_USER, create_zip, start_tls_server, tls_client_no_auth};
    use std::fs;

    fn create_test_repo(base: &std::path::Path) {
        let pkg_dir = base.join("packages").join("testpkg").join("1.0");
        fs::create_dir_all(&pkg_dir).unwrap();
        fs::write(
            pkg_dir.join("manifest.json"),
            r#"{"name":"testpkg","description":"A test","files":{"test.exe":"util/"},"dependencies":[]}"#,
        )
        .unwrap();
        create_zip(&pkg_dir, &[("test.exe", b"fake-exe-content")]);
    }

    fn auth_get(client: &reqwest::blocking::Client, url: &str) -> reqwest::blocking::Response {
        client.get(url).basic_auth(TEST_USER, Some(TEST_PASS)).send().unwrap()
    }

    #[test]
    fn test_get_index() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let (_rt, port, fp) = start_tls_server(tmp.path());
        let client = tls_client_no_auth(&fp);

        let resp = auth_get(&client, &format!("https://localhost:{port}/index"));
        assert_eq!(resp.status(), 200);
        let json: serde_json::Value = resp.json().unwrap();
        assert_eq!(json["testpkg"], "1.0");
    }

    #[test]
    fn test_get_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let (_rt, port, fp) = start_tls_server(tmp.path());
        let client = tls_client_no_auth(&fp);

        let resp = auth_get(&client, &format!("https://localhost:{port}/packages/testpkg/1.0/manifest.json"));
        assert_eq!(resp.status(), 200);
        let json: serde_json::Value = resp.json().unwrap();
        assert_eq!(json["name"], "testpkg");
    }

    #[test]
    fn test_get_zip() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let (_rt, port, fp) = start_tls_server(tmp.path());
        let client = tls_client_no_auth(&fp);

        let resp = auth_get(&client, &format!("https://localhost:{port}/packages/testpkg/1.0/files.zip"));
        assert_eq!(resp.status(), 200);
        let bytes = resp.bytes().unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_not_found_package() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let (_rt, port, fp) = start_tls_server(tmp.path());
        let client = tls_client_no_auth(&fp);

        let resp = auth_get(&client, &format!("https://localhost:{port}/packages/nonexistent/1.0/manifest.json"));
        assert_eq!(resp.status(), 404);
    }

    #[test]
    fn test_not_found_version() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let (_rt, port, fp) = start_tls_server(tmp.path());
        let client = tls_client_no_auth(&fp);

        let resp = auth_get(&client, &format!("https://localhost:{port}/packages/testpkg/9.9/manifest.json"));
        assert_eq!(resp.status(), 404);
    }

    #[test]
    fn test_not_found_file() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let (_rt, port, fp) = start_tls_server(tmp.path());
        let client = tls_client_no_auth(&fp);

        let resp = auth_get(&client, &format!("https://localhost:{port}/packages/testpkg/1.0/missing.exe"));
        assert_eq!(resp.status(), 404);
    }

    #[test]
    fn test_path_traversal_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let (_rt, port, fp) = start_tls_server(tmp.path());
        let client = tls_client_no_auth(&fp);

        let resp = auth_get(&client, &format!("https://localhost:{port}/packages/testpkg/1.0/..%2F..%2Fetc%2Fpasswd"));
        assert_ne!(resp.status(), 200);
    }

    #[test]
    fn test_auth_rejected_without_credentials() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let (_rt, port, fp) = start_tls_server(tmp.path());
        let client = tls_client_no_auth(&fp);

        // No auth header
        let resp = client.get(format!("https://localhost:{port}/index")).send().unwrap();
        assert_eq!(resp.status(), 401);
    }

    #[test]
    fn test_auth_rejected_wrong_password() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let (_rt, port, fp) = start_tls_server(tmp.path());
        let client = tls_client_no_auth(&fp);

        let resp =
            client.get(format!("https://localhost:{port}/index")).basic_auth("admin", Some("wrong")).send().unwrap();
        assert_eq!(resp.status(), 401);
    }

    #[test]
    fn test_auth_accepted_correct_credentials() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let (_rt, port, fp) = start_tls_server(tmp.path());
        let client = tls_client_no_auth(&fp);

        let resp = auth_get(&client, &format!("https://localhost:{port}/index"));
        assert_eq!(resp.status(), 200);
    }

    #[test]
    fn test_upload_package() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let (_rt, port, fp) = start_tls_server(tmp.path());
        let client = tls_client_no_auth(&fp);

        // Upload a manifest
        let manifest = r#"{"name":"newpkg","description":"test","files":{"new.exe":"util/"},"dependencies":[]}"#;
        let resp = client
            .post(format!("https://localhost:{port}/upload/newpkg/1.0/manifest.json"))
            .basic_auth(TEST_USER, Some(TEST_PASS))
            .body(manifest.to_string())
            .send()
            .unwrap();
        assert_eq!(resp.status(), 201);

        // Upload a zip
        let mut zip_buf = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut zip_buf);
            zip.start_file("new.exe", zip::write::SimpleFileOptions::default()).unwrap();
            std::io::Write::write_all(&mut zip, b"new-binary").unwrap();
            zip.finish().unwrap();
        }
        let resp = client
            .post(format!("https://localhost:{port}/upload/newpkg/1.0/files.zip"))
            .basic_auth(TEST_USER, Some(TEST_PASS))
            .body(zip_buf.into_inner())
            .send()
            .unwrap();
        assert_eq!(resp.status(), 201);

        // Verify files exist on disk
        assert!(tmp.path().join("packages/newpkg/1.0/manifest.json").is_file());
        assert!(tmp.path().join("packages/newpkg/1.0/files.zip").is_file());
    }

    #[test]
    fn test_upload_rejects_bad_filename() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let (_rt, port, fp) = start_tls_server(tmp.path());
        let client = tls_client_no_auth(&fp);

        let resp = client
            .post(format!("https://localhost:{port}/upload/pkg/1.0/evil.txt"))
            .basic_auth(TEST_USER, Some(TEST_PASS))
            .body("data")
            .send()
            .unwrap();
        assert_eq!(resp.status(), 400);
    }
}
