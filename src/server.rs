use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use base64::Engine;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use crate::repo::RepoIndex;

pub struct AppState {
    pub index: RepoIndex,
    pub auth: (String, String),
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/index", get(get_index))
        .route("/packages/{name}", get(get_versions))
        .route("/packages/{name}/{version}/{filename}", get(get_file))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state)
}

async fn auth_middleware(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let (expected_user, expected_pass) = &state.auth;

    let authorized = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .is_some_and(|creds| creds.split_once(':').is_some_and(|(u, p)| u == expected_user && p == expected_pass));

    if authorized { next.run(req).await } else { (StatusCode::UNAUTHORIZED, "Unauthorized").into_response() }
}

/// Start the server on the given port.
///
/// # Errors
/// Returns an error if the server fails to bind or run.
pub async fn run(repo_path: PathBuf, port: u16, auth: (String, String)) -> std::io::Result<()> {
    let index = RepoIndex::scan(&repo_path)?;
    let pkg_count = index.packages.len();

    let state = Arc::new(AppState { index, auth });
    let app = build_router(state);

    let (cert_path, key_path) = crate::tls::ensure_certs()?;
    let fingerprint = crate::tls::current_fingerprint()?;
    let tls_config = RustlsConfig::from_pem_file(&cert_path, &key_path).await.map_err(std::io::Error::other)?;

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("Serving repo {} on https://{addr}", repo_path.display());
    println!("{pkg_count} packages available");
    println!("Fingerprint: {fingerprint}");
    println!("Basic Auth: enabled");

    axum_server::bind_rustls(addr, tls_config).serve(app.into_make_service()).await.map_err(std::io::Error::other)
}

async fn get_index(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let value = serde_json::to_value(state.index.index_summary()).unwrap_or_default();
    let size = serde_json::to_string(&value).map_or(0, |s| s.len());
    println!("GET /index ({size} bytes)");
    Json(value)
}

async fn get_versions(State(state): State<Arc<AppState>>, Path(name): Path<String>) -> impl IntoResponse {
    if !is_safe_segment(&name) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let Some(pkg) = state.index.packages.get(&name) else {
        return Err(StatusCode::NOT_FOUND);
    };
    let value = serde_json::json!({
        "name": name,
        "latest": pkg.latest,
        "versions": pkg.versions,
    });
    Ok(Json(value))
}

/// Check that a URL path segment contains no traversal or special characters.
fn is_safe_segment(s: &str) -> bool {
    !s.is_empty()
        && !s.contains("..")
        && !s.contains('/')
        && !s.contains('\\')
        && !s.contains(':')
        && !s.contains('\0')
        && !s.starts_with('.')
}

async fn get_file(
    State(state): State<Arc<AppState>>,
    Path((name, version, filename)): Path<(String, String, String)>,
) -> impl IntoResponse {
    let Some(pkg) = state.index.packages.get(&name) else {
        return Err(StatusCode::NOT_FOUND);
    };
    if !pkg.versions.contains(&version) {
        return Err(StatusCode::NOT_FOUND);
    }

    if !is_safe_segment(&name) || !is_safe_segment(&version) || !is_safe_segment(&filename) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let path = state.index.package_file_path(&name, &version, &filename);

    // Verify resolved path is inside the repo
    let Ok(canonical) = tokio::fs::canonicalize(&path).await else {
        return Err(StatusCode::NOT_FOUND);
    };
    let Ok(repo_base) = tokio::fs::canonicalize(state.index.package_file_path(&name, &version, "")).await else {
        return Err(StatusCode::NOT_FOUND);
    };
    if !canonical.starts_with(&repo_base) {
        return Err(StatusCode::BAD_REQUEST);
    }
    match tokio::fs::read(&canonical).await {
        Ok(bytes) => {
            println!("GET /packages/{name}/{version}/{filename} ({} bytes)", bytes.len());
            Ok(bytes)
        }
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
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
}
