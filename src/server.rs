use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use crate::repo::RepoIndex;

pub struct AppState {
    pub index: RepoIndex,
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/index", get(get_index))
        .route("/packages/{name}", get(get_versions))
        .route("/packages/{name}/{version}/{filename}", get(get_file))
        .with_state(state)
}

/// Start the server on the given port.
///
/// # Errors
/// Returns an error if the server fails to bind or run.
pub async fn run(repo_path: PathBuf, port: u16) -> std::io::Result<()> {
    let index = RepoIndex::scan(&repo_path)?;
    let pkg_count = index.packages.len();

    let state = Arc::new(AppState { index });
    let app = build_router(state);

    let (cert_path, key_path) = crate::tls::ensure_certs()?;
    let fingerprint = crate::tls::current_fingerprint()?;
    let tls_config = RustlsConfig::from_pem_file(&cert_path, &key_path).await.map_err(std::io::Error::other)?;

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("Serving repo {} on https://{addr}", repo_path.display());
    println!("{pkg_count} packages available");
    println!("Fingerprint: {fingerprint}");

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
    use crate::testutil::helpers::{start_tls_server, tls_client};
    use std::fs;

    fn create_test_repo(base: &std::path::Path) {
        let pkg_dir = base.join("packages").join("testpkg").join("1.0");
        fs::create_dir_all(&pkg_dir).unwrap();
        fs::write(
            pkg_dir.join("blob.json"),
            r#"{"name":"testpkg","description":"A test","files":{"test.exe":"util/"},"dependencies":[]}"#,
        )
        .unwrap();
        fs::write(pkg_dir.join("test.exe"), b"fake-exe-content").unwrap();
    }

    #[test]
    fn test_get_index() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let (_rt, port, fp) = start_tls_server(tmp.path());
        let client = tls_client(&fp);

        let resp = client.get(format!("https://localhost:{port}/index")).send().unwrap();
        assert_eq!(resp.status(), 200);
        let json: serde_json::Value = resp.json().unwrap();
        assert_eq!(json["testpkg"], "1.0");
    }

    #[test]
    fn test_get_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let (_rt, port, fp) = start_tls_server(tmp.path());
        let client = tls_client(&fp);

        let resp = client.get(format!("https://localhost:{port}/packages/testpkg/1.0/blob.json")).send().unwrap();
        assert_eq!(resp.status(), 200);
        let json: serde_json::Value = resp.json().unwrap();
        assert_eq!(json["name"], "testpkg");
    }

    #[test]
    fn test_get_file() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let (_rt, port, fp) = start_tls_server(tmp.path());
        let client = tls_client(&fp);

        let resp = client.get(format!("https://localhost:{port}/packages/testpkg/1.0/test.exe")).send().unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.bytes().unwrap().as_ref(), b"fake-exe-content");
    }

    #[test]
    fn test_not_found_package() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let (_rt, port, fp) = start_tls_server(tmp.path());
        let client = tls_client(&fp);

        let resp = client.get(format!("https://localhost:{port}/packages/nonexistent/1.0/blob.json")).send().unwrap();
        assert_eq!(resp.status(), 404);
    }

    #[test]
    fn test_not_found_version() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let (_rt, port, fp) = start_tls_server(tmp.path());
        let client = tls_client(&fp);

        let resp = client.get(format!("https://localhost:{port}/packages/testpkg/9.9/blob.json")).send().unwrap();
        assert_eq!(resp.status(), 404);
    }

    #[test]
    fn test_not_found_file() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let (_rt, port, fp) = start_tls_server(tmp.path());
        let client = tls_client(&fp);

        let resp = client.get(format!("https://localhost:{port}/packages/testpkg/1.0/missing.exe")).send().unwrap();
        assert_eq!(resp.status(), 404);
    }

    #[test]
    fn test_path_traversal_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let (_rt, port, fp) = start_tls_server(tmp.path());
        let client = tls_client(&fp);

        let resp =
            client.get(format!("https://localhost:{port}/packages/testpkg/1.0/..%2F..%2Fetc%2Fpasswd")).send().unwrap();
        assert_ne!(resp.status(), 200);
    }
}
