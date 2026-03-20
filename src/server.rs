use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;

use crate::repo::RepoIndex;

pub struct AppState {
    pub index: RepoIndex,
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/index", get(get_index))
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

    let addr = format!("0.0.0.0:{port}");
    println!("Serving repo {} on {addr}", repo_path.display());
    println!("{pkg_count} packages available");

    let listener = TcpListener::bind(&addr).await?;
    axum::serve(listener, app)
        .await
        .map_err(std::io::Error::other)
}

async fn get_index(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let value = serde_json::to_value(state.index.index_summary()).unwrap_or_default();
    let size = serde_json::to_string(&value).map_or(0, |s| s.len());
    println!("GET /index ({size} bytes)");
    Json(value)
}

async fn get_file(
    State(state): State<Arc<AppState>>,
    Path((name, version, filename)): Path<(String, String, String)>,
) -> impl IntoResponse {
    let pkg = state.index.packages.get(&name);
    if pkg.is_none() || !pkg.unwrap().versions.contains(&version) {
        return Err(StatusCode::NOT_FOUND);
    }

    let path = state.index.package_file_path(&name, &version, &filename);
    match tokio::fs::read(&path).await {
        Ok(bytes) => {
            println!("GET /packages/{name}/{version}/{filename} ({} bytes)", bytes.len());
            Ok(bytes)
        }
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use std::fs;
    use tower::ServiceExt;

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

    fn build_test_app(repo_path: &std::path::Path) -> Router {
        let index = RepoIndex::scan(repo_path).unwrap();
        let state = Arc::new(AppState { index });
        build_router(state)
    }

    #[tokio::test]
    async fn test_get_index() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let app = build_test_app(tmp.path());

        let resp = app
            .oneshot(Request::get("/index").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["testpkg"], "1.0");
    }

    #[tokio::test]
    async fn test_get_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let app = build_test_app(tmp.path());

        let resp = app
            .oneshot(
                Request::get("/packages/testpkg/1.0/blob.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["name"], "testpkg");
    }

    #[tokio::test]
    async fn test_get_file() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let app = build_test_app(tmp.path());

        let resp = app
            .oneshot(
                Request::get("/packages/testpkg/1.0/test.exe")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body.as_ref(), b"fake-exe-content");
    }

    #[tokio::test]
    async fn test_not_found_package() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let app = build_test_app(tmp.path());

        let resp = app
            .oneshot(
                Request::get("/packages/nonexistent/1.0/blob.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_not_found_version() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let app = build_test_app(tmp.path());

        let resp = app
            .oneshot(
                Request::get("/packages/testpkg/9.9/blob.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_not_found_file() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let app = build_test_app(tmp.path());

        let resp = app
            .oneshot(
                Request::get("/packages/testpkg/1.0/missing.exe")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
