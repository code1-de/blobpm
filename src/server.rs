use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use base64::Engine;
use futures_util::StreamExt;
use std::collections::HashMap;
use std::io::{BufWriter, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use crate::repo::{Manifest, RepoIndex};

/// Maximum failed auth attempts per IP before first lockout.
pub(crate) const MAX_AUTH_FAILURES: u32 = 5;
/// Base lockout duration in seconds (doubles on each subsequent violation tier).
pub(crate) const BASE_LOCKOUT_SECS: u64 = 30;
/// Maximum lockout duration in seconds (1 hour cap). Also the inactivity reset threshold.
pub(crate) const MAX_LOCKOUT_SECS: u64 = 3600;
/// Maximum concurrent connections.
pub(crate) const MAX_CONCURRENT: usize = 20;
/// Maximum concurrent connections per IP.
pub(crate) const MAX_CONNECTIONS_PER_IP: u32 = 10;
/// Prune auth failure map when it exceeds this many entries.
const AUTH_MAP_MAX: usize = 128;
/// Server-side request timeout in seconds (covers entire request lifecycle).
pub(crate) const REQUEST_TIMEOUT_SECS: u64 = 600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    Reader,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct UserEntry {
    pub username: String,
    pub password: String,
    pub role: UserRole,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ServerConfig {
    pub repo: PathBuf,
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<PathBuf>,
    pub users: Vec<UserEntry>,
}

fn default_bind() -> String {
    // Localhost on both stacks — safe default, reachable via IPv4 or IPv6 clients.
    "127.0.0.1,::1".to_string()
}

/// Parse the `bind` config field into one or more IP addresses.
///
/// Accepts either a single address ("0.0.0.0", "::", "127.0.0.1") or a
/// comma-separated list ("0.0.0.0,::") for dual-stack deployments.
/// Note: on Linux, binding a single "::" listener also accepts IPv4
/// connections (`IPV6_V6ONLY=0` by default), so "::" alone is usually enough.
/// Windows binds are strict IPv6-only; use "0.0.0.0,::" there.
fn parse_bind_addrs(bind: &str) -> std::io::Result<Vec<std::net::IpAddr>> {
    let addrs: Result<Vec<_>, _> = bind.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).map(str::parse).collect();
    let addrs = addrs.map_err(|e: std::net::AddrParseError| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Invalid bind address in {bind:?}: {e}"))
    })?;
    if addrs.is_empty() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "bind must not be empty"));
    }
    Ok(addrs)
}

const fn default_port() -> u16 {
    53777
}

/// Per-IP auth failure tracking for exponential backoff.
pub(crate) struct AuthFailure {
    count: u32,
    last_attempt: Instant,
}

pub struct AppState {
    pub index: std::sync::RwLock<RepoIndex>,
    pub users: Vec<UserEntry>,
    pub repo_path: PathBuf,
    pub auth_failures: std::sync::Mutex<HashMap<IpAddr, AuthFailure>>,
    pub active_connections: std::sync::Mutex<HashMap<IpAddr, u32>>,
    pub log_file: std::sync::Mutex<Option<BufWriter<std::fs::File>>>,
}

impl AppState {
    fn log_entry(&self, ip: IpAddr, method: &str, path: &str, status: u16, detail: Option<&str>) {
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
        let detail_str = detail.map_or_else(String::new, |d| format!("  {d}"));
        let line = format!("{now}  {ip}  {method} {path}  {status}{detail_str}\n");
        print!("{line}");
        if let Ok(mut guard) = self.log_file.lock()
            && let Some(f) = guard.as_mut()
        {
            let _ = f.write_all(line.as_bytes());
            let _ = f.flush();
        }
    }
}

/// Sanitize an IO error for logging: return the OS error description without filesystem paths.
fn sanitize_io_error(err: &std::io::Error) -> String {
    match err.raw_os_error() {
        Some(code) => format!("{} (os error {code})", err.kind()),
        None => err.kind().to_string(),
    }
}

/// Calculate lockout duration in seconds based on failure count.
/// Doubles for each batch of `MAX_AUTH_FAILURES`: 30s, 60s, 120s, … capped at `MAX_LOCKOUT_SECS`.
fn lockout_secs(count: u32) -> u64 {
    if count < MAX_AUTH_FAILURES {
        return 0;
    }
    let level = u64::from((count / MAX_AUTH_FAILURES) - 1);
    (BASE_LOCKOUT_SECS << level.min(20)).min(MAX_LOCKOUT_SECS)
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/index", get(get_index))
        .route("/packages/{name}", get(get_versions))
        .route("/packages/{name}/{version}/{filename}", get(get_file))
        .route(
            "/upload/{name}/{version}/{filename}",
            axum::routing::post(post_upload).layer(axum::extract::DefaultBodyLimit::max(crate::MAX_UPLOAD_SIZE)),
        )
        .route("/packages/{name}/{version}", axum::routing::delete(delete_version))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .layer(middleware::map_response(add_security_headers))
        .layer(middleware::from_fn(request_timeout_middleware))
        .layer(middleware::from_fn_with_state(state.clone(), per_ip_limit_middleware))
        .layer(tower::limit::ConcurrencyLimitLayer::new(MAX_CONCURRENT))
        .with_state(state)
}

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let ip = addr.ip();

    let path = req.uri().path().to_string();
    let method = req.method().as_str().to_string();

    // Check per-IP rate limit with exponential backoff
    if let Ok(failures) = state.auth_failures.lock()
        && let Some(entry) = failures.get(&ip)
    {
        let lockout = lockout_secs(entry.count);
        if lockout > 0 && entry.last_attempt.elapsed().as_secs() < lockout {
            state.log_entry(
                ip,
                &method,
                &path,
                429,
                Some(&format!("per-IP auth lockout ({lockout}s, {} failures)", entry.count)),
            );
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::WWW_AUTHENTICATE, "Basic realm=\"blob\"")],
                "Too many failed attempts. Try again later.",
            )
                .into_response();
        }
    }

    // Match credentials against users list
    let matched_role = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|creds| {
            creds.split_once(':').and_then(|(u, p)| {
                state.users.iter().find_map(|entry| {
                    let u_ok = constant_time_eq::constant_time_eq(u.as_bytes(), entry.username.as_bytes());
                    let p_ok = constant_time_eq::constant_time_eq(p.as_bytes(), entry.password.as_bytes());
                    if u_ok & p_ok { Some(entry.role) } else { None }
                })
            })
        });

    if let Some(role) = matched_role {
        // Clear failures on successful auth
        if let Ok(mut failures) = state.auth_failures.lock() {
            failures.remove(&ip);
        }
        // Readers can only GET
        let is_write = method != "GET";
        if is_write && role == UserRole::Reader {
            state.log_entry(ip, &method, &path, 403, Some("reader attempted write"));
            return (StatusCode::FORBIDDEN, "Forbidden: read-only access").into_response();
        }
        next.run(req).await
    } else {
        let count = if let Ok(mut failures) = state.auth_failures.lock() {
            // Prune stale entries to bound HashMap size
            if failures.len() > AUTH_MAP_MAX {
                failures.retain(|_, entry| {
                    let expiry = lockout_secs(entry.count).max(BASE_LOCKOUT_SECS);
                    entry.last_attempt.elapsed().as_secs() < expiry
                });
            }
            let entry = failures.entry(ip).or_insert(AuthFailure { count: 0, last_attempt: Instant::now() });
            // Full reset after long inactivity
            if entry.last_attempt.elapsed().as_secs() >= MAX_LOCKOUT_SECS {
                entry.count = 0;
            }
            entry.count += 1;
            entry.last_attempt = Instant::now();
            entry.count
        } else {
            0
        };
        let lockout = lockout_secs(count);
        state.log_entry(
            ip,
            &method,
            &path,
            401,
            Some(&format!("auth failed ({count}/{MAX_AUTH_FAILURES}, next lockout {lockout}s)")),
        );
        (StatusCode::UNAUTHORIZED, [(header::WWW_AUTHENTICATE, "Basic realm=\"blob\"")], "Unauthorized").into_response()
    }
}

/// Drop guard that decrements the per-IP connection counter on request completion or cancellation.
struct IpConnectionGuard {
    state: Arc<AppState>,
    ip: IpAddr,
}

impl Drop for IpConnectionGuard {
    fn drop(&mut self) {
        if let Ok(mut active) = self.state.active_connections.lock()
            && let Some(count) = active.get_mut(&self.ip)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                active.remove(&self.ip);
            }
        }
    }
}

async fn per_ip_limit_middleware(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let ip = addr.ip();

    let _guard = {
        let mut active = state.active_connections.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = active.entry(ip).or_insert(0);
        if *count >= MAX_CONNECTIONS_PER_IP {
            return (StatusCode::TOO_MANY_REQUESTS, "Too many connections from this IP").into_response();
        }
        *count += 1;
        IpConnectionGuard { state: Arc::clone(&state), ip }
    };

    next.run(req).await
}

async fn request_timeout_middleware(req: Request, next: Next) -> Response {
    match tokio::time::timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS), next.run(req)).await {
        Ok(response) => response,
        Err(_) => (StatusCode::REQUEST_TIMEOUT, "Request timed out").into_response(),
    }
}

/// Start the server from a config file.
///
/// # Errors
/// Returns an error if the server fails to bind or run.
pub async fn run(config: ServerConfig) -> std::io::Result<()> {
    if config.users.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "No users configured. Add at least one user to the config file.",
        ));
    }
    for user in &config.users {
        if user.username.is_empty() || user.password.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Username and password must not be empty (user: {:?}).", user.username),
            ));
        }
    }

    let index = RepoIndex::scan(&config.repo)?;
    let pkg_count = index.packages.len();

    let bind_addrs = parse_bind_addrs(&config.bind)?;

    println!("Serving repo {} on https://{}:{}", config.repo.display(), config.bind, config.port);

    let log_file = if let Some(path) = &config.log {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| std::io::Error::new(e.kind(), format!("Cannot open log file {}: {e}", path.display())))?;
        println!("Log file: {}", path.display());
        std::sync::Mutex::new(Some(BufWriter::new(file)))
    } else {
        std::sync::Mutex::new(None)
    };

    let admin_count = config.users.iter().filter(|u| u.role == UserRole::Admin).count();
    let reader_count = config.users.len() - admin_count;

    let state = Arc::new(AppState {
        index: std::sync::RwLock::new(index),
        users: config.users,
        repo_path: config.repo,
        auth_failures: std::sync::Mutex::new(HashMap::new()),
        active_connections: std::sync::Mutex::new(HashMap::new()),
        log_file,
    });
    let app = build_router(state);

    let (cert_path, key_path) = crate::tls::ensure_certs()?;
    let fingerprint = crate::tls::current_fingerprint()?;
    let tls_config = RustlsConfig::from_pem_file(&cert_path, &key_path).await.map_err(std::io::Error::other)?;

    println!("{pkg_count} packages available");
    println!("Fingerprint: {fingerprint}");
    println!("Users: {admin_count} admin, {reader_count} reader");

    // Spawn one listener per bind address; fail fast if any listener errors out.
    let make_service = app.into_make_service_with_connect_info::<SocketAddr>();
    let mut tasks = tokio::task::JoinSet::new();
    for bind_addr in bind_addrs {
        let addr = SocketAddr::from((bind_addr, config.port));
        let tls_cfg = tls_config.clone();
        let svc = make_service.clone();
        tasks.spawn(async move {
            axum_server::bind_rustls(addr, tls_cfg).serve(svc).await.map_err(std::io::Error::other)
        });
    }
    while let Some(res) = tasks.join_next().await {
        res.map_err(std::io::Error::other)??;
    }
    Ok(())
}

async fn get_index(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let value = {
        let Ok(index) = state.index.read() else {
            state.log_entry(addr.ip(), "GET", "/index", 500, Some("index lock failed"));
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        };
        serde_json::to_value(index.index_summary()).unwrap_or_default()
    };
    let size = serde_json::to_string(&value).map_or(0, |s| s.len());
    state.log_entry(addr.ip(), "GET", "/index", 200, Some(&format!("{size} bytes")));
    Ok(Json(value))
}

async fn get_versions(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let path = format!("/packages/{name}");
    if !is_safe_segment(&name) {
        state.log_entry(addr.ip(), "GET", &path, 400, Some("unsafe segment"));
        return Err(StatusCode::BAD_REQUEST);
    }
    let value = {
        let Ok(index) = state.index.read() else {
            state.log_entry(addr.ip(), "GET", &path, 500, Some("index lock failed"));
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        };
        let Some(pkg) = index.packages.get(&name) else {
            state.log_entry(addr.ip(), "GET", &path, 404, None);
            return Err(StatusCode::NOT_FOUND);
        };
        serde_json::json!({
            "name": name,
            "latest": pkg.latest,
            "versions": pkg.versions,
        })
    };
    state.log_entry(addr.ip(), "GET", &path, 200, None);
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
    resp.headers_mut()
        .insert(header::STRICT_TRANSPORT_SECURITY, "max-age=63072000; includeSubDomains".parse().unwrap());
    resp
}

async fn get_file(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path((name, version, filename)): Path<(String, String, String)>,
) -> impl IntoResponse {
    let url_path = format!("/packages/{name}/{version}/{filename}");
    if !is_safe_segment(&name) || !is_safe_segment(&version) || !is_safe_segment(&filename) {
        state.log_entry(addr.ip(), "GET", &url_path, 400, Some("unsafe segment"));
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check index (lock scope limited to avoid holding across await)
    {
        let Ok(index) = state.index.read() else {
            state.log_entry(addr.ip(), "GET", &url_path, 500, Some("index lock failed"));
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        };
        let Some(pkg) = index.packages.get(&name) else {
            state.log_entry(addr.ip(), "GET", &url_path, 404, Some("package not found"));
            return Err(StatusCode::NOT_FOUND);
        };
        if !pkg.versions.contains(&version) {
            state.log_entry(addr.ip(), "GET", &url_path, 404, Some("version not found"));
            return Err(StatusCode::NOT_FOUND);
        }
    }

    let fs_path = state.repo_path.join("packages").join(&name).join(&version).join(&filename);

    let Ok(canonical) = tokio::fs::canonicalize(&fs_path).await else {
        state.log_entry(addr.ip(), "GET", &url_path, 404, Some("file not found"));
        return Err(StatusCode::NOT_FOUND);
    };
    let Ok(repo_base) = tokio::fs::canonicalize(state.repo_path.join("packages").join(&name).join(&version)).await
    else {
        state.log_entry(addr.ip(), "GET", &url_path, 404, Some("version dir not found"));
        return Err(StatusCode::NOT_FOUND);
    };
    if !canonical.starts_with(&repo_base) {
        state.log_entry(addr.ip(), "GET", &url_path, 400, Some("path traversal attempt"));
        return Err(StatusCode::BAD_REQUEST);
    }
    match tokio::fs::read(&canonical).await {
        Ok(bytes) => {
            state.log_entry(addr.ip(), "GET", &url_path, 200, Some(&format!("{} bytes", bytes.len())));
            let content_type =
                if std::path::Path::new(&filename).extension().is_some_and(|ext| ext.eq_ignore_ascii_case("json")) {
                    "application/json"
                } else {
                    "application/octet-stream"
                };
            Ok(([(header::CONTENT_TYPE, content_type), (header::X_CONTENT_TYPE_OPTIONS, "nosniff")], bytes))
        }
        Err(e) => {
            state.log_entry(addr.ip(), "GET", &url_path, 404, Some(&format!("read error: {}", sanitize_io_error(&e))));
            Err(StatusCode::NOT_FOUND)
        }
    }
}

/// Verify that a zip file contains all files listed in the manifest (and no extras).
fn validate_zip_against_manifest(manifest_path: &std::path::Path, zip_path: &std::path::Path) -> Result<(), String> {
    let manifest_data = std::fs::read(manifest_path).map_err(|e| format!("read manifest: {e}"))?;
    let manifest: Manifest = serde_json::from_slice(&manifest_data).map_err(|e| format!("parse manifest: {e}"))?;
    let zip_file = std::fs::File::open(zip_path).map_err(|e| format!("open zip: {e}"))?;
    let archive = zip::ZipArchive::new(zip_file).map_err(|e| format!("parse zip: {e}"))?;

    let zip_names: std::collections::HashSet<String> =
        (0..archive.len()).filter_map(|i| archive.name_for_index(i).map(String::from)).collect();
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

/// Validate an uploaded manifest: parse JSON, check name match, validate paths/deps,
/// and cross-validate against zip if present. Returns `Err((status_code, message))` on failure.
async fn validate_uploaded_manifest(manifest_path: &std::path::Path, expected_name: &str) -> Result<(), (u16, String)> {
    let data =
        tokio::fs::read(manifest_path).await.map_err(|e| (500, format!("read manifest: {}", sanitize_io_error(&e))))?;
    let manifest: Manifest = serde_json::from_slice(&data).map_err(|e| (400, format!("invalid manifest JSON: {e}")))?;
    if manifest.name != expected_name {
        return Err((400, format!("manifest name mismatch: URL={expected_name}, manifest={}", manifest.name)));
    }
    for (file, dest_dir) in &manifest.files {
        if crate::client::validate_manifest_path(file, dest_dir, expected_name).is_err() {
            return Err((400, format!("unsafe path: {file} -> {dest_dir}")));
        }
    }
    for dep in &manifest.dependencies {
        if dep == expected_name {
            return Err((400, format!("package cannot depend on itself: {dep}")));
        }
        if crate::client::validate_pkg_spec("dependency", dep).is_err() {
            return Err((400, format!("invalid dependency name: {dep}")));
        }
    }
    for (dest, target) in &manifest.links {
        if crate::client::validate_manifest_path(dest, target, expected_name).is_err() {
            return Err((400, format!("unsafe link path: {dest} -> {target}")));
        }
    }
    Ok(())
}

/// Remove empty version and package directories after a failed upload.
async fn cleanup_empty_package_dirs(version_dir: &std::path::Path, packages_root: &std::path::Path) {
    if let Ok(mut entries) = tokio::fs::read_dir(version_dir).await
        && entries.next_entry().await.ok().flatten().is_some()
    {
        return; // Not empty
    }
    let _ = tokio::fs::remove_dir(version_dir).await;
    if let Some(parent) = version_dir.parent()
        && parent != packages_root
        && let Ok(mut entries) = tokio::fs::read_dir(parent).await
        && entries.next_entry().await.ok().flatten().is_none()
    {
        let _ = tokio::fs::remove_dir(parent).await;
    }
}

#[allow(clippy::too_many_lines)]
async fn post_upload(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path((name, version, filename)): Path<(String, String, String)>,
    request: axum::extract::Request,
) -> impl IntoResponse {
    use tokio::io::AsyncWriteExt;

    let url_path = format!("/upload/{name}/{version}/{filename}");
    let ip = addr.ip();

    if !is_safe_segment(&name) || !is_safe_segment(&version) || !is_safe_segment(&filename) {
        state.log_entry(ip, "POST", &url_path, 400, Some("unsafe segment in path"));
        return Err(StatusCode::BAD_REQUEST);
    }
    if filename != "manifest.json" && filename != "files.zip" {
        state.log_entry(ip, "POST", &url_path, 400, Some("filename must be manifest.json or files.zip"));
        return Err(StatusCode::BAD_REQUEST);
    }

    // Canonicalize packages root first, then validate the target stays inside it
    let Ok(canonical_packages) = tokio::fs::canonicalize(state.repo_path.join("packages")).await else {
        state.log_entry(ip, "POST", &url_path, 500, Some("canonicalize packages failed"));
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let dir = canonical_packages.join(&name).join(&version);
    if !dir.starts_with(&canonical_packages) {
        state.log_entry(ip, "POST", &url_path, 400, Some("path traversal attempt"));
        return Err(StatusCode::BAD_REQUEST);
    }

    // For zip uploads, require manifest to be uploaded first
    if filename == "files.zip" && !dir.join("manifest.json").is_file() {
        state.log_entry(ip, "POST", &url_path, 400, Some("manifest.json must be uploaded before files.zip"));
        return Err(StatusCode::BAD_REQUEST);
    }

    if let Err(e) = tokio::fs::create_dir_all(&dir).await {
        state.log_entry(ip, "POST", &url_path, 500, Some(&format!("create dir failed: {}", sanitize_io_error(&e))));
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let final_path = dir.join(&filename);
    let tmp_path = dir.join(format!(".{filename}.tmp"));

    // Stream body directly to temp file — avoids buffering large uploads in RAM
    let mut tmp_file = match tokio::fs::File::create(&tmp_path).await {
        Ok(f) => f,
        Err(e) => {
            state.log_entry(ip, "POST", &url_path, 500, Some(&format!("create temp file: {}", sanitize_io_error(&e))));
            cleanup_empty_package_dirs(&dir, &canonical_packages).await;
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    let mut stream = request.into_body().into_data_stream();
    let mut bytes_written: u64 = 0;
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(c) => c,
            Err(e) => {
                state.log_entry(
                    ip,
                    "POST",
                    &url_path,
                    500,
                    Some(&format!("stream error after {bytes_written} bytes: {e}")),
                );
                let _ = tokio::fs::remove_file(&tmp_path).await;
                cleanup_empty_package_dirs(&dir, &canonical_packages).await;
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };
        bytes_written += chunk.len() as u64;
        if bytes_written > crate::MAX_UPLOAD_SIZE as u64 {
            let max = crate::MAX_UPLOAD_SIZE;
            state.log_entry(ip, "POST", &url_path, 413, Some(&format!("upload exceeds {max} byte limit")));
            let _ = tokio::fs::remove_file(&tmp_path).await;
            cleanup_empty_package_dirs(&dir, &canonical_packages).await;
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        if let Err(e) = tmp_file.write_all(&chunk).await {
            state.log_entry(ip, "POST", &url_path, 500, Some(&format!("write error: {}", sanitize_io_error(&e))));
            let _ = tokio::fs::remove_file(&tmp_path).await;
            cleanup_empty_package_dirs(&dir, &canonical_packages).await;
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }
    if let Err(e) = tmp_file.flush().await {
        state.log_entry(ip, "POST", &url_path, 500, Some(&format!("flush error: {}", sanitize_io_error(&e))));
        let _ = tokio::fs::remove_file(&tmp_path).await;
        cleanup_empty_package_dirs(&dir, &canonical_packages).await;
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    drop(tmp_file);

    if filename == "manifest.json"
        && let Err((status, msg)) = validate_uploaded_manifest(&tmp_path, &name).await
    {
        state.log_entry(ip, "POST", &url_path, status, Some(&msg));
        let _ = tokio::fs::remove_file(&tmp_path).await;
        cleanup_empty_package_dirs(&dir, &canonical_packages).await;
        return Err(if status < 500 { StatusCode::BAD_REQUEST } else { StatusCode::INTERNAL_SERVER_ERROR });
    }

    if let Err(e) = tokio::fs::rename(&tmp_path, &final_path).await {
        state.log_entry(ip, "POST", &url_path, 500, Some(&format!("rename failed: {}", sanitize_io_error(&e))));
        let _ = tokio::fs::remove_file(&tmp_path).await;
        cleanup_empty_package_dirs(&dir, &canonical_packages).await;
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // Cross-validate zip against manifest (zip is always uploaded after manifest)
    if filename == "files.zip" {
        let manifest_path = dir.join("manifest.json");
        if let Err(e) = validate_zip_against_manifest(&manifest_path, &final_path) {
            state.log_entry(ip, "POST", &url_path, 400, Some(&format!("zip/manifest mismatch: {e}")));
            // Clean up both zip and manifest to avoid leaving the package in a broken state
            let _ = tokio::fs::remove_file(&final_path).await;
            let _ = tokio::fs::remove_file(&manifest_path).await;
            cleanup_empty_package_dirs(&dir, &canonical_packages).await;
            // Rescan index so the broken version is removed
            if let Ok(new_index) = RepoIndex::scan(&state.repo_path)
                && let Ok(mut index) = state.index.write()
            {
                *index = new_index;
            }
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    state.log_entry(ip, "POST", &url_path, 201, Some(&format!("{bytes_written} bytes")));

    // Rescan index after zip upload (package is complete) or after manifest upload
    // for meta-packages (no zip expected). Rescanning on manifest-only upload for
    // non-meta packages is harmless — the package appears in the index early, but
    // clients will get a 404 on the zip until it arrives.
    if let Ok(new_index) = RepoIndex::scan(&state.repo_path)
        && let Ok(mut index) = state.index.write()
    {
        *index = new_index;
    }

    Ok(StatusCode::CREATED)
}

async fn delete_version(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path((name, version)): Path<(String, String)>,
) -> impl IntoResponse {
    let url_path = format!("/packages/{name}/{version}");
    let ip = addr.ip();

    if !is_safe_segment(&name) || !is_safe_segment(&version) {
        state.log_entry(ip, "DELETE", &url_path, 400, Some("unsafe segment in path"));
        return Err(StatusCode::BAD_REQUEST);
    }

    let dir = state.repo_path.join("packages").join(&name).join(&version);
    let Ok(canonical_dir) = tokio::fs::canonicalize(&dir).await else {
        state.log_entry(ip, "DELETE", &url_path, 404, Some("version not found"));
        return Err(StatusCode::NOT_FOUND);
    };
    let Ok(canonical_packages) = tokio::fs::canonicalize(state.repo_path.join("packages")).await else {
        state.log_entry(ip, "DELETE", &url_path, 500, Some("canonicalize packages failed"));
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };
    if !canonical_dir.starts_with(&canonical_packages) {
        state.log_entry(ip, "DELETE", &url_path, 400, Some("path traversal attempt"));
        return Err(StatusCode::BAD_REQUEST);
    }

    if let Err(e) = tokio::fs::remove_dir_all(&canonical_dir).await {
        state.log_entry(ip, "DELETE", &url_path, 500, Some(&format!("delete failed: {}", sanitize_io_error(&e))));
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // Remove parent package dir if now empty
    let pkg_dir = state.repo_path.join("packages").join(&name);
    if let Ok(mut entries) = tokio::fs::read_dir(&pkg_dir).await
        && entries.next_entry().await.ok().flatten().is_none()
    {
        let _ = tokio::fs::remove_dir(&pkg_dir).await;
    }

    // Rescan index
    if let Ok(new_index) = RepoIndex::scan(&state.repo_path)
        && let Ok(mut index) = state.index.write()
    {
        *index = new_index;
    }

    state.log_entry(ip, "DELETE", &url_path, 200, Some("deleted"));
    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use super::{parse_bind_addrs, sanitize_io_error};
    use crate::server::{UserEntry, UserRole};
    use crate::testutil::helpers::create_zip;
    use crate::testutil::server_helpers::{
        TEST_PASS, TEST_USER, start_tls_server, start_tls_server_with_users, tls_client_no_auth,
    };
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

    fn auth_delete(client: &reqwest::blocking::Client, url: &str) -> reqwest::blocking::Response {
        client.delete(url).basic_auth(TEST_USER, Some(TEST_PASS)).send().unwrap()
    }

    #[test]
    fn test_parse_bind_addrs_single_ipv4() {
        let a = parse_bind_addrs("0.0.0.0").unwrap();
        assert_eq!(a.len(), 1);
        assert!(a[0].is_ipv4());
    }

    #[test]
    fn test_parse_bind_addrs_single_ipv6() {
        let a = parse_bind_addrs("::").unwrap();
        assert_eq!(a.len(), 1);
        assert!(a[0].is_ipv6());
    }

    #[test]
    fn test_parse_bind_addrs_dual_stack_list() {
        let a = parse_bind_addrs("0.0.0.0, ::").unwrap();
        assert_eq!(a.len(), 2);
        assert!(a[0].is_ipv4());
        assert!(a[1].is_ipv6());
    }

    #[test]
    fn test_parse_bind_addrs_rejects_empty() {
        assert!(parse_bind_addrs("").is_err());
        assert!(parse_bind_addrs(",").is_err());
    }

    #[test]
    fn test_parse_bind_addrs_rejects_garbage() {
        assert!(parse_bind_addrs("not-an-ip").is_err());
        assert!(parse_bind_addrs("0.0.0.0,nope").is_err());
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
        assert_eq!(json["testpkg"]["latest"], "1.0");
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

    #[test]
    fn test_delete_version() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let (_rt, port, fp) = start_tls_server(tmp.path());
        let client = tls_client_no_auth(&fp);

        // Verify package exists in index
        let resp = auth_get(&client, &format!("https://localhost:{port}/index"));
        let json: serde_json::Value = resp.json().unwrap();
        assert!(json["testpkg"].is_object());

        // Delete it
        let resp = auth_delete(&client, &format!("https://localhost:{port}/packages/testpkg/1.0"));
        assert_eq!(resp.status(), 200);

        // Verify gone from index
        let resp = auth_get(&client, &format!("https://localhost:{port}/index"));
        let json: serde_json::Value = resp.json().unwrap();
        assert!(!json["testpkg"].is_object());

        // Verify files gone from disk
        assert!(!tmp.path().join("packages/testpkg/1.0").exists());
        // Parent dir should also be cleaned up
        assert!(!tmp.path().join("packages/testpkg").exists());
    }

    #[test]
    fn test_delete_one_of_two_versions() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path()); // creates testpkg/1.0

        // Add a second version
        let pkg_dir = tmp.path().join("packages").join("testpkg").join("2.0");
        fs::create_dir_all(&pkg_dir).unwrap();
        fs::write(
            pkg_dir.join("manifest.json"),
            r#"{"name":"testpkg","description":"A test","files":{"test.exe":"util/"},"dependencies":[]}"#,
        )
        .unwrap();
        create_zip(&pkg_dir, &[("test.exe", b"v2-binary")]);

        let (_rt, port, fp) = start_tls_server(tmp.path());
        let client = tls_client_no_auth(&fp);

        // Delete only 1.0
        let resp = auth_delete(&client, &format!("https://localhost:{port}/packages/testpkg/1.0"));
        assert_eq!(resp.status(), 200);

        // 1.0 gone
        assert!(!tmp.path().join("packages/testpkg/1.0").exists());
        // 2.0 still exists
        assert!(tmp.path().join("packages/testpkg/2.0").exists());
        // Parent dir NOT cleaned up
        assert!(tmp.path().join("packages/testpkg").exists());

        // Index updated: testpkg still present with latest=2.0
        let resp = auth_get(&client, &format!("https://localhost:{port}/index"));
        let json: serde_json::Value = resp.json().unwrap();
        assert_eq!(json["testpkg"]["latest"], "2.0");
    }

    #[test]
    fn test_delete_nonexistent_returns_404() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let (_rt, port, fp) = start_tls_server(tmp.path());
        let client = tls_client_no_auth(&fp);

        let resp = auth_delete(&client, &format!("https://localhost:{port}/packages/testpkg/9.9"));
        assert_eq!(resp.status(), 404);
    }

    #[test]
    fn test_delete_path_traversal_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let (_rt, port, fp) = start_tls_server(tmp.path());
        let client = tls_client_no_auth(&fp);

        let resp = auth_delete(&client, &format!("https://localhost:{port}/packages/..%2F..%2F/1.0"));
        assert_eq!(resp.status(), 400);
    }

    #[test]
    fn test_delete_without_auth() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let (_rt, port, fp) = start_tls_server(tmp.path());
        let client = tls_client_no_auth(&fp);

        let resp = client.delete(format!("https://localhost:{port}/packages/testpkg/1.0")).send().unwrap();
        assert_eq!(resp.status(), 401);
        // Verify package still exists
        assert!(tmp.path().join("packages/testpkg/1.0").exists());
    }

    #[test]
    fn test_delete_unsafe_segment() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let (_rt, port, fp) = start_tls_server(tmp.path());
        let client = tls_client_no_auth(&fp);

        // Hidden segment (starts with dot)
        let resp = auth_delete(&client, &format!("https://localhost:{port}/packages/.secret/1.0"));
        assert_eq!(resp.status(), 400);

        // Hidden version
        let resp = auth_delete(&client, &format!("https://localhost:{port}/packages/testpkg/.hidden"));
        assert_eq!(resp.status(), 400);

        // Windows reserved name
        let resp = auth_delete(&client, &format!("https://localhost:{port}/packages/CON/1.0"));
        assert_eq!(resp.status(), 400);
    }

    #[test]
    fn test_reader_can_get_but_not_post() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let users = vec![
            UserEntry { username: "admin".to_string(), password: "adminpass".to_string(), role: UserRole::Admin },
            UserEntry { username: "reader".to_string(), password: "readpass".to_string(), role: UserRole::Reader },
        ];
        let (_rt, port, fp) = start_tls_server_with_users(tmp.path(), users);
        let client = tls_client_no_auth(&fp);

        // Reader can GET
        let resp = client
            .get(format!("https://localhost:{port}/index"))
            .basic_auth("reader", Some("readpass"))
            .send()
            .unwrap();
        assert_eq!(resp.status(), 200);

        // Reader cannot POST (upload)
        let resp = client
            .post(format!("https://localhost:{port}/upload/pkg/1.0/manifest.json"))
            .basic_auth("reader", Some("readpass"))
            .body("{}")
            .send()
            .unwrap();
        assert_eq!(resp.status(), 403);

        // Reader cannot DELETE
        let resp = client
            .delete(format!("https://localhost:{port}/packages/testpkg/1.0"))
            .basic_auth("reader", Some("readpass"))
            .send()
            .unwrap();
        assert_eq!(resp.status(), 403);
    }

    #[test]
    fn test_admin_can_post_and_delete() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_repo(tmp.path());
        let users = vec![
            UserEntry { username: "admin".to_string(), password: "adminpass".to_string(), role: UserRole::Admin },
            UserEntry { username: "reader".to_string(), password: "readpass".to_string(), role: UserRole::Reader },
        ];
        let (_rt, port, fp) = start_tls_server_with_users(tmp.path(), users);
        let client = tls_client_no_auth(&fp);

        // Admin can DELETE
        let resp = client
            .delete(format!("https://localhost:{port}/packages/testpkg/1.0"))
            .basic_auth("admin", Some("adminpass"))
            .send()
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[test]
    fn sanitize_io_error_strips_os_error_paths() {
        // OS errors include paths — sanitize should return kind + error code only
        let err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let sanitized = sanitize_io_error(&err);
        assert!(!sanitized.contains("C:\\"), "should not contain paths: {sanitized}");
        assert!(sanitized.contains("not found"), "should contain error kind: {sanitized}");
    }

    #[test]
    fn sanitize_io_error_with_raw_os_error() {
        let err = std::io::Error::from_raw_os_error(2); // ENOENT / ERROR_FILE_NOT_FOUND
        let sanitized = sanitize_io_error(&err);
        assert!(sanitized.contains("os error 2"), "should contain os error code: {sanitized}");
        // Must not contain any filesystem path from the error message
        assert!(!sanitized.contains('\\'), "should not contain backslash paths: {sanitized}");
        assert!(!sanitized.contains('/'), "should not contain forward slash paths: {sanitized}");
    }

    #[test]
    fn test_failed_zip_validation_cleans_up_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("packages")).unwrap();
        let (_rt, port, fp) = start_tls_server(tmp.path());
        let client = tls_client_no_auth(&fp);

        // Upload a manifest that expects "tool.exe"
        let manifest = r#"{"name":"cleanpkg","description":"","files":{"tool.exe":"bin/"},"dependencies":[]}"#;
        let resp = client
            .post(format!("https://localhost:{port}/upload/cleanpkg/1.0/manifest.json"))
            .basic_auth(TEST_USER, Some(TEST_PASS))
            .body(manifest.to_string())
            .send()
            .unwrap();
        assert_eq!(resp.status(), 201);

        // Upload a zip with a DIFFERENT file — validation should fail
        let mut zip_buf = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut zip_buf);
            zip.start_file("wrong.exe", zip::write::SimpleFileOptions::default()).unwrap();
            std::io::Write::write_all(&mut zip, b"wrong").unwrap();
            zip.finish().unwrap();
        }
        let resp = client
            .post(format!("https://localhost:{port}/upload/cleanpkg/1.0/files.zip"))
            .basic_auth(TEST_USER, Some(TEST_PASS))
            .body(zip_buf.into_inner())
            .send()
            .unwrap();
        assert_eq!(resp.status(), 400);

        // Both manifest and zip should be cleaned up
        assert!(
            !tmp.path().join("packages/cleanpkg/1.0/manifest.json").exists(),
            "manifest should be removed after failed zip validation"
        );
        assert!(
            !tmp.path().join("packages/cleanpkg/1.0/files.zip").exists(),
            "zip should be removed after failed zip validation"
        );

        // Package should not appear in the index
        let resp = auth_get(&client, &format!("https://localhost:{port}/index"));
        let json: serde_json::Value = resp.json().unwrap();
        assert!(!json["cleanpkg"].is_object(), "package should not appear in index after failed upload");
    }

    #[test]
    fn test_upload_rejects_self_dependency() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("packages")).unwrap();
        let (_rt, port, fp) = start_tls_server(tmp.path());
        let client = tls_client_no_auth(&fp);

        // Manifest where "selfpkg" depends on itself
        let manifest = r#"{"name":"selfpkg","description":"","files":{"tool.exe":"bin/"},"dependencies":["selfpkg"]}"#;
        let resp = client
            .post(format!("https://localhost:{port}/upload/selfpkg/1.0/manifest.json"))
            .basic_auth(TEST_USER, Some(TEST_PASS))
            .body(manifest.to_string())
            .send()
            .unwrap();
        assert_eq!(resp.status(), 400, "server should reject self-dependency");
    }

    #[test]
    fn test_upload_rejects_unsafe_link_paths() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("packages")).unwrap();
        let (_rt, port, fp) = start_tls_server(tmp.path());
        let client = tls_client_no_auth(&fp);

        // Manifest with a link that uses path traversal
        let manifest = r#"{"name":"linkpkg","description":"","files":{},"dependencies":[],"links":{"bin/tool.exe":"../../../evil.exe"}}"#;
        let resp = client
            .post(format!("https://localhost:{port}/upload/linkpkg/1.0/manifest.json"))
            .basic_auth(TEST_USER, Some(TEST_PASS))
            .body(manifest.to_string())
            .send()
            .unwrap();
        assert_eq!(resp.status(), 400, "server should reject unsafe link path");
    }
}
