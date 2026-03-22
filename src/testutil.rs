//! Shared test utilities for TLS server setup.

#[cfg(test)]
pub mod helpers {
    use crate::repo::RepoIndex;
    use crate::server::{self, AppState};
    use std::fs;
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU16, Ordering};

    static NEXT_PORT: AtomicU16 = AtomicU16::new(19000);

    pub const TEST_USER: &str = "test";
    pub const TEST_PASS: &str = "test";

    /// Start a TLS test server with default test credentials.
    pub fn start_tls_server(repo_path: &Path) -> (tokio::runtime::Runtime, u16, String) {
        start_tls_server_with_auth(repo_path, (TEST_USER.to_string(), TEST_PASS.to_string()))
    }

    /// Start a TLS test server with specific auth credentials.
    pub fn start_tls_server_with_auth(
        repo_path: &Path,
        auth: (String, String),
    ) -> (tokio::runtime::Runtime, u16, String) {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let index = RepoIndex::scan(repo_path).unwrap();
        let state =
            Arc::new(AppState {
                index: std::sync::RwLock::new(index),
                auth,
                repo_path: repo_path.to_path_buf(),
                auth_failures: std::sync::Mutex::new(std::collections::HashMap::new()),
            });
        let app = server::build_router(state);

        let key_pair = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, rcgen::DnValue::Utf8String("test".to_string()));
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_der = cert.der();
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();
        let fingerprint = crate::tls::cert_fingerprint(cert_der.as_ref());

        let rt = tokio::runtime::Runtime::new().unwrap();
        let port = NEXT_PORT.fetch_add(1, Ordering::Relaxed);
        rt.block_on(async {
            let tls_config =
                axum_server::tls_rustls::RustlsConfig::from_pem(cert_pem.into_bytes(), key_pem.into_bytes())
                    .await
                    .unwrap();

            let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
            tokio::spawn(async move {
                axum_server::bind_rustls(addr, tls_config)
                    .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                    .await
                    .unwrap();
            });

            // Wait for the server to be ready
            for _ in 0..50 {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                if tokio::net::TcpStream::connect(addr).await.is_ok() {
                    break;
                }
            }
        });

        (rt, port, fingerprint)
    }

    /// Build a reqwest client that trusts a specific fingerprint (no auth).
    pub fn tls_client_no_auth(fingerprint: &str) -> reqwest::blocking::Client {
        let tls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(crate::tls::TofuVerifier::new(
                fingerprint.to_string(),
                std::path::PathBuf::new(),
            )))
            .with_no_client_auth();

        reqwest::blocking::Client::builder().use_preconfigured_tls(tls_config).build().unwrap()
    }

    /// Create a files.zip in `dir` containing the given files.
    pub fn create_zip(dir: &Path, files: &[(&str, &[u8])]) {
        let zip_path = dir.join("files.zip");
        let file = fs::File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        for (name, content) in files {
            zip.start_file(*name, options).unwrap();
            std::io::Write::write_all(&mut zip, content).unwrap();
        }
        zip.finish().unwrap();
    }
}
