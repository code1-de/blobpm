use rcgen::{CertificateParams, KeyPair};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use std::{fs, io};

/// Path to the server certificate.
///
/// # Errors
/// Returns an error if the home directory cannot be determined.
pub fn cert_path() -> io::Result<PathBuf> {
    crate::client::blob_dir().map(|p| p.join("cert.pem"))
}

/// Path to the server private key.
///
/// # Errors
/// Returns an error if the home directory cannot be determined.
pub fn key_path() -> io::Result<PathBuf> {
    crate::client::blob_dir().map(|p| p.join("key.pem"))
}

/// Generate a self-signed TLS certificate and key.
///
/// # Errors
/// Returns an error if certificate generation or file writing fails.
pub fn generate_keys() -> io::Result<String> {
    let cert = cert_path()?;
    let key = key_path()?;
    if cert.is_file() || key.is_file() {
        eprint!("TLS certificates already exist. Overwrite? [y/N] ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "Aborted"));
        }
    }

    let key_pair = KeyPair::generate().map_err(|e| io::Error::other(format!("Key generation failed: {e}")))?;

    let mut params = CertificateParams::new(vec!["localhost".to_string()])
        .map_err(|e| io::Error::other(format!("Cert params failed: {e}")))?;
    params.distinguished_name.push(rcgen::DnType::CommonName, rcgen::DnValue::Utf8String("blob server".to_string()));

    let cert = params.self_signed(&key_pair).map_err(|e| io::Error::other(format!("Cert generation failed: {e}")))?;

    let cert_der = cert.der().to_vec();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    let cert_file = cert_path()?;
    let key_file = key_path()?;

    if let Some(parent) = cert_file.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(&cert_file, &cert_pem)?;
    fs::write(&key_file, &key_pem)?;

    let fingerprint = cert_fingerprint(&cert_der);

    println!("Generated cert: {}", cert_file.display());
    println!("Generated key:  {}", key_file.display());

    Ok(fingerprint)
}

/// Ensure certs exist, generate if missing. Returns (`cert_path`, `key_path`).
///
/// # Errors
/// Returns an error if cert generation or path resolution fails.
pub fn ensure_certs() -> io::Result<(PathBuf, PathBuf)> {
    let cert = cert_path()?;
    let key = key_path()?;

    if !cert.is_file() || !key.is_file() {
        println!("No TLS certificates found, generating...");
        generate_keys()?;
    }

    Ok((cert, key))
}

/// Compute SHA256 fingerprint of DER-encoded certificate bytes, displayed as 16-bit groups.
#[must_use]
pub fn cert_fingerprint(der_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(der_bytes);
    let hash = hasher.finalize();
    hash.chunks(2).map(|pair| format!("{:02x}{:02x}", pair[0], pair[1])).collect::<Vec<_>>().join(":")
}

/// Read the fingerprint of the current server cert.
///
/// # Errors
/// Returns an error if the cert file cannot be read.
pub fn current_fingerprint() -> io::Result<String> {
    let cert = cert_path()?;
    let pem_data = fs::read(&cert)?;
    let der = pem::parse(&pem_data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Failed to parse cert PEM: {e}")))?;
    Ok(cert_fingerprint(der.contents()))
}

/// A TOFU (Trust On First Use) certificate verifier, like SSH.
///
/// - No saved fingerprint: prompts user to accept, saves it
/// - Saved fingerprint matches: connection proceeds
/// - Saved fingerprint differs: connection refused
#[derive(Debug)]
pub struct TofuVerifier {
    saved_fingerprint: String,
    config_path: PathBuf,
}

impl TofuVerifier {
    /// Create a new TOFU verifier with the saved fingerprint from config.
    #[must_use]
    pub fn new(saved_fingerprint: String, config_path: PathBuf) -> Self {
        Self { saved_fingerprint, config_path }
    }
}

// TODO: add --accept-fingerprint flag for non-interactive use (scripts, CI), otherwise TLS handshake will hang
impl ServerCertVerifier for TofuVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fingerprint = cert_fingerprint(end_entity.as_ref());

        if self.saved_fingerprint.is_empty() {
            // First connection — prompt user
            eprintln!("New server certificate:");
            eprintln!("Fingerprint: {fingerprint}");
            eprint!("Trust this certificate? [y/N] ");

            let mut input = String::new();
            if std::io::stdin().read_line(&mut input).is_ok() && input.trim().eq_ignore_ascii_case("y") {
                // Save fingerprint to config
                if let Ok(content) = fs::read_to_string(&self.config_path)
                    && let Ok(mut config) = serde_json::from_str::<serde_json::Value>(&content)
                {
                    config["server_fingerprint"] = serde_json::Value::String(fingerprint);
                    let _ = fs::write(&self.config_path, serde_json::to_string_pretty(&config).unwrap_or_default());
                }
                return Ok(ServerCertVerified::assertion());
            }
            return Err(rustls::Error::General("Certificate not trusted by user".to_string()));
        }

        if fingerprint == self.saved_fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            eprintln!("WARNING: Server certificate has changed!");
            eprintln!("  Expected: {}", self.saved_fingerprint);
            eprintln!("  Got:      {fingerprint}");
            eprintln!("This could indicate a man-in-the-middle attack.");
            eprintln!("If this is expected, delete server_fingerprint from config and reconnect.");
            Err(rustls::Error::General("Certificate fingerprint mismatch".to_string()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

/// Build a reqwest blocking client with TOFU cert verification and optional basic auth.
///
/// # Errors
/// Returns an error if the TLS config or client build fails.
pub fn build_client(config: &super::client::Config) -> io::Result<reqwest::blocking::Client> {
    let config_path = super::client::config_path().unwrap_or_default();

    let tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TofuVerifier::new(config.server_fingerprint.clone(), config_path)))
        .with_no_client_auth();

    reqwest::blocking::Client::builder()
        .use_preconfigured_tls(tls_config)
        .build()
        .map_err(|e| io::Error::other(format!("Failed to build HTTP client: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_consistent() {
        let data = b"test certificate data";
        let fp1 = cert_fingerprint(data);
        let fp2 = cert_fingerprint(data);
        assert_eq!(fp1, fp2);
        assert!(fp1.contains(':'));
        // 16 groups of 4 hex chars with 15 colons = 16*4 + 15 = 79
        assert_eq!(fp1.len(), 79);
    }

    #[test]
    fn fingerprint_differs_for_different_data() {
        let fp1 = cert_fingerprint(b"cert A");
        let fp2 = cert_fingerprint(b"cert B");
        assert_ne!(fp1, fp2);
    }
}
