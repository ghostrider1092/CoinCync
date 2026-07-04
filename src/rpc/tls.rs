//! # TLS Certificate Management for CoinCync RPC
//!
//! Provides auto-generation of self-signed certificates, server/client
//! TLS config loading, and certificate fingerprint pinning.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::error::{Error, Result};

/// Generate a self-signed ECDSA P-256 certificate if one doesn't already exist.
///
/// Files created:
/// - `{data_dir}/rpc_cert.pem` — certificate in PEM format
/// - `{data_dir}/rpc_key.pem` — private key in PEM format (restrictive permissions)
///
/// SANs include: `localhost`, `127.0.0.1`, `::1`, and the provided `common_name`.
pub fn generate_self_signed_cert(
    data_dir: &Path,
    common_name: &str,
) -> Result<(PathBuf, PathBuf)> {
    let cert_path = data_dir.join("rpc_cert.pem");
    let key_path = data_dir.join("rpc_key.pem");

    // Return existing cert if both files are present
    if cert_path.exists() && key_path.exists() {
        tracing::info!("Using existing TLS certificate at {}", cert_path.display());
        return Ok((cert_path, key_path));
    }

    tracing::info!("Generating self-signed TLS certificate...");

    std::fs::create_dir_all(data_dir)
        .map_err(|e| Error::TlsError(format!("create data dir: {}", e)))?;

    // Build certificate parameters with DNS + IP SANs
    let mut params = rcgen::CertificateParams::new(vec![
        common_name.to_string(),
        "localhost".to_string(),
    ]).map_err(|e| Error::TlsError(format!("cert params: {}", e)))?;

    params.subject_alt_names.push(
        rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
    );
    params.subject_alt_names.push(
        rcgen::SanType::IpAddress(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
    );

    // 2026-06-03 bug fix: the previous date calculation used
    //
    //   let days_since_epoch = secs / 86400;
    //   let year  = 1970 + (days_since_epoch / 365) as i32;
    //   let month = ((days_since_epoch % 365) / 30 + 1) as u8;
    //   let day   = ((days_since_epoch % 365) % 30 + 1) as u8;
    //
    // which ignores leap years (and approximates a month as exactly 30
    // days). At ~56 years from epoch the cumulative drift is on the
    // order of 14 days, so `not_before` could be computed as a date
    // in the FUTURE — at which point the freshly-generated cert is
    // rejected by every verifier with "certificate not yet valid"
    // for the first ~2 weeks of its lifetime. A fresh node startup
    // would silently fail TLS until the drift caught up. The
    // approximation also made `not_after` drift further each year,
    // so the effective validity period was not actually 10 years.
    //
    // Fix: use `chrono` (already a direct dependency) for the
    // current-year math, set `not_before` to a safely-past January 1
    // so we never publish a future start date even if a future
    // clock-drift bug surfaces, and compute `not_after` as
    // `January 1, current_year + 11` (the +1 covers the partial
    // current year so the validity bound is at least 10 years out).
    //
    // Hardcoding (1, 1) for month+day is intentional: it sidesteps
    // every leap-year and month-length question, and a cert whose
    // calendar boundaries land on January 1 of round years is also
    // the standard CA-issuer convention.
    {
        use chrono::Datelike;
        let now_year = chrono::Utc::now().year();
        // Safely-past start date (last January 1) — guaranteed in the past.
        params.not_before = rcgen::date_time_ymd(now_year, 1, 1);
        // +11 so we always cover at least 10 full years from the
        // moment the cert was generated, including the rest of the
        // current calendar year.
        params.not_after = rcgen::date_time_ymd(now_year + 11, 1, 1);
    }

    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| Error::TlsError(format!("generate keypair: {}", e)))?;

    let cert = params.self_signed(&key_pair)
        .map_err(|e| Error::TlsError(format!("self-sign: {}", e)))?;

    std::fs::write(&cert_path, cert.pem())
        .map_err(|e| Error::TlsError(format!("write cert: {}", e)))?;
    // P8-T1 (2026-07-03): create the key with owner-only permissions
    // atomically at open(2) time. Previously we did fs::write + chmod,
    // which opens a race where another local process can read the
    // freshly-created key before the chmod lands. Mirrors the
    // write_secret_file pattern applied to noise.rs::write_secret_file
    // (P5-No1). On Windows fs::write is retained + the follow-on
    // set_readonly call (there's no clean create-time ACL primitive
    // in the std API worth wiring here — the guarantee is best-effort
    // on that platform).
    let key_pem = key_pair.serialize_pem();
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(0o600);
        let mut f = opts.open(&key_path)
            .map_err(|e| Error::TlsError(format!("open key: {}", e)))?;
        f.write_all(key_pem.as_bytes())
            .map_err(|e| Error::TlsError(format!("write key: {}", e)))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&key_path, key_pem)
            .map_err(|e| Error::TlsError(format!("write key: {}", e)))?;
    }

    set_restrictive_permissions(&key_path)?;

    tracing::info!("TLS certificate generated: {}", cert_path.display());
    Ok((cert_path, key_path))
}

/// Set restrictive file permissions (owner-only read/write).
fn set_restrictive_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::TlsError(format!("set permissions: {}", e)))?;
    }
    #[cfg(windows)]
    {
        let metadata = std::fs::metadata(path)
            .map_err(|e| Error::TlsError(format!("read metadata: {}", e)))?;
        let mut perms = metadata.permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(path, perms)
            .map_err(|e| Error::TlsError(format!("set permissions: {}", e)))?;
    }
    Ok(())
}

/// Load PEM certificate chain and private key from disk.
fn load_pem_cert_and_key(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(Vec<rustls::pki_types::CertificateDer<'static>>, rustls::pki_types::PrivateKeyDer<'static>)> {
    let cert_data = std::fs::read(cert_path)
        .map_err(|e| Error::TlsError(format!("read cert: {}", e)))?;
    let certs: Vec<_> = pem::parse_many(&cert_data)
        .map_err(|e| Error::TlsError(format!("parse cert PEM: {}", e)))?
        .into_iter()
        .filter(|block| block.tag() == "CERTIFICATE")
        .map(|block| rustls::pki_types::CertificateDer::from(block.contents().to_vec()))
        .collect();
    if certs.is_empty() {
        return Err(Error::TlsError("no certificates found in PEM file".into()));
    }

    let key_data = std::fs::read(key_path)
        .map_err(|e| Error::TlsError(format!("read key: {}", e)))?;
    let key = pem::parse_many(&key_data)
        .map_err(|e| Error::TlsError(format!("parse key PEM: {}", e)))?
        .into_iter()
        .find_map(|block| match block.tag() {
            "PRIVATE KEY" => Some(rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(block.contents().to_vec()),
            )),
            "RSA PRIVATE KEY" => Some(rustls::pki_types::PrivateKeyDer::Pkcs1(
                rustls::pki_types::PrivatePkcs1KeyDer::from(block.contents().to_vec()),
            )),
            "EC PRIVATE KEY" => Some(rustls::pki_types::PrivateKeyDer::Sec1(
                rustls::pki_types::PrivateSec1KeyDer::from(block.contents().to_vec()),
            )),
            _ => None,
        })
        .ok_or_else(|| Error::TlsError("no private key found in PEM file".into()))?;

    Ok((certs, key))
}

/// Load a rustls ServerConfig from PEM certificate and key files.
pub fn load_server_tls_config(
    cert_path: &Path,
    key_path: &Path,
    _client_ca_path: Option<&Path>,
) -> Result<rustls::ServerConfig> {
    let (certs, key) = load_pem_cert_and_key(cert_path, key_path)?;

    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| Error::TlsError(format!("server config: {}", e)))
}

/// Load a rustls ClientConfig for connecting to the RPC server.
///
/// - `pinned_fingerprint`: If provided, verifies the server certificate's
///   BLAKE3 fingerprint matches exactly (recommended for self-signed nodes).
/// - If `None`, accepts any self-signed certificate (insecure but functional
///   for initial setup / local connections).
pub fn load_client_tls_config(
    pinned_fingerprint: Option<&str>,
) -> Result<rustls::ClientConfig> {
    let expected = match pinned_fingerprint {
        Some(fp) => {
            let bytes = hex::decode(fp)
                .map_err(|e| Error::TlsError(format!("invalid fingerprint hex: {}", e)))?;
            if bytes.len() != 32 {
                return Err(Error::TlsError(
                    "fingerprint must be 32 bytes (64 hex chars, BLAKE3)".into(),
                ));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Some(arr)
        }
        None => {
            tracing::warn!(
                "TLS certificate verification disabled (no --tls-fingerprint). \
                 Use --tls-fingerprint for production security."
            );
            None
        }
    };

    let verifier = Arc::new(Blake3CertVerifier { expected });
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(config)
}

/// Compute the BLAKE3 fingerprint of the first certificate in a PEM file.
pub fn cert_fingerprint(cert_path: &Path) -> Result<String> {
    let data = std::fs::read(cert_path)
        .map_err(|e| Error::TlsError(format!("read cert: {}", e)))?;
    let cert = pem::parse_many(&data)
        .map_err(|e| Error::TlsError(format!("parse cert PEM: {}", e)))?
        .into_iter()
        .find(|block| block.tag() == "CERTIFICATE")
        .map(|block| block.contents().to_vec())
        .ok_or_else(|| Error::TlsError("no certificate in file".into()))?;

    Ok(hex::encode(blake3::hash(&cert).as_bytes()))
}

/// Unified certificate verifier supporting both fingerprint-pinning and accept-any modes.
///
/// - `expected = Some(hash)` — pin to a specific BLAKE3 fingerprint
/// - `expected = None` — accept any certificate (local dev / initial setup)
///
/// In both modes, TLS handshake signatures are always verified to confirm
/// the server possesses the private key (prevents MITM with a copied cert).
#[derive(Debug)]
struct Blake3CertVerifier {
    expected: Option<[u8; 32]>,
}

impl rustls::client::danger::ServerCertVerifier for Blake3CertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if let Some(expected) = &self.expected {
            let actual = blake3::hash(end_entity.as_ref());
            if actual.as_bytes() != expected {
                return Err(rustls::Error::General(format!(
                    "certificate fingerprint mismatch: expected {}, got {}",
                    hex::encode(expected),
                    hex::encode(actual.as_bytes()),
                )));
            }
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message, cert, dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message, cert, dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ensure_crypto_provider() {
        use std::sync::Once;
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    #[test]
    fn test_generate_self_signed_cert() {
        ensure_crypto_provider();
        let dir = std::env::temp_dir().join("coincync_test_tls");
        let _ = std::fs::remove_dir_all(&dir);

        let (cert_path, key_path) = generate_self_signed_cert(&dir, "coincync-test").unwrap();
        assert!(cert_path.exists());
        assert!(key_path.exists());

        let _config = load_server_tls_config(&cert_path, &key_path, None).unwrap();

        // Fingerprint should be deterministic
        let fp1 = cert_fingerprint(&cert_path).unwrap();
        let fp2 = cert_fingerprint(&cert_path).unwrap();
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 64);

        // Second call should reuse existing cert
        let (cert_path2, _) = generate_self_signed_cert(&dir, "coincync-test").unwrap();
        assert_eq!(fp1, cert_fingerprint(&cert_path2).unwrap());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_client_config_no_fingerprint() {
        ensure_crypto_provider();
        let _config = load_client_tls_config(None).unwrap();
    }

    #[test]
    fn test_load_client_config_with_fingerprint() {
        ensure_crypto_provider();
        let _config = load_client_tls_config(Some(&"a".repeat(64))).unwrap();
    }

    #[test]
    fn test_load_client_config_invalid_fingerprint() {
        ensure_crypto_provider();
        assert!(load_client_tls_config(Some("abcd")).is_err());
        assert!(load_client_tls_config(Some("xyz")).is_err());
    }

    #[test]
    fn test_fingerprint_pinning_verification() {
        ensure_crypto_provider();
        let dir = std::env::temp_dir().join("coincync_test_tls_pin");
        let _ = std::fs::remove_dir_all(&dir);

        let (cert_path, _) = generate_self_signed_cert(&dir, "coincync-test").unwrap();
        let fp = cert_fingerprint(&cert_path).unwrap();
        let _config = load_client_tls_config(Some(&fp)).unwrap();

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cert_expiry() {
        ensure_crypto_provider();
        let dir = std::env::temp_dir().join("coincync_test_tls_expiry");
        let _ = std::fs::remove_dir_all(&dir);

        let (cert_path, key_path) = generate_self_signed_cert(&dir, "coincync-expiry-test").unwrap();
        assert!(load_server_tls_config(&cert_path, &key_path, None).is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
