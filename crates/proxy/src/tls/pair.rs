use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use rustls::crypto::ring;
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use super::expiry;

/// Why a certificate, key or CA file was refused.
#[derive(Debug)]
pub enum TlsError {
    /// The file could not be read.
    Read(PathBuf, std::io::Error),
    /// The PEM held no usable certificate or key, or they do not match.
    Invalid(String),
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(p, e) => write!(f, "{}: {e}", p.display()),
            Self::Invalid(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for TlsError {}

/// A certificate chain and its private key, checked to match.
#[derive(Debug, Clone)]
pub struct CertPair {
    pub(crate) key: Arc<CertifiedKey>,
    not_after: Option<SystemTime>,
}

impl CertPair {
    /// Parses a PEM chain (leaf first) and a PEM key.
    pub fn from_pem(cert: &[u8], key: &[u8]) -> Result<Self, TlsError> {
        let invalid = |what: &str, e: &dyn fmt::Display| TlsError::Invalid(format!("{what}: {e}"));
        let chain = CertificateDer::pem_slice_iter(cert)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| invalid("certificate", &e))?;
        let Some(leaf) = chain.first() else {
            return Err(TlsError::Invalid("no certificate in the PEM".into()));
        };
        let not_after = expiry::not_after(leaf);
        let key = PrivateKeyDer::from_pem_slice(key).map_err(|e| invalid("private key", &e))?;
        let key = CertifiedKey::from_der(chain, key, &ring::default_provider())
            .map_err(|e| invalid("certificate and key", &e))?;
        Ok(Self {
            key: Arc::new(key),
            not_after,
        })
    }

    /// Reads and parses both files.
    pub fn load(cert: &Path, key: &Path) -> Result<Self, TlsError> {
        let read = |p: &Path| std::fs::read(p).map_err(|e| TlsError::Read(p.to_owned(), e));
        Self::from_pem(&read(cert)?, &read(key)?)
    }

    /// When the leaf certificate expires, if its validity could be read.
    pub fn not_after(&self) -> Option<SystemTime> {
        self.not_after
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use rcgen::{CertificateParams, KeyPair, date_time_ymd};

    use super::*;

    fn leaf(not_after: Option<(i32, u8, u8)>) -> (String, String) {
        let mut p = CertificateParams::new(vec!["dvarapala.test".to_owned()]).unwrap();
        if let Some((y, m, d)) = not_after {
            p.not_after = date_time_ymd(y, m, d);
        }
        let key = KeyPair::generate().unwrap();
        (p.self_signed(&key).unwrap().pem(), key.serialize_pem())
    }

    #[test]
    fn matching_pair_loads_and_reports_expiry() {
        let (cert, key) = leaf(Some((2031, 1, 2)));
        let pair = CertPair::from_pem(cert.as_bytes(), key.as_bytes()).unwrap();
        // 2031-01-02T00:00:00Z
        assert_eq!(
            pair.not_after(),
            Some(UNIX_EPOCH + Duration::from_secs(1_925_078_400))
        );
    }

    #[test]
    fn key_of_another_certificate_is_refused() {
        let (cert, _) = leaf(None);
        let (_, other_key) = leaf(None);
        let e = CertPair::from_pem(cert.as_bytes(), other_key.as_bytes()).unwrap_err();
        assert!(e.to_string().starts_with("certificate and key: "), "{e}");
    }

    #[test]
    fn empty_chain_says_so() {
        let (_, key) = leaf(None);
        let e = CertPair::from_pem(b"", key.as_bytes()).unwrap_err();
        assert_eq!(e.to_string(), "no certificate in the PEM");
    }

    #[test]
    fn garbage_and_empty_input_are_refused() {
        let (cert, key) = leaf(None);
        for (c, k) in [
            ("", key.as_str()),
            (cert.as_str(), ""),
            ("not pem", "not pem"),
            (key.as_str(), cert.as_str()),
        ] {
            assert!(CertPair::from_pem(c.as_bytes(), k.as_bytes()).is_err());
        }
    }

    #[test]
    fn missing_file_names_the_path() {
        let e = CertPair::load(
            Path::new("/nonexistent/cert.pem"),
            Path::new("/nonexistent/key.pem"),
        )
        .unwrap_err();
        assert!(e.to_string().contains("/nonexistent/cert.pem"), "{e}");
    }
}
