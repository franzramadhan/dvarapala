use std::fmt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

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
pub struct CertPair(());

impl CertPair {
    /// Parses a PEM chain (leaf first) and a PEM key.
    pub fn from_pem(_cert: &[u8], _key: &[u8]) -> Result<Self, TlsError> {
        todo!("rfc 0003")
    }

    /// Reads and parses both files.
    pub fn load(_cert: &Path, _key: &Path) -> Result<Self, TlsError> {
        todo!("rfc 0003")
    }

    /// When the leaf certificate expires, if its validity could be read.
    pub fn not_after(&self) -> Option<SystemTime> {
        todo!("rfc 0003")
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
    #[ignore = "rfc 0003"]
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
    #[ignore = "rfc 0003"]
    fn key_of_another_certificate_is_refused() {
        let (cert, _) = leaf(None);
        let (_, other_key) = leaf(None);
        assert!(CertPair::from_pem(cert.as_bytes(), other_key.as_bytes()).is_err());
    }

    #[test]
    #[ignore = "rfc 0003"]
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
    #[ignore = "rfc 0003"]
    fn missing_file_names_the_path() {
        let e = CertPair::load(
            Path::new("/nonexistent/cert.pem"),
            Path::new("/nonexistent/key.pem"),
        )
        .unwrap_err();
        assert!(e.to_string().contains("/nonexistent/cert.pem"), "{e}");
    }
}
