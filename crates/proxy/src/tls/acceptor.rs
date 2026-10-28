use std::path::PathBuf;
use std::time::Duration;

use super::TlsError;

/// Listener TLS settings.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
    /// Connections still handshaking after this are closed.
    pub handshake_timeout: Duration,
    /// Handshakes in progress at once; over it, close before any crypto.
    pub max_handshakes: usize,
}

/// A loaded TLS listener config. Clones share the certificate, so
/// [`Tls::reload`] on one is seen by all.
#[derive(Debug, Clone)]
pub struct Tls(());

impl Tls {
    pub fn new(_config: TlsConfig) -> Result<Self, TlsError> {
        todo!("rfc 0003")
    }

    /// Reads the certificate and key again. On error the old pair stays.
    pub fn reload(&self) -> Result<(), TlsError> {
        todo!("rfc 0003")
    }
}
