//! The `[tls]` and `[upstream_tls]` sections (RFC 0003).

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use super::duration;

/// RFC 0003 listener TLS. No `cert` means a cleartext listener.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Tls {
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    #[serde(deserialize_with = "duration")]
    pub handshake_timeout: Duration,
    pub max_handshakes: usize,
}

/// RFC 0003 verification of `https://` upstreams.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct UpstreamTls {
    pub ca_file: Option<PathBuf>,
    pub server_name: Option<String>,
}

impl Tls {
    /// `(cert, key)` when TLS is on; an error when only one is set.
    pub fn paths(&self) -> Result<Option<(&Path, &Path)>, String> {
        match (&self.cert, &self.key) {
            (Some(c), Some(k)) => Ok(Some((c, k))),
            (None, None) => Ok(None),
            (Some(_), None) => Err("tls.key is required with tls.cert".into()),
            (None, Some(_)) => Err("tls.cert is required with tls.key".into()),
        }
    }
}

impl Default for Tls {
    fn default() -> Self {
        Self {
            cert: None,
            key: None,
            handshake_timeout: Duration::from_secs(10),
            max_handshakes: 1024,
        }
    }
}
