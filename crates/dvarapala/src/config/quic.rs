//! The `[quic]` section (RFC 0006).

use std::net::SocketAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::{Tls, duration};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuicRetry {
    UnderLoad,
    Always,
    Never,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Quic {
    /// Unset: no UDP socket, no HTTP/3.
    pub listen: Option<SocketAddr>,
    pub advertise: bool,
    pub retry: QuicRetry,
    pub retry_threshold: usize,
    pub max_connections: usize,
    pub max_streams: u32,
    #[serde(
        deserialize_with = "duration",
        serialize_with = "crate::config::view::ser_duration"
    )]
    pub idle_timeout: Duration,
}

impl Default for Quic {
    fn default() -> Self {
        Self {
            listen: None,
            advertise: true,
            retry: QuicRetry::UnderLoad,
            retry_threshold: 256,
            max_connections: 10_000,
            max_streams: 100,
            idle_timeout: Duration::from_secs(30),
        }
    }
}

/// What the binary starts for `[quic]`.
#[derive(Debug, Clone, PartialEq)]
pub struct QuicPlan {
    pub quic: Quic,
    pub listen: SocketAddr,
    /// `tls.handshake_timeout`
    pub handshake_timeout: Duration,
    /// The port for `Alt-Svc` on TCP responses, `None` with `advertise = false`.
    pub alt_svc: Option<u16>,
}

impl Quic {
    /// `None` when `quic.listen` is unset; an error without `[tls]`, without
    /// the `http3` feature, or on a bad value.
    pub fn plan(&self, tls: &Tls) -> Result<Option<QuicPlan>, String> {
        let Some(listen) = self.listen else {
            return Ok(None);
        };
        if tls.paths()?.is_none() {
            return Err("quic.listen needs tls.cert and tls.key: QUIC is always TLS".into());
        }
        if !cfg!(feature = "http3") {
            return Err("quic.listen needs a build with the http3 feature".into());
        }
        for (zero, key) in [
            (self.max_connections == 0, "quic.max_connections"),
            (self.max_streams == 0, "quic.max_streams"),
            (self.idle_timeout.is_zero(), "quic.idle_timeout"),
        ] {
            if zero {
                return Err(format!("{key} must be above 0"));
            }
        }
        Ok(Some(QuicPlan {
            quic: self.clone(),
            listen,
            handshake_timeout: tls.handshake_timeout,
            alt_svc: self.advertise.then_some(listen.port()),
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn tls() -> Tls {
        Tls {
            cert: Some(PathBuf::from("c.pem")),
            key: Some(PathBuf::from("k.pem")),
            ..Tls::default()
        }
    }

    fn on() -> Quic {
        Quic {
            listen: Some("192.0.2.1:8443".parse().unwrap()),
            ..Quic::default()
        }
    }

    // case 5
    #[test]
    fn unset_listen_binds_nothing() {
        assert_eq!(Quic::default().plan(&tls()), Ok(None));
    }

    // case 14
    #[test]
    fn needs_tls() {
        assert!(on().plan(&Tls::default()).unwrap_err().contains("tls.cert"));
    }

    // cases 3 and 4
    #[cfg(feature = "http3")]
    #[test]
    fn advertise_sets_alt_svc() {
        let p = on().plan(&tls()).unwrap().unwrap();
        assert_eq!(p.alt_svc, Some(8443));
        assert_eq!(p.handshake_timeout, tls().handshake_timeout);
        let off = Quic {
            advertise: false,
            ..on()
        };
        assert_eq!(off.plan(&tls()).unwrap().unwrap().alt_svc, None);
    }

    #[cfg(feature = "http3")]
    #[test]
    fn bad_values_name_the_key() {
        for (q, key) in [
            (
                Quic {
                    max_connections: 0,
                    ..on()
                },
                "quic.max_connections",
            ),
            (
                Quic {
                    max_streams: 0,
                    ..on()
                },
                "quic.max_streams",
            ),
            (
                Quic {
                    idle_timeout: Duration::ZERO,
                    ..on()
                },
                "quic.idle_timeout",
            ),
        ] {
            assert!(q.plan(&tls()).unwrap_err().contains(key), "{key}");
        }
    }

    // case 15
    #[cfg(not(feature = "http3"))]
    #[test]
    fn needs_the_feature() {
        assert!(on().plan(&tls()).unwrap_err().contains("http3 feature"));
    }
}
