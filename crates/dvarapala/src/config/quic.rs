//! The `[quic]` section (RFC 0006).

use std::net::SocketAddr;
use std::time::Duration;

use serde::Deserialize;

use super::{Tls, duration};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuicRetry {
    UnderLoad,
    Always,
    Never,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Quic {
    /// Unset: no UDP socket, no HTTP/3.
    pub listen: Option<SocketAddr>,
    pub advertise: bool,
    pub retry: QuicRetry,
    pub retry_threshold: usize,
    pub max_connections: usize,
    pub max_streams: u32,
    #[serde(deserialize_with = "duration")]
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
        let _ = tls;
        todo!("rfc 0006")
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
    #[ignore = "rfc 0006"]
    fn unset_listen_binds_nothing() {
        assert_eq!(Quic::default().plan(&tls()), Ok(None));
    }

    // case 14
    #[test]
    #[ignore = "rfc 0006"]
    fn needs_tls() {
        assert!(on().plan(&Tls::default()).unwrap_err().contains("tls.cert"));
    }

    // cases 3 and 4
    #[cfg(feature = "http3")]
    #[test]
    #[ignore = "rfc 0006"]
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
    #[ignore = "rfc 0006"]
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
    #[ignore = "rfc 0006"]
    fn needs_the_feature() {
        assert!(on().plan(&tls()).unwrap_err().contains("http3 feature"));
    }
}
