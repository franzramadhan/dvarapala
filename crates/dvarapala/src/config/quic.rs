//! The `[quic]` section (RFC 0006).

use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::time::Duration;

use dvarapala_engine::{ConnsConfig, Limit};
use serde::{Deserialize, Serialize};

use super::{L4, Tls, duration};

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
    /// RFC 0036: open connections per client; 0 off.
    pub max_per_client: u32,
    /// RFC 0036: new connections per second per client; 0 off.
    pub accept_rate: u32,
    pub accept_burst: u32,
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
            max_per_client: 256,
            accept_rate: 0,
            accept_burst: 64,
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
    /// RFC 0036: the per-client limits, grouped as `[l4]` says.
    pub conns: ConnsConfig,
}

impl Quic {
    /// `None` when `quic.listen` is unset; an error without `[tls]`, without
    /// the `http3` feature, or on a bad value.
    pub fn plan(&self, tls: &Tls, l4: &L4) -> Result<Option<QuicPlan>, String> {
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
        if self.accept_burst == 0 {
            return Err("quic.accept_burst must be at least 1".into());
        }
        let accept = match self.accept_rate {
            0 => None,
            r => Some(
                Limit::new(r, self.accept_burst).map_err(|e| format!("quic.accept_rate: {e}"))?,
            ),
        };
        let conns = ConnsConfig {
            max_per_client: self.max_per_client,
            accept,
            prefix_v4: l4.prefix_v4,
            prefix_v6: l4.prefix_v6,
            max_clients: NonZeroUsize::new(l4.max_clients)
                .ok_or("l4.max_clients must be at least 1")?,
            exempt: Vec::new(),
        };
        Ok(Some(QuicPlan {
            conns,
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
        assert_eq!(Quic::default().plan(&tls(), &L4::default()), Ok(None));
    }

    // case 14
    #[test]
    fn needs_tls() {
        assert!(
            on().plan(&Tls::default(), &L4::default())
                .unwrap_err()
                .contains("tls.cert")
        );
    }

    // cases 3 and 4
    #[cfg(feature = "http3")]
    #[test]
    fn advertise_sets_alt_svc() {
        let p = on().plan(&tls(), &L4::default()).unwrap().unwrap();
        assert_eq!(p.alt_svc, Some(8443));
        assert_eq!(p.handshake_timeout, tls().handshake_timeout);
        let off = Quic {
            advertise: false,
            ..on()
        };
        assert_eq!(
            off.plan(&tls(), &L4::default()).unwrap().unwrap().alt_svc,
            None
        );
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
                    accept_burst: 0,
                    ..on()
                },
                "quic.accept_burst",
            ),
            (
                Quic {
                    idle_timeout: Duration::ZERO,
                    ..on()
                },
                "quic.idle_timeout",
            ),
        ] {
            assert!(
                q.plan(&tls(), &L4::default()).unwrap_err().contains(key),
                "{key}"
            );
        }
    }

    // RFC 0036: grouping and capacity come from `[l4]`
    #[cfg(feature = "http3")]
    #[test]
    fn limits_follow_the_keys_and_l4_grouping() {
        let q = Quic {
            max_per_client: 3,
            accept_rate: 5,
            accept_burst: 7,
            ..on()
        };
        let l4 = L4 {
            prefix_v6: 56,
            max_clients: 9,
            ..L4::default()
        };
        let c = q.plan(&tls(), &l4).unwrap().unwrap().conns;
        assert_eq!(c.max_per_client, 3);
        assert_eq!(c.accept, Some(Limit::new(5, 7).unwrap()));
        assert_eq!((c.prefix_v4, c.prefix_v6), (32, 56));
        assert_eq!(c.max_clients.get(), 9);
        let off = Quic::default().plan(&tls(), &l4);
        assert_eq!(off, Ok(None));
    }

    // case 15
    #[cfg(not(feature = "http3"))]
    #[test]
    fn needs_the_feature() {
        assert!(
            on().plan(&tls(), &L4::default())
                .unwrap_err()
                .contains("http3 feature")
        );
    }
}
