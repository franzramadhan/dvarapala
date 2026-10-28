//! Protocol sections: the upstream protocol and HTTP/2 limits (RFC 0004),
//! and upgrades (RFC 0005).

use std::time::Duration;

use dvarapala_proxy::{Http2Limits, UpgradeConfig};
use serde::Deserialize;

use super::duration;

/// RFC 0004 protocol to the upstream.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamProtocol {
    #[default]
    Http1,
    Http2,
    Auto,
}

/// RFC 0004 HTTP/2 listener limits. Defaults come from [`Http2Limits`].
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Http2 {
    pub max_concurrent_streams: u32,
    pub max_pending_reset_streams: usize,
    pub max_local_error_resets: usize,
    pub max_header_list_size: u32,
    /// `"0s"` turns keepalive off.
    #[serde(deserialize_with = "duration")]
    pub keepalive_interval: Duration,
    #[serde(deserialize_with = "duration")]
    pub keepalive_timeout: Duration,
}

impl Default for Http2 {
    fn default() -> Self {
        let d = Http2Limits::default();
        Self {
            max_concurrent_streams: d.max_concurrent_streams,
            max_pending_reset_streams: d.max_pending_reset_streams,
            max_local_error_resets: d.max_local_error_resets,
            max_header_list_size: d.max_header_list_size,
            keepalive_interval: d.keepalive_interval.unwrap_or_default(),
            keepalive_timeout: d.keepalive_timeout,
        }
    }
}

/// RFC 0005 WebSocket and other HTTP/1.1 upgrades. Defaults come from
/// [`UpgradeConfig`].
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Upgrade {
    /// `[]` turns upgrades off.
    pub protocols: Vec<String>,
    pub max_tunnels: usize,
    #[serde(deserialize_with = "duration")]
    pub idle_timeout: Duration,
    /// `"0s"` turns the limit off.
    #[serde(deserialize_with = "duration")]
    pub max_lifetime: Duration,
}

impl Default for Upgrade {
    fn default() -> Self {
        let d = UpgradeConfig::default();
        Self {
            protocols: d.protocols,
            max_tunnels: d.max_tunnels,
            idle_timeout: d.idle_timeout,
            max_lifetime: d.max_lifetime.unwrap_or_default(),
        }
    }
}

#[cfg(test)]
// figment::Jail closures return figment::Error by value; not ours to box
#[allow(clippy::result_large_err)]
mod tests {
    use std::path::Path;

    use figment::Jail;

    use super::*;
    use crate::config::load;

    #[test]
    fn http2_defaults_match_the_rfc() {
        Jail::expect_with(|j| {
            j.set_env("DVARAPALA__UPSTREAM", "http://127.0.0.1:8081");
            let c = load(None).map_err(|e| e.to_string())?;
            assert_eq!(c.upstream_protocol, UpstreamProtocol::Http1);
            let h = &c.http2;
            assert_eq!(
                (h.max_concurrent_streams, h.max_pending_reset_streams),
                (100, 20)
            );
            assert_eq!(
                (h.max_local_error_resets, h.max_header_list_size),
                (1024, 16384)
            );
            assert_eq!(h.keepalive_interval, Duration::from_secs(30));
            assert_eq!(h.keepalive_timeout, Duration::from_secs(10));
            Ok(())
        });
    }

    #[test]
    fn http2_from_file_and_env() {
        Jail::expect_with(|j| {
            j.create_file(
                "d.toml",
                "upstream = \"http://127.0.0.1:8081\"\nupstream_protocol = \"http2\"\n[http2]\nkeepalive_interval = \"0s\"\n",
            )?;
            j.set_env("DVARAPALA__HTTP2__MAX_CONCURRENT_STREAMS", "8");
            let c = load(Some(Path::new("d.toml"))).map_err(|e| e.to_string())?;
            assert_eq!(c.upstream_protocol, UpstreamProtocol::Http2);
            assert_eq!(c.http2.keepalive_interval, Duration::ZERO);
            assert_eq!(c.http2.max_concurrent_streams, 8);
            Ok(())
        });
        Jail::expect_with(|j| {
            j.create_file(
                "d.toml",
                "upstream = \"http://127.0.0.1:8081\"\nupstream_protocol = \"h2\"\n",
            )?;
            let e = load(Some(Path::new("d.toml"))).unwrap_err().to_string();
            assert!(e.contains("h2"), "{e}");
            Ok(())
        });
    }

    #[test]
    fn upgrade_defaults_match_the_rfc() {
        Jail::expect_with(|j| {
            j.set_env("DVARAPALA__UPSTREAM", "http://127.0.0.1:8081");
            let u = load(None).map_err(|e| e.to_string())?.upgrade;
            assert_eq!(u.protocols, ["websocket"]);
            assert_eq!(u.max_tunnels, 10_000);
            assert_eq!(u.idle_timeout, Duration::from_secs(300));
            assert_eq!(u.max_lifetime, Duration::from_secs(86_400));
            Ok(())
        });
    }

    #[test]
    fn upgrade_from_file_and_env() {
        Jail::expect_with(|j| {
            j.create_file(
                "d.toml",
                "upstream = \"http://127.0.0.1:8081\"\n[upgrade]\nprotocols = []\nmax_lifetime = \"0s\"\n",
            )?;
            j.set_env("DVARAPALA__UPGRADE__IDLE_TIMEOUT", "30s");
            let u = load(Some(Path::new("d.toml")))
                .map_err(|e| e.to_string())?
                .upgrade;
            assert!(u.protocols.is_empty());
            assert_eq!(u.max_lifetime, Duration::ZERO);
            assert_eq!(u.idle_timeout, Duration::from_secs(30));
            Ok(())
        });
    }
}
