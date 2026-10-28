use std::time::Duration;

/// HTTP/1.1 upgrades passed through to the upstream (RFC 0005).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeConfig {
    /// `Upgrade` tokens passed to the upstream, lowercase; empty turns
    /// upgrades off.
    pub protocols: Vec<String>,
    /// Open tunnels at once; over it, `503`.
    pub max_tunnels: usize,
    /// No bytes in either direction for this long closes a tunnel.
    pub idle_timeout: Duration,
    /// Closes any tunnel after this long; `None` off.
    pub max_lifetime: Option<Duration>,
}

impl Default for UpgradeConfig {
    fn default() -> Self {
        Self {
            protocols: vec!["websocket".to_owned()],
            max_tunnels: 10_000,
            idle_timeout: Duration::from_secs(300),
            max_lifetime: Some(Duration::from_secs(24 * 3600)),
        }
    }
}
