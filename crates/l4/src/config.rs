use std::fmt;
use std::time::Duration;

use dvarapala_engine::{Cidr, ConnsConfig};

use crate::proxy_protocol::Version;

/// The `[l4]` section (RFC 0009).
#[derive(Debug, Clone, PartialEq)]
pub struct L4Config {
    /// `false` keeps only the timeouts.
    pub enabled: bool,
    /// Open connections in total; 0 off.
    pub max_connections: usize,
    pub conns: ConnsConfig,
    /// Time to receive each request head.
    pub header_timeout: Duration,
    /// A connection with no bytes either way and no request in flight for
    /// this long is closed; `None` off.
    pub idle_timeout: Option<Duration>,
    /// Bytes per second over a 10 s window; 0 off.
    pub min_body_rate: u64,
    /// PROXY protocol from trusted balancers (RFC 0030); `None` off.
    pub proxy_protocol: Option<ProxyProtocol>,
}

/// The `l4.proxy_protocol*` keys (RFC 0030).
#[derive(Debug, Clone, PartialEq)]
pub struct ProxyProtocol {
    pub version: Version,
    /// Peers that must send a header; never empty.
    pub from: Vec<Cidr>,
    /// Time to receive the whole header.
    pub timeout: Duration,
}

impl ProxyProtocol {
    pub(crate) fn trusts(&self, ip: std::net::IpAddr) -> bool {
        self.from.iter().any(|c| c.contains(ip))
    }
}

impl Default for L4Config {
    fn default() -> Self {
        Self {
            enabled: true,
            max_connections: 0,
            conns: ConnsConfig::default(),
            header_timeout: Duration::from_secs(30),
            idle_timeout: Some(Duration::from_secs(60)),
            min_body_rate: 0,
            proxy_protocol: None,
        }
    }
}

impl L4Config {
    /// No limits, the default timeouts: what a bare `TcpListener` gets.
    pub fn timeouts_only() -> Self {
        Self {
            enabled: false,
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L4Error(pub String);

impl fmt::Display for L4Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "l4: {}", self.0)
    }
}

impl std::error::Error for L4Error {}
