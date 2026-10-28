use std::fmt;

use dvarapala_engine::{Cidr, ScheduleConfig};

use crate::UpgradeConfig;

/// One destination on the allow list.
#[derive(Debug, Clone, PartialEq)]
pub struct Destination {
    /// Label in logs and metrics.
    pub name: String,
    /// `http://host[:port]` or `https://host[:port]`.
    pub origin: String,
    pub schedule: ScheduleConfig,
    /// Requests or tunnels in flight at once; 0 off.
    pub max_concurrent: usize,
}

/// The forward proxy: who may use it and where requests may go.
#[derive(Debug, Clone)]
pub struct ForwardConfig {
    /// Peers allowed to use the proxy.
    pub clients: Vec<Cidr>,
    /// Allow `CONNECT` to listed destinations.
    pub connect: bool,
    pub destinations: Vec<Destination>,
    /// Limits for `CONNECT` tunnels (RFC 0005).
    pub tunnels: UpgradeConfig,
    /// Verification of `https://` destinations (RFC 0003).
    #[cfg(feature = "tls")]
    pub tls: crate::tls::UpstreamTls,
}

impl Default for ForwardConfig {
    fn default() -> Self {
        Self {
            clients: vec![
                "127.0.0.0/8".parse().expect("valid"),
                "::1/128".parse().expect("valid"),
            ],
            connect: true,
            destinations: Vec::new(),
            tunnels: UpgradeConfig::default(),
            #[cfg(feature = "tls")]
            tls: crate::tls::UpstreamTls::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardError {
    /// A destination's origin is not `http(s)://host[:port]`, or repeats one.
    Origin(String),
    /// A destination's limits are invalid.
    Schedule(String),
    /// `https://` without the `tls` feature.
    Unsupported(String),
    /// The upstream TLS settings could not be loaded.
    Tls(String),
}

impl fmt::Display for ForwardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Origin(why) => write!(f, "forward destination: {why}"),
            Self::Schedule(why) => write!(f, "forward destination limits: {why}"),
            Self::Unsupported(o) => write!(f, "destination {o:?}: https:// needs the tls feature"),
            Self::Tls(why) => write!(f, "upstream tls: {why}"),
        }
    }
}

impl std::error::Error for ForwardError {}
