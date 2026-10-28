use std::fmt;
use std::time::Duration;

use dvarapala_engine::Cidr;

/// The `[xdp]` section, checked by the binary.
#[derive(Debug, Clone, PartialEq)]
pub struct XdpConfig {
    pub enforce: bool,
    pub allow: Vec<Cidr>,
    pub block: Vec<Cidr>,
    /// Zero turns dynamic blocks off.
    pub block_ttl: Duration,
    pub max_blocks: u32,
    pub pps: u32,
    pub syn_pps: u32,
    pub udp_pps: u32,
    pub burst: u32,
    pub prefix_v4: u8,
    pub prefix_v6: u8,
    pub max_sources: u32,
    /// The protected ports; 0 none.
    pub tcp_port: u16,
    pub udp_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attach {
    /// Native, else generic with a warning.
    Auto,
    Native,
    Generic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XdpError(pub String);

impl fmt::Display for XdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "xdp: {}", self.0)
    }
}

impl std::error::Error for XdpError {}
