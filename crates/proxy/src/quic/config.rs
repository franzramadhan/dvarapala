use std::net::SocketAddr;
use std::time::Duration;

/// When a new connection must prove its address with a Retry first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retry {
    /// Once handshakes in progress reach `retry_threshold`.
    UnderLoad,
    Always,
    /// Lab use only: spoofed Initials cost handshakes.
    Never,
}

#[derive(Debug, Clone)]
pub struct QuicConfig {
    pub listen: SocketAddr,
    pub retry: Retry,
    pub retry_threshold: usize,
    /// Open connections, handshakes included; over it, refused before the
    /// handshake.
    pub max_connections: usize,
    /// Bidirectional streams per connection.
    pub max_streams: u32,
    pub idle_timeout: Duration,
    pub handshake_timeout: Duration,
    /// How long a Retry token is valid; QUIC keeps it in whole seconds.
    pub retry_token_lifetime: Duration,
}

impl QuicConfig {
    /// The RFC 0006 defaults on `listen`.
    pub fn new(listen: SocketAddr) -> Self {
        Self {
            listen,
            retry: Retry::UnderLoad,
            retry_threshold: 256,
            max_connections: 10_000,
            max_streams: 100,
            idle_timeout: Duration::from_secs(30),
            handshake_timeout: Duration::from_secs(10),
            retry_token_lifetime: Duration::from_secs(10),
        }
    }
}
