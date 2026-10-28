use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use dvarapala_engine::{BlockSink, Cidr};
use tokio::net::TcpListener;

use crate::conn::Conn;
use crate::limits::Limits;
use crate::{L4Config, L4Error};

/// A TCP listener that closes connections over the limits before any TLS
/// or HTTP work (RFC 0009).
pub struct Listener {
    tcp: TcpListener,
    limits: Option<Arc<Limits>>,
    config: L4Config,
    block: Option<BlockSink>,
}

impl Listener {
    pub fn new(tcp: TcpListener, config: L4Config) -> Result<Self, L4Error> {
        let limits = config.enabled.then(|| Limits::new(&config)).transpose()?;
        Ok(Self {
            tcp,
            limits,
            config,
            block: None,
        })
    }

    /// Reports clients over the accept rate to `sink` (RFC 0011). They
    /// completed a handshake, so the address is not spoofed.
    pub fn with_block(mut self, sink: BlockSink) -> Self {
        self.block = Some(sink);
        self
    }

    /// The next connection within the limits; refused ones are closed and
    /// counted here.
    pub async fn accept(&self) -> io::Result<(Conn, SocketAddr)> {
        loop {
            let (io, addr) = self.tcp.accept().await?;
            let guard = match &self.limits {
                None => None,
                // a refused stream is dropped here, closed unread
                Some(l) => match l.admit(addr.ip()) {
                    Ok(g) => Some(g),
                    Err(reason) => {
                        if let (Some(b), "rate") = (&self.block, reason) {
                            let c = &self.config.conns;
                            let prefix = if addr.is_ipv4() {
                                c.prefix_v4
                            } else {
                                c.prefix_v6
                            };
                            b.block(Cidr::of(addr.ip(), prefix));
                        }
                        continue;
                    }
                },
            };
            return Ok((Conn::new(io, guard), addr));
        }
    }

    pub fn config(&self) -> &L4Config {
        &self.config
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.tcp.local_addr()
    }
}

impl From<TcpListener> for Listener {
    /// No limits, the default timeouts.
    fn from(tcp: TcpListener) -> Self {
        Self {
            tcp,
            limits: None,
            config: L4Config::timeouts_only(),
            block: None,
        }
    }
}
