use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use dvarapala_engine::{BlockSink, Cidr};
use tokio::net::{TcpListener, TcpStream};

use crate::conn::Conn;
use crate::limits::{Guard, Limits};
use crate::{L4Config, L4Error, ProxyProtocol};

/// A TCP listener that closes connections over the limits before any TLS
/// or HTTP work (RFC 0009).
pub struct Listener {
    tcp: TcpListener,
    limits: Option<Arc<Limits>>,
    config: L4Config,
    block: Option<BlockSink>,
    proxy: Option<Arc<ProxyProtocol>>,
}

/// An accepted connection. A trusted balancer's connection still owes its
/// PROXY protocol header (RFC 0030): [`Accepted::ready`] reads it in the
/// connection's own task, so a slow balancer never holds up the accept
/// loop.
pub struct Accepted {
    peer: SocketAddr,
    state: State,
}

enum State {
    Ready(Conn),
    Header {
        io: TcpStream,
        guard: Option<Guard>,
        limits: Option<Arc<Limits>>,
        proxy: Arc<ProxyProtocol>,
    },
}

impl Listener {
    pub fn new(tcp: TcpListener, config: L4Config) -> Result<Self, L4Error> {
        let limits = config.enabled.then(|| Limits::new(&config)).transpose()?;
        let proxy = config.proxy_protocol.clone().map(Arc::new);
        if proxy.as_ref().is_some_and(|p| p.from.is_empty()) {
            return Err(L4Error(
                "proxy_protocol_from must list the balancers".into(),
            ));
        }
        Ok(Self {
            tcp,
            limits,
            config,
            block: None,
            proxy,
        })
    }

    /// Reports clients over the accept rate to `sink` (RFC 0011). They
    /// completed a handshake, so the address is not spoofed. Clients a
    /// balancer speaks for are never reported: their packets come from the
    /// balancer (RFC 0030).
    pub fn with_block(mut self, sink: BlockSink) -> Self {
        self.block = Some(sink);
        self
    }

    /// The next connection within the limits; refused ones are closed and
    /// counted here. A trusted balancer's connection is checked against
    /// `max_connections` only, the rest waits for its header.
    pub async fn accept(&self) -> io::Result<Accepted> {
        loop {
            let (io, addr) = self.tcp.accept().await?;
            if let Some(p) = self.proxy.as_ref().filter(|p| p.trusts(addr.ip())) {
                let guard = match &self.limits {
                    None => None,
                    Some(l) => match l.total(addr.ip()) {
                        Ok(g) => Some(g),
                        Err(_) => continue,
                    },
                };
                return Ok(Accepted {
                    peer: addr,
                    state: State::Header {
                        io,
                        guard,
                        limits: self.limits.clone(),
                        proxy: p.clone(),
                    },
                });
            }
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
            return Ok(Accepted {
                peer: addr,
                state: State::Ready(Conn::new(io, guard)),
            });
        }
    }

    pub fn config(&self) -> &L4Config {
        &self.config
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.tcp.local_addr()
    }
}

impl Accepted {
    /// The TCP peer: the client, or the balancer before its header.
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// The connection and its client. A trusted balancer's header is read
    /// first, under `proxy_protocol_timeout`, then the per-client limits
    /// apply to the client it carries. `None` when the header is missing,
    /// invalid or late, or the client is over its limits: the connection
    /// is closed with nothing written.
    pub async fn ready(self) -> Option<(Conn, SocketAddr)> {
        let (mut io, mut guard, limits, proxy) = match self.state {
            State::Ready(conn) => return Some((conn, self.peer)),
            State::Header {
                io,
                guard,
                limits,
                proxy,
            } => (io, guard, limits, proxy),
        };
        let _ = (&mut io, &mut guard, limits, proxy);
        todo!("rfc 0030")
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
            proxy: None,
        }
    }
}
