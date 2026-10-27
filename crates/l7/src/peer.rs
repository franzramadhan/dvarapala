use std::net::SocketAddr;

/// The TCP peer of a request, set as a request extension by the server.
/// Layers that key on the client read it; without it they fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerAddr(pub SocketAddr);
