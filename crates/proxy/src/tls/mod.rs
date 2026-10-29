//! TLS listener and `https://` upstreams (RFC 0003).

mod acceptor;
mod client;
mod expiry;
mod hello;
#[doc(hidden)]
pub mod ja4;
mod pair;
mod prefixed;

pub use acceptor::{Tls, TlsConfig};
pub use client::{Connector, UpstreamTls};
#[doc(hidden)]
pub use expiry::not_after as cert_not_after;
pub use pair::{CertPair, TlsError};
