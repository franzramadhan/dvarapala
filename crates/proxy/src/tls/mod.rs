//! TLS listener and `https://` upstreams (RFC 0003).

mod acceptor;
mod client;
mod expiry;
mod pair;

pub use acceptor::{Tls, TlsConfig};
pub(crate) use client::Connector;
pub use client::UpstreamTls;
#[doc(hidden)]
pub use expiry::not_after as cert_not_after;
pub use pair::{CertPair, TlsError};
