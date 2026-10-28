//! HTTP/3 over QUIC (RFC 0006): a UDP listener with Retry under load and
//! connection limits, serving into the same service as the TCP listener.

mod body;
mod config;
mod endpoint;
mod h3;

pub use body::H3Body;
pub use config::{QuicConfig, Retry};
pub use endpoint::{QuicError, QuicListener};
