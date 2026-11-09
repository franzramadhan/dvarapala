//! HTTP/3 over QUIC (RFC 0006): a UDP listener with Retry under load and
//! connection limits (per client, RFC 0036), serving into the same service as the TCP listener.

mod body;
mod config;
mod endpoint;
mod h3;
mod limits;

pub use body::H3Body;
pub use config::{QuicConfig, Retry};
pub use endpoint::{QuicError, QuicListener};
pub use limits::{ClientGuard, ClientLimits};
