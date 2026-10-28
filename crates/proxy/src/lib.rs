//! Reverse proxy to one upstream, forward proxy to listed destinations
//! (RFC 0007), and the server that runs a service on a TCP listener with
//! graceful shutdown.

mod alt_svc;
mod forward;
mod hop;
mod http2;
#[cfg(feature = "http3")]
pub mod quic;
mod reverse;
mod server;
#[cfg(feature = "tls")]
pub mod tls;
mod tunnels;
mod upgrade;
mod upstream;

pub use alt_svc::AltSvc;
pub use forward::{Destination, ForwardConfig, ForwardError, ForwardProxy, Routes};
pub use hop::allowed_upgrade;
pub use http2::Http2Limits;
pub use reverse::{ProxyBody, ReverseProxy, UpstreamError};
pub use server::serve;
#[cfg(feature = "tls")]
pub use server::serve_tls;
pub use upgrade::UpgradeConfig;
pub use upstream::{UpstreamConfig, UpstreamProtocol};
