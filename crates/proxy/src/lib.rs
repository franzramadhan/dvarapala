//! Reverse proxy to one upstream, and the server that runs a service on a
//! TCP listener with graceful shutdown.

// rfc 0001 stubs: removed once the proxy layer fills the bodies in
#![allow(dead_code, unused_variables)]

mod hop;
mod reverse;
mod server;

pub use reverse::{ProxyBody, ReverseProxy, UpstreamError};
pub use server::serve;
