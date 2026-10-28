//! Forward proxy with per-destination egress rate shaping (RFC 0007).

mod config;
mod proxy;
mod route;

pub use config::{Destination, ForwardConfig, ForwardError};
pub use proxy::ForwardProxy;
pub use route::Routes;
