//! Limits on connections before any HTTP is parsed: a cap on open
//! connections per client and in total, a bucket on new connections, and
//! idle and slow-body timeouts (RFC 0009). The PROXY protocol header of a
//! trusted load balancer sets the client (RFC 0030).

mod body;
mod config;
mod conn;
mod limits;
mod listener;
pub mod proxy_protocol;

pub use body::{BodyRate, MinBodyRate, TooSlow, is_too_slow};
pub use config::{L4Config, L4Error, ProxyProtocol};
pub use conn::{Activity, Conn, InFlight};
pub use listener::{Accepted, Listener};
