//! HTTP layers that ask the engine for a verdict before the request goes on.

// rfc 0001 stubs: removed once the l7 layer fills the bodies in
#![allow(dead_code, unused_variables)]

mod peer;
mod rate_limit;

pub use peer::PeerAddr;
pub use rate_limit::{RateLimit, RateLimitConfig, RateLimitLayer};
