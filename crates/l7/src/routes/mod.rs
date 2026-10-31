//! RFC 0013: per-route policy, matched on host, path, method and client.
//! The matcher and the route buckets live in the engine (RFC 0028); this
//! adapts `http` requests to them and keeps the gateway-only fields.

mod policy;

pub use dvarapala_engine::{Host, Matcher, PathMatch, RouteKey};
#[doc(hidden)]
pub use policy::fuzz_route_match;
pub use policy::{NoWaf, RouteConfig, Routes};
