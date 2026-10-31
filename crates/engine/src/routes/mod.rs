//! RFC 0013: per-route policy, matched on host, path, method and client.
//! Moved here from `l7` by RFC 0028 so the C ABI reaches it: plain `&str`
//! and bytes, no `http` types.

mod limits;
mod matcher;

pub use limits::{RouteKey, RouteLimits};
pub use matcher::{Host, Matcher, PathMatch, parse_method, strip_port};
