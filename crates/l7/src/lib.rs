//! HTTP layers that ask the engine for a verdict before the request goes on.

mod admin;
mod challenge;
mod control;
mod detection;
mod fingerprint;
mod grpc;
mod peer;
mod rate_limit;
mod reply;
mod routes;

pub use admin::{Call, MAX_QUERY, Refusal, authorized, fuzz_admin_query, parse as parse_admin};
pub use challenge::{ChallengeConfig, PageBody, fuzz_verify, unix_now};
pub use control::{Block, Reload, Status};
pub use detection::{Detection, Scoring};
pub use fingerprint::{Fingerprints, Ja4};
pub use grpc::{GrpcStatus, grpc_response, is_grpc};
pub use peer::PeerAddr;
pub use rate_limit::{RateLimit, RateLimitConfig, RateLimitLayer};
pub use routes::{Host, Matcher, PathMatch, RouteConfig, RouteKey, Routes, fuzz_route_match};
