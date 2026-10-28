//! HTTP layers that ask the engine for a verdict before the request goes on.

mod detection;
mod grpc;
mod peer;
mod rate_limit;

pub use detection::{Detection, Scoring};
pub use grpc::{GrpcStatus, grpc_response, is_grpc};
pub use peer::PeerAddr;
pub use rate_limit::{RateLimit, RateLimitConfig, RateLimitLayer};
