//! HTTP layers that ask the engine for a verdict before the request goes on.

mod challenge;
mod detection;
mod fingerprint;
mod grpc;
mod peer;
mod rate_limit;

pub use challenge::{ChallengeConfig, PageBody, fuzz_verify, unix_now};
pub use detection::{Detection, Scoring};
pub use fingerprint::{Fingerprints, Ja4};
pub use grpc::{GrpcStatus, grpc_response, is_grpc};
pub use peer::PeerAddr;
pub use rate_limit::{RateLimit, RateLimitConfig, RateLimitLayer};
