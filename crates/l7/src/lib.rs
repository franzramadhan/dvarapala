//! HTTP layers that ask the engine for a verdict before the request goes on.

mod admin;
mod challenge;
mod control;
mod detection;
mod fingerprint;
mod grpc;
#[cfg(feature = "ui")]
mod oidc;
mod peer;
mod rate_limit;
#[cfg(feature = "replay")]
mod replay;
mod reply;
mod routes;
mod session;
#[cfg(feature = "waf")]
mod waf;

pub use admin::{
    Call, MAX_QUERY, Refusal, authorized, cookie, csrf_ok, fuzz_admin_query, parse as parse_admin,
    secure_url,
};
pub use challenge::{ChallengeConfig, PageBody, fuzz_verify, unix_now};
pub use control::{Block, Reload, Status};
pub use detection::{Detection, Scoring};
pub use fingerprint::{Fingerprints, Ja4};
pub use grpc::{GrpcStatus, grpc_response, is_grpc};
#[cfg(feature = "ui")]
pub use oidc::{
    Denied, Logins, OidcConfig, Pending, Provider, callback as oidc_callback,
    check as check_id_token, discovery_url, enc as percent_encode, fuzz_oidc_callback, id_token,
    provider, token_request,
};
pub use peer::PeerAddr;
pub use rate_limit::{RateLimit, RateLimitConfig, RateLimitLayer};
#[cfg(feature = "replay")]
pub use replay::{Line, MAX_HEADERS, MAX_LINE, fuzz_replay_line};
pub use reply::totals as request_totals;
pub use routes::{
    Host, Matcher, NoWaf, PathMatch, RouteConfig, RouteKey, Routes, fuzz_route_match,
};
pub use session::{Method as LoginMethod, Session, Sessions};
#[cfg(feature = "waf")]
pub use waf::{Endpoint, HEADROOM, Waf, WafBody, WafConfig, WafLayer, fuzz_waf_frame};
