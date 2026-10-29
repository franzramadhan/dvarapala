//! RFC 0017: a WAF stage that asks an inspection agent over SPOP.

mod agent;
mod body;
mod frame;
mod layer;

pub use agent::Endpoint;
pub use body::WafBody;
#[doc(hidden)]
pub use frame::fuzz_waf_frame;
pub use layer::{HEADROOM, Waf, WafConfig, WafLayer};
