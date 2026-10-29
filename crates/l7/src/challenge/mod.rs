//! RFC 0012: the proof-of-work challenge and its pass cookie.

mod body;
mod config;
mod page;
mod pass;

pub use body::PageBody;
#[allow(unused_imports)]
pub(crate) use config::Challenge;
pub use config::{ChallengeConfig, unix_now};
#[allow(unused_imports)]
pub(crate) use page::VERIFY_PATH;
#[doc(hidden)]
pub use page::fuzz_verify;
