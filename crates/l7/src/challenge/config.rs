#![allow(unused_variables, unused_imports, dead_code)]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dvarapala_engine::{ChallengeMode, ClientKey, Pass};
use http::HeaderMap;
use http::header::COOKIE;

use super::pass::Keys;

#[derive(Debug, Clone)]
pub struct ChallengeConfig {
    pub mode: ChallengeMode,
    /// Leading zero bits of work, 8 to 24.
    pub difficulty: u8,
    /// How long a seed can be solved.
    pub timeout: Duration,
    /// How long a pass is valid.
    pub pass_ttl: Duration,
    /// The HMAC key; empty picks a random one for this process.
    pub secret: Vec<u8>,
    /// `Secure` on the pass cookie.
    pub cookie_secure: bool,
    /// The wall clock in Unix seconds. [`unix_now`] outside tests.
    pub unix: fn() -> u64,
}

/// Seconds since the Unix epoch.
pub fn unix_now() -> u64 {
    todo!("rfc 0012")
}

pub(crate) const COOKIE_NAME: &str = "dvarapala_pass";

/// The layer's challenge settings with their key.
pub(crate) struct Challenge {
    pub(crate) config: ChallengeConfig,
    pub(crate) keys: Keys,
}

impl Challenge {
    pub(crate) fn new(config: ChallengeConfig) -> Self {
        todo!("rfc 0012")
    }

    /// What the request's cookie says, before the engine decides.
    pub(crate) fn pass(&self, headers: &HeaderMap, key: ClientKey, required: bool) -> Pass {
        todo!("rfc 0012")
    }
}

pub(crate) fn count(result: &'static str) {
    todo!("rfc 0012")
}

/// The first `dvarapala_pass` value in the `Cookie` headers.
pub(crate) fn pass_cookie(headers: &HeaderMap) -> Option<&str> {
    todo!("rfc 0012")
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    #[ignore = "rfc 0012"]
    fn finds_the_pass_among_cookies() {
        let mut h = HeaderMap::new();
        assert_eq!(pass_cookie(&h), None);
        h.append(COOKIE, HeaderValue::from_static("a=1; dvarapala_passx=2"));
        assert_eq!(pass_cookie(&h), None);
        h.append(
            COOKIE,
            HeaderValue::from_static("b=2;dvarapala_pass=9.ab ; c=3"),
        );
        assert_eq!(pass_cookie(&h), Some("9.ab"));
    }
}
