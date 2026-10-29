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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub(crate) const COOKIE_NAME: &str = "dvarapala_pass";

/// The layer's challenge settings with their key.
pub(crate) struct Challenge {
    pub(crate) config: ChallengeConfig,
    pub(crate) keys: Keys,
}

impl Challenge {
    pub(crate) fn new(config: ChallengeConfig) -> Self {
        Self {
            keys: Keys::new(&config.secret),
            config,
        }
    }

    /// What the request's cookie says, before the engine decides.
    pub(crate) fn pass(&self, headers: &HeaderMap, key: ClientKey, required: bool) -> Pass {
        match pass_cookie(headers) {
            Some(v) if self.keys.check_pass(key, v, (self.config.unix)()) => return Pass::Valid,
            Some(_) => count("invalid_pass"),
            None => {}
        }
        if required {
            Pass::Required
        } else {
            Pass::Missing
        }
    }
}

pub(crate) fn count(result: &'static str) {
    metrics::counter!("dvarapala_challenges_total", "result" => result).increment(1);
}

/// The first `dvarapala_pass` value in the `Cookie` headers.
pub(crate) fn pass_cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|c| c.trim().strip_prefix(COOKIE_NAME)?.strip_prefix('='))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
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
