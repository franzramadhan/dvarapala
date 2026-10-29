#![allow(unused_variables, unused_imports, dead_code)]
use std::time::Duration;

use bytes::Bytes;
use dvarapala_engine::{ChallengeMode, ClientKey};
use http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, HeaderValue, LOCATION, SET_COOKIE,
};
use http::{Response, StatusCode};
use ring::digest;

use super::PageBody;
use super::config::{COOKIE_NAME, Challenge, ChallengeConfig, count};
use super::pass::digits;

/// Where the page sends a solution.
pub(crate) const VERIFY_PATH: &str = "/.well-known/dvarapala/verify";

/// Nothing from the request is written into it: the numbers come from us,
/// and the script reads its own location for the return path.
const TEMPLATE: &str = include_str!("page.html");

const CSP: &str = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; \
                   frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

/// Longest return path kept; longer ones go to `/`.
const MAX_RETURN: usize = 2048;

impl Challenge {
    /// The challenge page for `key`, with a fresh seed.
    pub(crate) fn page<R: PageBody>(&self, key: ClientKey) -> Response<R> {
        todo!("rfc 0012")
    }

    /// The verify endpoint: a pass and a redirect to the return path when
    /// the work is right, the redirect alone (a fresh challenge) otherwise.
    pub(crate) fn verify<R: PageBody>(&self, query: Option<&str>, key: ClientKey) -> Response<R> {
        todo!("rfc 0012")
    }
}

/// The verify query: `t`, `s` and `n` as sent, `r` decoded and checked.
struct Query<'a> {
    t: Option<u64>,
    s: &'a str,
    n: &'a str,
    r: String,
}

impl<'a> Query<'a> {
    fn parse(q: &'a str) -> Self {
        todo!("rfc 0012")
    }
}

/// The decoded return path when it stays on this site: one `/`, then not
/// `/` or `\` (a scheme-relative URL), printable ASCII only.
fn safe_return(encoded: &str) -> Option<String> {
    todo!("rfc 0012")
}

/// `SHA-256(seed ":" nonce)` starts with `difficulty` zero bits.
fn work_ok(seed: &str, nonce: &str, difficulty: u8) -> bool {
    todo!("rfc 0012")
}

fn leading_zeros(h: &[u8]) -> u32 {
    todo!("rfc 0012")
}

/// Fuzzing entry (RFC 0012 case 15): the verify query and a cookie header.
#[doc(hidden)]
pub fn fuzz_verify(query: &str, cookie: &str) {
    todo!("rfc 0012")
}

#[cfg(test)]
mod tests {
    use http_body_util::Full;

    use super::*;

    fn challenge(now: u64) -> Challenge {
        Challenge::new(ChallengeConfig {
            mode: ChallengeMode::Always,
            difficulty: 8,
            timeout: Duration::from_secs(60),
            pass_ttl: Duration::from_secs(3600),
            secret: vec![3; 32],
            cookie_secure: true,
            unix: match now {
                1000 => || 1000,
                _ => || 1100,
            },
        })
    }

    pub(crate) fn solve(seed: &str, difficulty: u8) -> u64 {
        (0..)
            .find(|n| work_ok(seed, &n.to_string(), difficulty))
            .unwrap()
    }

    fn key(last: u8) -> ClientKey {
        ClientKey::V4([192, 0, 2, last].into())
    }

    #[test]
    #[ignore = "rfc 0012"]
    fn right_work_in_time_gets_a_pass() {
        let c = challenge(1000);
        let s = c.keys.seed(key(1), 990);
        let n = solve(&s, 8);
        let res =
            c.verify::<Full<Bytes>>(Some(&format!("t=990&s={s}&n={n}&r=%2Fa%3Fb%3D1")), key(1));
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        assert_eq!(res.headers()[LOCATION], "/a?b=1");
        let cookie = res.headers()[SET_COOKIE].to_str().unwrap();
        assert!(cookie.starts_with("dvarapala_pass=4600."), "{cookie}");
        assert!(
            cookie.ends_with("; HttpOnly; SameSite=Lax; Secure"),
            "{cookie}"
        );
    }

    #[test]
    #[ignore = "rfc 0012"]
    fn stale_foreign_or_lazy_work_fails() {
        let s = challenge(1000).keys.seed(key(1), 990);
        let n = solve(&s, 8);
        let q = format!("t=990&s={s}&n={n}&r=/");
        // 110 s later, past the 60 s timeout
        let res = challenge(1100).verify::<Full<Bytes>>(Some(&q), key(1));
        assert!(!res.headers().contains_key(SET_COOKIE));
        let res = challenge(1000).verify::<Full<Bytes>>(Some(&q), key(2));
        assert!(!res.headers().contains_key(SET_COOKIE));
        let lazy = (0..).find(|n| !work_ok(&s, &n.to_string(), 8)).unwrap();
        let q = format!("t=990&s={s}&n={lazy}&r=/");
        let res = challenge(1000).verify::<Full<Bytes>>(Some(&q), key(1));
        assert!(!res.headers().contains_key(SET_COOKIE));
        // issued in the future
        let s = challenge(1000).keys.seed(key(1), 1050);
        let q = format!("t=1050&s={s}&n={}&r=/", solve(&s, 8));
        let res = challenge(1000).verify::<Full<Bytes>>(Some(&q), key(1));
        assert!(!res.headers().contains_key(SET_COOKIE));
    }

    #[test]
    #[ignore = "rfc 0012"]
    fn return_path_stays_on_site() {
        let long = format!("/{}", "a".repeat(3000));
        for r in [
            "//evil.example",
            "/%5Cevil",
            "%2F%2Fevil",
            "https://x",
            "/a%0D%0ASet-Cookie:x",
            "/a b",
            "",
            "/%zz",
            &long,
        ] {
            assert_eq!(Query::parse(&format!("r={r}")).r, "/", "{r:?}");
        }
        assert_eq!(Query::parse("r=%2Fp%2520q%3Fx%3D1").r, "/p%20q?x=1");
        assert_eq!(Query::parse("x=1").r, "/");
    }

    #[test]
    #[ignore = "rfc 0012"]
    fn page_carries_no_request_data() {
        let res = challenge(1000).page::<Full<Bytes>>(key(1));
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        assert_eq!(res.headers()[CACHE_CONTROL], "no-store");
        assert!(res.headers().contains_key(CONTENT_SECURITY_POLICY));
    }

    #[test]
    #[ignore = "rfc 0012"]
    fn zero_bits_counted_across_bytes() {
        assert_eq!(leading_zeros(&[0, 0, 0x10, 0xff]), 19);
        assert_eq!(leading_zeros(&[0x80]), 0);
        assert_eq!(leading_zeros(&[0, 0]), 16);
        assert!(!work_ok("s", "", 0));
        assert!(!work_ok("s", "-1", 0));
        assert!(work_ok("s", "1", 0));
    }
}
