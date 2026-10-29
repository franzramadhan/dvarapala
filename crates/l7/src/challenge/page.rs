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
        let t = (self.config.unix)();
        let html = TEMPLATE
            .replacen("{T}", &t.to_string(), 1)
            .replacen("{S}", &self.keys.seed(key, t), 1)
            .replacen("{D}", &self.config.difficulty.to_string(), 1);
        count("issued");
        let mut res = Response::new(R::page(Bytes::from(html)));
        *res.status_mut() = StatusCode::FORBIDDEN;
        let h = res.headers_mut();
        h.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
        h.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        h.insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
        res
    }

    /// The verify endpoint: a pass and a redirect to the return path when
    /// the work is right, the redirect alone (a fresh challenge) otherwise.
    pub(crate) fn verify<R: PageBody>(&self, query: Option<&str>, key: ClientKey) -> Response<R> {
        let q = Query::parse(query.unwrap_or(""));
        let now = (self.config.unix)();
        let fresh =
            q.t.is_some_and(|t| t <= now && now - t <= self.config.timeout.as_secs());
        let ok = fresh
            && q.t.is_some_and(|t| self.keys.check_seed(key, t, q.s))
            && work_ok(q.s, q.n, self.config.difficulty);
        let mut res = Response::new(R::default());
        *res.status_mut() = StatusCode::SEE_OTHER;
        let h = res.headers_mut();
        h.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        h.insert(
            LOCATION,
            HeaderValue::from_str(&q.r).unwrap_or(HeaderValue::from_static("/")),
        );
        if !ok {
            count("failed");
            return res;
        }
        count("passed");
        tracing::debug!(msg = "challenge_passed", key = %key);
        let ttl = self.config.pass_ttl.as_secs();
        let cookie = format!(
            "{COOKIE_NAME}={}; Path=/; Max-Age={ttl}; HttpOnly; SameSite=Lax{}",
            self.keys.pass(key, now + ttl),
            if self.config.cookie_secure {
                "; Secure"
            } else {
                ""
            }
        );
        if let Ok(v) = HeaderValue::from_str(&cookie) {
            h.insert(SET_COOKIE, v);
        }
        res
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
        let (mut t, mut s, mut n, mut r) = (None, None, None, None);
        for (k, v) in q.split('&').filter_map(|p| p.split_once('=')) {
            match k {
                "t" if t.is_none() => t = Some(v),
                "s" if s.is_none() => s = Some(v),
                "n" if n.is_none() => n = Some(v),
                "r" if r.is_none() => r = Some(v),
                _ => {}
            }
        }
        Self {
            t: t.and_then(digits),
            s: s.unwrap_or(""),
            n: n.unwrap_or(""),
            r: r.and_then(safe_return).unwrap_or_else(|| "/".into()),
        }
    }
}

/// The decoded return path when it stays on this site: one `/`, then not
/// `/` or `\` (a scheme-relative URL), printable ASCII only.
fn safe_return(encoded: &str) -> Option<String> {
    if encoded.len() > MAX_RETURN * 3 {
        return None;
    }
    let b = encoded.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = b.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    let ok = out.len() <= MAX_RETURN
        && out.first() == Some(&b'/')
        && !matches!(out.get(1), Some(b'/' | b'\\'))
        && out.iter().all(|c| (0x21..=0x7e).contains(c));
    ok.then(|| String::from_utf8(out).ok())?
}

/// `SHA-256(seed ":" nonce)` starts with `difficulty` zero bits.
fn work_ok(seed: &str, nonce: &str, difficulty: u8) -> bool {
    if digits(nonce).is_none() {
        return false;
    }
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(seed.as_bytes());
    ctx.update(b":");
    ctx.update(nonce.as_bytes());
    leading_zeros(ctx.finish().as_ref()) >= u32::from(difficulty)
}

fn leading_zeros(h: &[u8]) -> u32 {
    let mut n = 0;
    for b in h {
        n += b.leading_zeros();
        if *b != 0 {
            break;
        }
    }
    n
}

/// Fuzzing entry (RFC 0012 case 15): the verify query and a cookie header.
#[doc(hidden)]
pub fn fuzz_verify(query: &str, cookie: &str) {
    let c = Challenge::new(ChallengeConfig {
        mode: ChallengeMode::Always,
        difficulty: 8,
        timeout: Duration::from_secs(60),
        pass_ttl: Duration::from_secs(60),
        secret: vec![1; 32],
        cookie_secure: true,
        unix: || 1_000_000,
    });
    let key = ClientKey::V4([192, 0, 2, 1].into());
    let _ = c.verify::<http_body_util::Full<Bytes>>(Some(query), key);
    let mut h = http::HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(cookie) {
        h.insert(http::header::COOKIE, v);
    }
    let _ = c.pass(&h, key, false);
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
    fn return_path_stays_on_site() {
        let long = format!("/{}", "a".repeat(3000));
        let huge = format!("/{}", "a".repeat(7000));
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
            &huge,
        ] {
            assert_eq!(Query::parse(&format!("r={r}")).r, "/", "{r:?}");
        }
        assert_eq!(Query::parse("r=%2Fp%2520q%3Fx%3D1").r, "/p%20q?x=1");
        assert_eq!(Query::parse("x=1").r, "/");
    }

    #[test]
    fn page_carries_no_request_data() {
        let res = challenge(1000).page::<Full<Bytes>>(key(1));
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        assert_eq!(res.headers()[CACHE_CONTROL], "no-store");
        assert!(res.headers().contains_key(CONTENT_SECURITY_POLICY));
    }

    #[test]
    fn zero_bits_counted_across_bytes() {
        assert_eq!(leading_zeros(&[0, 0, 0x10, 0xff]), 19);
        assert_eq!(leading_zeros(&[0x80]), 0);
        assert_eq!(leading_zeros(&[0, 0]), 16);
        assert!(!work_ok("s", "", 0));
        assert!(!work_ok("s", "-1", 0));
        assert!(work_ok("s", "1", 0));
    }
}
