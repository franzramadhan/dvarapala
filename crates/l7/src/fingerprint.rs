//! RFC 0012: the client's JA4 TLS fingerprint and the rules on it.
#![allow(unused_variables, unused_imports, dead_code)]

use std::fmt;

use http::HeaderMap;
use http::header::{HeaderName, HeaderValue};

/// The JA4 fingerprint of the connection's ClientHello, set by the TLS
/// listener on every request (`t13d1516h2_8daaf6152771_e5627efa2ab1`).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ja4([u8; 36]);

impl Ja4 {
    /// `None` unless every byte is printable ASCII.
    pub fn new(b: [u8; 36]) -> Option<Self> {
        todo!("rfc 0012")
    }

    pub fn as_str(&self) -> &str {
        todo!("rfc 0012")
    }
}

impl fmt::Display for Ja4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!("rfc 0012")
    }
}

impl fmt::Debug for Ja4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!("rfc 0012")
    }
}

/// One rule entry: a full JA4, or a prefix written with a trailing `*`.
#[derive(Debug, Clone)]
struct Pattern(String, bool);

impl Pattern {
    fn parse(s: &str) -> Result<Self, String> {
        todo!("rfc 0012")
    }

    fn matches(&self, f: &Ja4) -> bool {
        todo!("rfc 0012")
    }
}

/// What the rules say about a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    None,
    Deny,
    Challenge,
}

/// `[fingerprint]`: deny, challenge, and the upstream header.
#[derive(Debug, Clone, Default)]
pub struct Fingerprints {
    deny: Vec<Pattern>,
    challenge: Vec<Pattern>,
    header: Option<HeaderName>,
}

impl Fingerprints {
    /// Fails on an entry that is not a JA4 or a prefix, or a bad header name.
    pub fn new(deny: &[String], challenge: &[String], header: &str) -> Result<Self, String> {
        todo!("rfc 0012")
    }

    /// Whether the TLS listener needs to compute JA4 at all.
    pub fn enabled(&self) -> bool {
        todo!("rfc 0012")
    }

    pub(crate) fn rule(&self, f: Option<Ja4>) -> Rule {
        todo!("rfc 0012")
    }

    /// Replaces the client's copy of the header with the computed JA4.
    pub(crate) fn forward(&self, headers: &mut HeaderMap, f: Option<Ja4>) {
        todo!("rfc 0012")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHROME: &[u8; 36] = b"t13d1516h2_8daaf6152771_e5627efa2ab1";

    fn f() -> Option<Ja4> {
        Ja4::new(*CHROME)
    }

    #[test]
    #[ignore = "rfc 0012"]
    fn exact_and_prefix_rules() {
        let r = Fingerprints::new(
            &["t13d1516h2_*".into()],
            &[String::from_utf8(CHROME.to_vec()).unwrap()],
            "",
        )
        .unwrap();
        assert_eq!(r.rule(f()), Rule::Deny, "deny wins");
        let r = Fingerprints::new(&["t12*".into()], &["t13d*".into()], "").unwrap();
        assert_eq!(r.rule(f()), Rule::Challenge);
        assert_eq!(r.rule(None), Rule::None);
        assert!(r.enabled());
        assert!(!Fingerprints::default().enabled());
    }

    #[test]
    #[ignore = "rfc 0012"]
    fn rejects_bad_entries() {
        for bad in ["", "*", "short", "t13 d*"] {
            assert!(
                Fingerprints::new(&[bad.into()], &[], "").is_err(),
                "{bad:?}"
            );
        }
        assert!(Fingerprints::new(&[], &[], "bad header").is_err());
    }

    #[test]
    #[ignore = "rfc 0012"]
    fn header_replaces_the_clients_copy() {
        let r = Fingerprints::new(&[], &[], "x-ja4").unwrap();
        let mut h = HeaderMap::new();
        h.append("x-ja4", HeaderValue::from_static("spoofed"));
        h.append("x-ja4", HeaderValue::from_static("again"));
        r.forward(&mut h, f());
        assert_eq!(h.get_all("x-ja4").iter().count(), 1);
        assert_eq!(h["x-ja4"].as_bytes(), CHROME);
        r.forward(&mut h, None);
        assert!(!h.contains_key("x-ja4"));
    }

    #[test]
    #[ignore = "rfc 0012"]
    fn ja4_is_printable() {
        let mut b = *CHROME;
        b[3] = b' ';
        assert!(Ja4::new(b).is_none());
        assert_eq!(f().unwrap().to_string().as_bytes(), CHROME);
    }
}
