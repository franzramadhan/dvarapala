//! RFC 0012: the client's JA4 TLS fingerprint and the rules on it.

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
        b.iter().all(u8::is_ascii_graphic).then_some(Self(b))
    }

    pub fn as_str(&self) -> &str {
        // checked in `new`
        std::str::from_utf8(&self.0).unwrap_or_default()
    }
}

impl fmt::Display for Ja4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for Ja4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ja4({})", self.as_str())
    }
}

/// One rule entry: a full JA4, or a prefix written with a trailing `*`.
#[derive(Debug, Clone)]
struct Pattern(String, bool);

impl Pattern {
    fn parse(s: &str) -> Result<Self, String> {
        match s.strip_suffix('*') {
            Some(p) if !p.is_empty() && p.len() < 36 && p.bytes().all(|b| b.is_ascii_graphic()) => {
                Ok(Self(p.into(), true))
            }
            None if s.len() == 36 && s.bytes().all(|b| b.is_ascii_graphic()) => {
                Ok(Self(s.into(), false))
            }
            _ => Err(format!(
                "fingerprint {s:?}: a 36-character JA4, or a prefix ending in *"
            )),
        }
    }

    fn matches(&self, f: &Ja4) -> bool {
        if self.1 {
            f.as_str().starts_with(&self.0)
        } else {
            f.as_str() == self.0
        }
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
        let parse = |v: &[String]| {
            v.iter()
                .map(|s| Pattern::parse(s))
                .collect::<Result<_, _>>()
        };
        let header = (!header.is_empty())
            .then(|| HeaderName::try_from(header))
            .transpose()
            .map_err(|e| format!("fingerprint.header {header:?}: {e}"))?;
        Ok(Self {
            deny: parse(deny)?,
            challenge: parse(challenge)?,
            header,
        })
    }

    /// Whether the TLS listener needs to compute JA4 at all.
    pub fn enabled(&self) -> bool {
        !self.deny.is_empty() || !self.challenge.is_empty() || self.header.is_some()
    }

    pub(crate) fn rule(&self, f: Option<Ja4>) -> Rule {
        let Some(f) = f else {
            return Rule::None;
        };
        let hit = |v: &[Pattern]| v.iter().any(|p| p.matches(&f));
        let rule = if hit(&self.deny) {
            Rule::Deny
        } else if hit(&self.challenge) {
            Rule::Challenge
        } else {
            return Rule::None;
        };
        let name = if rule == Rule::Deny {
            "deny"
        } else {
            "challenge"
        };
        metrics::counter!("dvarapala_fingerprint_matches_total", "rule" => name).increment(1);
        rule
    }

    /// Replaces the client's copy of the header with the computed JA4.
    pub(crate) fn forward(&self, headers: &mut HeaderMap, f: Option<Ja4>) {
        let Some(name) = &self.header else {
            return;
        };
        headers.remove(name);
        if let Some(v) = f.and_then(|f| HeaderValue::from_str(f.as_str()).ok()) {
            headers.insert(name.clone(), v);
        }
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
    fn ja4_is_printable() {
        let mut b = *CHROME;
        b[3] = b' ';
        assert!(Ja4::new(b).is_none());
        assert_eq!(f().unwrap().to_string().as_bytes(), CHROME);
    }
}
