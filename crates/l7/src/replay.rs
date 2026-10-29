//! RFC 0016: one access log line as the request the layer would have seen.
#![allow(unused_variables, unused_imports, dead_code, unreachable_code)]

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

use http::header::{HOST, HeaderName, HeaderValue};
use http::{Method, Request, Uri};
use serde::Deserialize;

use crate::{Ja4, PeerAddr};

/// Longest line read; a longer one is skipped.
pub const MAX_LINE: usize = 64 * 1024;
/// Headers per line at most.
pub const MAX_HEADERS: usize = 64;

#[derive(Deserialize)]
struct Raw {
    ts: f64,
    client: String,
    method: Option<String>,
    #[serde(default)]
    host: String,
    path: Option<String>,
    xff: Option<String>,
    ja4: Option<String>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
}

/// A parsed line: its time and the request, with `PeerAddr` and `Ja4`.
#[derive(Debug)]
pub struct Line {
    /// Unix time in seconds.
    pub ts: f64,
    pub request: Request<()>,
}

impl Line {
    /// One JSON object; unknown fields are ignored.
    pub fn parse(s: &str) -> Result<Self, String> {
        todo!("rfc 0016")
    }
}

/// Fuzz entry (RFC 0016 case 11): any bytes, never a panic.
pub fn fuzz_replay_line(data: &[u8]) {
    todo!("rfc 0016")
}

#[cfg(test)]
mod tests {
    use super::*;

    const JA4: &str = "t13d1516h2_8daaf6152771_e5627efa2ab1";

    // RFC 0016 case 1
    #[test]
    #[ignore = "rfc 0016"]
    fn every_field_reaches_the_request() {
        let s = format!(
            r#"{{"ts":1700000000.5,"client":"192.0.2.7","method":"POST","host":"app.example",
               "path":"/login?next=%2F","xff":"198.51.100.1","ja4":"{JA4}",
               "headers":{{"x-api-key":"k1"}},"status":200}}"#
        )
        .replace('\n', "");
        let l = Line::parse(&s).unwrap();
        let r = &l.request;
        assert_eq!(l.ts, 1_700_000_000.5);
        assert_eq!(r.method(), Method::POST);
        assert_eq!(r.uri(), "/login?next=%2F");
        assert_eq!(r.headers()["host"], "app.example");
        assert_eq!(r.headers()["x-forwarded-for"], "198.51.100.1");
        assert_eq!(r.headers()["x-api-key"], "k1");
        assert_eq!(
            r.extensions().get::<PeerAddr>(),
            Some(&PeerAddr("192.0.2.7:0".parse().unwrap()))
        );
        assert_eq!(r.extensions().get::<Ja4>().unwrap().as_str(), JA4);
        let min = Line::parse(r#"{"ts":0,"client":"2001:db8::1"}"#).unwrap();
        assert_eq!(
            (min.request.method(), min.request.uri().path()),
            (&Method::GET, "/")
        );
    }

    // RFC 0016 case 2
    #[test]
    #[ignore = "rfc 0016"]
    fn bad_lines_name_the_reason() {
        let headers: String = (0..65).map(|i| format!(r#""h{i}":"v","#)).collect();
        let cases = [
            ("not json".to_owned(), "expected"),
            (r#"{"client":"192.0.2.7"}"#.to_owned(), "ts"),
            (r#"{"ts":1}"#.to_owned(), "client"),
            (r#"{"ts":1,"client":"192.0.2.300"}"#.to_owned(), "client"),
            (r#"{"ts":-1,"client":"192.0.2.7"}"#.to_owned(), "ts"),
            (
                format!(
                    r#"{{"ts":1,"client":"192.0.2.7","x":"{}"}}"#,
                    "a".repeat(MAX_LINE)
                ),
                "line over",
            ),
            (
                format!(
                    r#"{{"ts":1,"client":"192.0.2.7","headers":{{{}"z":"v"}}}}"#,
                    headers
                ),
                "headers",
            ),
            (
                r#"{"ts":1,"client":"192.0.2.7","headers":{"bad name":"v"}}"#.to_owned(),
                "header name",
            ),
            (
                r#"{"ts":1,"client":"192.0.2.7","path":"http://x/"}"#.to_owned(),
                "path",
            ),
            (
                r#"{"ts":1,"client":"192.0.2.7","ja4":"short"}"#.to_owned(),
                "ja4",
            ),
        ];
        for (line, why) in cases {
            let e = Line::parse(&line).unwrap_err();
            assert!(e.contains(why), "{line:.80}: {e}");
        }
    }
}
