//! Admin API requests (RFC 0014): the endpoint, its parameters and the
//! bearer token check. Serving them is the binary's job.
#![allow(unused_variables, unused_imports, dead_code, unreachable_code)]

use dvarapala_engine::Cidr;
use http::{HeaderValue, StatusCode};

/// Longest query string read.
pub const MAX_QUERY: usize = 1024;

/// One admin call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    Status,
    Top,
    Reload,
    Blocks,
    /// `ttl` as given, parsed by the caller.
    Block {
        net: Cidr,
        ttl: Option<String>,
    },
    Unblock {
        net: Cidr,
    },
}

/// A refused call: its status and a reason for the body.
pub type Refusal = (StatusCode, String);

pub fn parse(method: &str, path: &str, query: Option<&str>) -> Result<Call, Refusal> {
    todo!("rfc 0014")
}

/// `Authorization: Bearer <token>`, compared in constant time for a given
/// length. An empty token never matches.
pub fn authorized(header: Option<&HeaderValue>, token: &[u8]) -> bool {
    todo!("rfc 0014")
}

/// `cidr=<net>`, required, host bits cleared so that `192.0.2.7/24` and
/// `192.0.2.0/24` name one block.
fn cidr(q: &str) -> Result<Cidr, Refusal> {
    todo!("rfc 0014")
}

/// The first `name=` value, percent-decoded.
fn param(q: &str, name: &str) -> Result<Option<String>, Refusal> {
    todo!("rfc 0014")
}

fn decode(v: &str) -> Option<String> {
    todo!("rfc 0014")
}

/// RFC 0014 case 12: an arbitrary method, path, query and authorization
/// header, one per line. Never panics.
pub fn fuzz_admin_query(data: &[u8]) {
    let s = String::from_utf8_lossy(data);
    let mut lines = s.splitn(4, '\n');
    let (m, p, q) = (lines.next(), lines.next(), lines.next());
    let _ = parse(m.unwrap_or(""), p.unwrap_or(""), q);
    if let Some(h) = lines.next().and_then(|h| HeaderValue::from_str(h).ok()) {
        let _ = authorized(Some(&h), b"0123456789abcdef0123456789abcdef");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "rfc 0014"]
    fn endpoints_and_parameters() {
        assert_eq!(parse("GET", "/status", None), Ok(Call::Status));
        assert_eq!(
            parse("POST", "/blocks", Some("cidr=192.0.2.7%2F24&ttl=10m")),
            Ok(Call::Block {
                net: "192.0.2.0/24".parse().unwrap(),
                ttl: Some("10m".into())
            })
        );
        assert_eq!(
            parse("DELETE", "/blocks", Some("cidr=2001:db8::1")),
            Ok(Call::Unblock {
                net: "2001:db8::1/128".parse().unwrap()
            })
        );
        let status = |m, p, q| parse(m, p, q).unwrap_err().0;
        assert_eq!(status("POST", "/blocks", None), StatusCode::BAD_REQUEST);
        assert_eq!(
            status("POST", "/blocks", Some("cidr=192.0.2.0/33")),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status("POST", "/blocks", Some("cidr=%zz")),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status("GET", "/reload", None),
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(status("GET", "/x", None), StatusCode::NOT_FOUND);
        let long = "a".repeat(MAX_QUERY + 1);
        assert_eq!(
            status("GET", "/blocks", Some(&long)),
            StatusCode::URI_TOO_LONG
        );
    }

    #[test]
    #[ignore = "rfc 0014"]
    fn bearer_token() {
        let token = b"0123456789abcdef0123456789abcdef";
        let h = |s: &str| HeaderValue::from_str(s).unwrap();
        assert!(!authorized(None, token));
        assert!(!authorized(Some(&h("Bearer nope")), token));
        assert!(!authorized(
            Some(&h("0123456789abcdef0123456789abcdef")),
            token
        ));
        assert!(authorized(
            Some(&h("Bearer 0123456789abcdef0123456789abcdef")),
            token
        ));
        assert!(!authorized(Some(&h("Bearer ")), b""));
    }
}
