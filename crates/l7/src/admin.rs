//! Admin API requests (RFC 0014): the endpoint, its parameters and the
//! bearer token check. Serving them is the binary's job.

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
    let q = query.unwrap_or("");
    if q.len() > MAX_QUERY {
        return Err((StatusCode::URI_TOO_LONG, "query over 1 KiB".into()));
    }
    Ok(match (path, method) {
        ("/status", "GET") => Call::Status,
        ("/top", "GET") => Call::Top,
        ("/reload", "POST") => Call::Reload,
        ("/blocks", "GET") => Call::Blocks,
        ("/blocks", "POST") => Call::Block {
            net: cidr(q)?,
            ttl: param(q, "ttl")?,
        },
        ("/blocks", "DELETE") => Call::Unblock { net: cidr(q)? },
        ("/status" | "/top" | "/reload" | "/blocks", _) => {
            return Err((StatusCode::METHOD_NOT_ALLOWED, "method not allowed".into()));
        }
        _ => return Err((StatusCode::NOT_FOUND, "no such endpoint".into())),
    })
}

/// `Authorization: Bearer <token>`, compared in constant time for a given
/// length. An empty token never matches.
pub fn authorized(header: Option<&HeaderValue>, token: &[u8]) -> bool {
    let Some(given) = header.and_then(|h| h.as_bytes().strip_prefix(b"Bearer ")) else {
        return false;
    };
    if token.is_empty() || given.len() != token.len() {
        return false;
    }
    let diff = given.iter().zip(token).fold(0u8, |d, (a, b)| d | (a ^ b));
    std::hint::black_box(diff) == 0
}

/// `cidr=<net>`, required, host bits cleared so that `192.0.2.7/24` and
/// `192.0.2.0/24` name one block.
fn cidr(q: &str) -> Result<Cidr, Refusal> {
    let bad = |m: String| (StatusCode::BAD_REQUEST, m);
    let s = param(q, "cidr")?.ok_or_else(|| bad("cidr is required".into()))?;
    let c: Cidr = s
        .parse()
        .map_err(|e: dvarapala_engine::CidrError| bad(e.to_string()))?;
    Ok(Cidr::of(c.addr(), c.prefix()))
}

/// The first `name=` value, percent-decoded.
fn param(q: &str, name: &str) -> Result<Option<String>, Refusal> {
    let Some(v) = q
        .split('&')
        .find_map(|kv| kv.split_once('=').filter(|(k, _)| *k == name))
        .map(|(_, v)| v)
    else {
        return Ok(None);
    };
    decode(v).map(Some).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!("{name}: bad percent escape"),
        )
    })
}

fn decode(v: &str) -> Option<String> {
    let b = v.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
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
