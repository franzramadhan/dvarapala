//! Admin API requests (RFC 0014): the endpoint, its parameters and the
//! bearer token check. Serving them is the binary's job.

use dvarapala_engine::Cidr;
use http::header::COOKIE;
use http::{HeaderMap, HeaderValue, StatusCode};

use crate::session::same;

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
    /// RFC 0021: the running config, redacted.
    Config,
    /// RFC 0021: the WAF settings, matched rules and rule files.
    Waf,
    /// RFC 0021: the Prometheus text.
    Metrics,
    /// RFC 0021: `observe` or `enforce` for one layer until the next reload.
    Mode {
        layer: ModeLayer,
        enforce: bool,
    },
    /// RFC 0022: the traffic history over `range` seconds.
    History {
        range_secs: u64,
    },
    /// RFC 0023: the sampling switch and the recent labels.
    Llm,
    /// RFC 0023: `on` for this long (`""` for the default), `None` stops.
    LlmSwitch {
        on: Option<String>,
    },
}

/// The ranges `GET /history` takes (RFC 0022), as `range=` names them.
pub const HISTORY_RANGES: [(&str, u64); 5] = [
    ("15m", 15 * 60),
    ("1h", 3_600),
    ("6h", 6 * 3_600),
    ("24h", 24 * 3_600),
    ("7d", 7 * 24 * 3_600),
];

/// A layer with an `observe` mode the console can switch (RFC 0021).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeLayer {
    Detection,
    Waf,
}

impl ModeLayer {
    pub fn name(self) -> &'static str {
        match self {
            Self::Detection => "detection",
            Self::Waf => "waf",
        }
    }
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
        ("/config", "GET") => Call::Config,
        ("/waf", "GET") => Call::Waf,
        ("/metrics", "GET") => Call::Metrics,
        ("/mode", "POST") => mode(q)?,
        ("/history", "GET") => history(q)?,
        ("/llm", "GET") => Call::Llm,
        ("/llm", "POST") => llm(q)?,
        (
            "/status" | "/top" | "/reload" | "/blocks" | "/config" | "/waf" | "/metrics" | "/mode"
            | "/history" | "/llm",
            _,
        ) => {
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
    !token.is_empty() && same(given, token)
}

/// The `name` cookie from `Cookie` headers.
pub fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .flat_map(|h| h.split(';'))
        .find_map(|kv| kv.trim().split_once('=').filter(|(k, _)| *k == name))
        .map(|(_, v)| v)
}

/// The CSRF header a cookie session's state changing call carries
/// (RFC 0018), compared in constant time.
pub fn csrf_ok(header: Option<&HeaderValue>, expected: &str) -> bool {
    header.is_some_and(|h| !expected.is_empty() && same(h.as_bytes(), expected.as_bytes()))
}

/// `https`, or `http` to a loopback host (a local IdP, tests).
pub fn secure_url(url: &str) -> bool {
    if url.starts_with("https://") {
        return true;
    }
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let auth = rest.split(['/', '?', '#']).next().unwrap_or("");
    if auth.contains('@') {
        return false;
    }
    let host = if auth.starts_with('[') {
        auth.split_inclusive(']').next().unwrap_or("")
    } else {
        auth.split(':').next().unwrap_or("")
    };
    matches!(host, "localhost" | "127.0.0.1" | "[::1]")
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

/// `layer=<detection|waf>&mode=<observe|enforce>`, both required.
fn mode(q: &str) -> Result<Call, Refusal> {
    let bad = |m: &str| (StatusCode::BAD_REQUEST, m.to_owned());
    let layer = match param(q, "layer")?.as_deref() {
        Some("detection") => ModeLayer::Detection,
        Some("waf") => ModeLayer::Waf,
        _ => return Err(bad("layer is \"detection\" or \"waf\"")),
    };
    let enforce = match param(q, "mode")?.as_deref() {
        Some("observe") => false,
        Some("enforce") => true,
        _ => return Err(bad("mode is \"observe\" or \"enforce\"")),
    };
    Ok(Call::Mode { layer, enforce })
}

/// `range=<15m|1h|6h|24h|7d>`, `15m` when absent.
fn history(q: &str) -> Result<Call, Refusal> {
    let range = param(q, "range")?;
    let name = range.as_deref().unwrap_or("15m");
    match HISTORY_RANGES.iter().find(|(n, _)| *n == name) {
        Some(&(_, range_secs)) => Ok(Call::History { range_secs }),
        None => Err((
            StatusCode::BAD_REQUEST,
            "range is one of 15m, 1h, 6h, 24h, 7d".into(),
        )),
    }
}

/// `on=<duration>`, `on` alone for the default, or `off`.
fn llm(q: &str) -> Result<Call, Refusal> {
    let has = |k: &str| q.split('&').any(|kv| kv.split('=').next() == Some(k));
    match (has("on"), has("off")) {
        (true, false) => Ok(Call::LlmSwitch {
            on: Some(param(q, "on")?.unwrap_or_default()),
        }),
        (false, true) => Ok(Call::LlmSwitch { on: None }),
        _ => Err((StatusCode::BAD_REQUEST, "use on=<duration> or off".into())),
    }
}

/// The first `name=` value, percent-decoded.
pub(crate) fn param(q: &str, name: &str) -> Result<Option<String>, Refusal> {
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

    // RFC 0022 case 9 (parsing)
    #[test]
    fn history_ranges() {
        assert_eq!(
            parse("GET", "/history", None),
            Ok(Call::History { range_secs: 900 })
        );
        assert_eq!(
            parse("GET", "/history", Some("range=7d")),
            Ok(Call::History {
                range_secs: 604_800
            })
        );
        let (status, msg) = parse("GET", "/history", Some("range=2d")).unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(msg.contains("15m, 1h, 6h, 24h, 7d"), "{msg}");
        assert_eq!(
            parse("POST", "/history", None).unwrap_err().0,
            StatusCode::METHOD_NOT_ALLOWED
        );
    }

    // RFC 0021 case 13 (parsing)
    #[test]
    fn mode_switch_queries() {
        assert_eq!(parse("GET", "/config", None), Ok(Call::Config));
        assert_eq!(parse("GET", "/waf", None), Ok(Call::Waf));
        assert_eq!(parse("GET", "/metrics", None), Ok(Call::Metrics));
        assert_eq!(
            parse("POST", "/mode", Some("layer=waf&mode=observe")),
            Ok(Call::Mode {
                layer: ModeLayer::Waf,
                enforce: false
            })
        );
        assert_eq!(
            parse("POST", "/mode", Some("mode=enforce&layer=detection")),
            Ok(Call::Mode {
                layer: ModeLayer::Detection,
                enforce: true
            })
        );
        let status = |q| parse("POST", "/mode", q).unwrap_err().0;
        for q in [
            Some("layer=xdp&mode=observe"),
            Some("layer=waf&mode=off"),
            Some("layer=waf"),
            Some("mode=observe"),
            None,
        ] {
            assert_eq!(status(q), StatusCode::BAD_REQUEST, "{q:?}");
        }
        assert_eq!(
            parse("GET", "/mode", None).unwrap_err().0,
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            parse("POST", "/config", None).unwrap_err().0,
            StatusCode::METHOD_NOT_ALLOWED
        );
    }

    // RFC 0023 (parsing)
    #[test]
    fn llm_switch_queries() {
        assert_eq!(parse("GET", "/llm", None), Ok(Call::Llm));
        let on = |q| parse("POST", "/llm", Some(q));
        assert_eq!(
            on("on=5m"),
            Ok(Call::LlmSwitch {
                on: Some("5m".into())
            })
        );
        assert_eq!(
            on("on"),
            Ok(Call::LlmSwitch {
                on: Some("".into())
            })
        );
        assert_eq!(on("off"), Ok(Call::LlmSwitch { on: None }));
        for q in ["", "on=5m&off", "x=1"] {
            assert_eq!(on(q).unwrap_err().0, StatusCode::BAD_REQUEST, "{q}");
        }
        assert_eq!(
            parse("DELETE", "/llm", None).unwrap_err().0,
            StatusCode::METHOD_NOT_ALLOWED
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

    #[test]
    fn cookie_and_csrf() {
        let mut m = HeaderMap::new();
        m.append(
            COOKIE,
            HeaderValue::from_static("a=1; dvarapala_session=abc"),
        );
        m.append(COOKIE, HeaderValue::from_static("b=2"));
        assert_eq!(cookie(&m, "dvarapala_session"), Some("abc"));
        assert_eq!(cookie(&m, "b"), Some("2"));
        assert_eq!(cookie(&m, "c"), None);
        let h = HeaderValue::from_static("x1");
        assert!(csrf_ok(Some(&h), "x1"));
        assert!(!csrf_ok(Some(&h), "x2"));
        assert!(!csrf_ok(None, "x1"));
        assert!(!csrf_ok(Some(&HeaderValue::from_static("")), ""));
    }
}
