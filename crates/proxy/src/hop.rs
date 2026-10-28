use std::net::IpAddr;

use http::header::{CONNECTION, HeaderMap, HeaderName, HeaderValue, TE};

/// RFC 9110 section 7.6.1, plus the legacy `proxy-connection`.
const HOP_BY_HOP: [&str; 9] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

const X_FORWARDED_FOR: &str = "x-forwarded-for";

/// Removes hop-by-hop headers (RFC 9110 section 7.6.1): the fixed list and
/// every header named in `Connection`. With `keep_trailers`, a `te` that
/// lists `trailers` becomes `te: trailers` (HTTP/2 upstreams, RFC 0004).
pub(crate) fn strip_hop_by_hop(headers: &mut HeaderMap, keep_trailers: bool) {
    let trailers = keep_trailers
        && headers
            .get_all(TE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .any(|t| {
                let name = t.split(';').next().unwrap_or_default();
                name.trim().eq_ignore_ascii_case("trailers")
            });
    let listed: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in listed {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
    if trailers {
        headers.insert(TE, HeaderValue::from_static("trailers"));
    }
}

/// The entry of `allowed` that an HTTP/1.1 upgrade request asks for:
/// `Connection` lists `upgrade` and `Upgrade` names that protocol
/// (RFC 0005). Other requests and protocols get `None`.
#[allow(dead_code)] // called from reverse.rs once implemented
pub(crate) fn allowed_upgrade<'a>(_headers: &HeaderMap, _allowed: &'a [String]) -> Option<&'a str> {
    todo!("rfc 0005")
}

/// Appends `peer` to `X-Forwarded-For`, keeping earlier hops.
pub(crate) fn append_forwarded_for(headers: &mut HeaderMap, peer: IpAddr) {
    let mut value: Vec<u8> = Vec::new();
    for v in headers.get_all(X_FORWARDED_FOR) {
        value.extend_from_slice(v.as_bytes());
        value.extend_from_slice(b", ");
    }
    value.extend_from_slice(peer.to_canonical().to_string().as_bytes());
    // earlier values were valid header bytes, and an address adds only ASCII
    if let Ok(v) = HeaderValue::from_bytes(&value) {
        headers.insert(X_FORWARDED_FOR, v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn strips_fixed_and_connection_listed_headers() {
        let mut h = HeaderMap::new();
        for (k, v) in [
            ("connection", "keep-alive, x-secret-hop"),
            ("keep-alive", "timeout=5"),
            ("te", "trailers"),
            ("transfer-encoding", "chunked"),
            ("upgrade", "h2c"),
            ("proxy-authorization", "Basic <token>"),
            ("x-secret-hop", "1"),
            ("x-end-to-end", "kept"),
        ] {
            h.append(k, HeaderValue::from_static(v));
        }
        strip_hop_by_hop(&mut h, false);
        assert_eq!(h.len(), 1);
        assert_eq!(h["x-end-to-end"], "kept");
    }

    /// RFC 0004 case 5
    #[test]
    fn http2_upstream_keeps_te_trailers_only() {
        let mut h = HeaderMap::new();
        h.append("te", HeaderValue::from_static("trailers"));
        h.append("te", HeaderValue::from_static("gzip"));
        strip_hop_by_hop(&mut h, true);
        assert_eq!(h.get_all("te").iter().collect::<Vec<_>>(), ["trailers"]);
        let mut h = HeaderMap::new();
        h.append("te", HeaderValue::from_static("gzip, trailers;q=0.5"));
        strip_hop_by_hop(&mut h, true);
        assert_eq!(h.get_all("te").iter().collect::<Vec<_>>(), ["trailers"]);
        let mut h = HeaderMap::new();
        h.append("te", HeaderValue::from_static("gzip"));
        strip_hop_by_hop(&mut h, true);
        assert!(h.get("te").is_none());
    }

    /// RFC 0004 case 6
    #[test]
    fn http1_upstream_strips_te_trailers() {
        let mut h = HeaderMap::new();
        h.append("te", HeaderValue::from_static("trailers"));
        strip_hop_by_hop(&mut h, false);
        assert!(h.get("te").is_none());
    }

    /// RFC 0005 case 5, plus the allow list
    #[test]
    #[ignore = "rfc 0005"]
    fn only_allowed_upgrades_pass() {
        let ws = ["websocket".to_owned()];
        let mut h = HeaderMap::new();
        h.insert("connection", HeaderValue::from_static("Upgrade"));
        h.insert("upgrade", HeaderValue::from_static("h2c"));
        assert_eq!(allowed_upgrade(&h, &ws), None);
        strip_hop_by_hop(&mut h, false);
        assert!(h.is_empty());
        h.insert(
            "connection",
            HeaderValue::from_static("keep-alive, Upgrade"),
        );
        h.insert("upgrade", HeaderValue::from_static("h2c, WebSocket"));
        assert_eq!(allowed_upgrade(&h, &ws), Some("websocket"));
        assert_eq!(allowed_upgrade(&h, &[]), None);
        // `Upgrade` alone, without `Connection: upgrade`, is not a request
        h.remove("connection");
        assert_eq!(allowed_upgrade(&h, &ws), None);
    }

    #[test]
    fn appends_to_existing_forwarded_for() {
        let mut h = HeaderMap::new();
        append_forwarded_for(&mut h, "192.0.2.10".parse().unwrap());
        assert_eq!(h["x-forwarded-for"], "192.0.2.10");
        append_forwarded_for(&mut h, "2001:db8::1".parse().unwrap());
        assert_eq!(h["x-forwarded-for"], "192.0.2.10, 2001:db8::1");
    }
}
