use std::net::IpAddr;

use http::header::{CONNECTION, HeaderMap, HeaderName, HeaderValue};

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
/// every header named in `Connection`.
pub(crate) fn strip_hop_by_hop(headers: &mut HeaderMap) {
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
        strip_hop_by_hop(&mut h);
        assert_eq!(h.len(), 1);
        assert_eq!(h["x-end-to-end"], "kept");
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
