use std::net::IpAddr;

use http::HeaderMap;

/// Removes hop-by-hop headers (RFC 9110 section 7.6.1): the fixed list and
/// every header named in `Connection`.
pub(crate) fn strip_hop_by_hop(_headers: &mut HeaderMap) {
    todo!("rfc 0001")
}

/// Appends `peer` to `X-Forwarded-For`, keeping earlier hops.
pub(crate) fn append_forwarded_for(_headers: &mut HeaderMap, _peer: IpAddr) {
    todo!("rfc 0001")
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    #[ignore = "rfc 0001 case 13"]
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
    #[ignore = "rfc 0001"]
    fn appends_to_existing_forwarded_for() {
        let mut h = HeaderMap::new();
        append_forwarded_for(&mut h, "192.0.2.10".parse().unwrap());
        assert_eq!(h["x-forwarded-for"], "192.0.2.10");
        append_forwarded_for(&mut h, "2001:db8::1".parse().unwrap());
        assert_eq!(h["x-forwarded-for"], "192.0.2.10, 2001:db8::1");
    }
}
