//! Client-supplied `content-type`: gRPC detection never panics and only
//! accepts `application/grpc`, optionally followed by `+` or `;`.
#![no_main]

use dvarapala_l7::is_grpc;
use http::{HeaderMap, HeaderValue, header::CONTENT_TYPE};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(v) = HeaderValue::from_bytes(data) else {
        return;
    };
    let mut h = HeaderMap::new();
    h.insert(CONTENT_TYPE, v);
    if is_grpc(&h) {
        assert!(data.len() >= 16 && data[..16].eq_ignore_ascii_case(b"application/grpc"));
        assert!(matches!(data.get(16), None | Some(b'+' | b';')));
    }
});
