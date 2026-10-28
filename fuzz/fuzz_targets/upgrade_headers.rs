//! RFC 0005: `Connection` and `Upgrade` values from the client, split at
//! the first newline. An upgrade is only ever one of the allowed protocols.
#![no_main]

use dvarapala_proxy::allowed_upgrade;
use http::{HeaderMap, HeaderValue};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut values = data.splitn(2, |b| *b == b'\n');
    let mut h = HeaderMap::new();
    for name in ["connection", "upgrade"] {
        if let Some(Ok(v)) = values.next().map(HeaderValue::from_bytes) {
            h.append(name, v);
        }
    }
    let allowed = ["websocket".to_owned()];
    if let Some(p) = allowed_upgrade(&h, &allowed) {
        assert_eq!(p, "websocket");
    }
});
