//! RFC 0030 case 4: the PROXY protocol parser on arbitrary bytes never
//! panics, never claims a header past the input or over the caps, and
//! never asks for more bytes than a header can hold.
#![no_main]

use dvarapala_l4::proxy_protocol::{MAX_V1, MAX_V2, Parsed, Version, parse};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for v in [Version::V1, Version::V2, Version::Any] {
        match parse(data, v) {
            Ok(Parsed::Done { len, .. }) => {
                assert!(len <= data.len() && len <= MAX_V2.max(MAX_V1));
            }
            Ok(Parsed::Incomplete(n)) => {
                assert!(n > 0 && data.len() + n <= MAX_V2.max(MAX_V1));
            }
            Err(_) => {}
        }
    }
});
