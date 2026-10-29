//! RFC 0012 case 14: an attacker's ClientHello. Never panics; a result is
//! always a 36-character JA4.
#![no_main]

use dvarapala_proxy::tls::ja4::from_handshake;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(f) = from_handshake(data) {
        assert_eq!(f.as_str().len(), 36);
    }
});
