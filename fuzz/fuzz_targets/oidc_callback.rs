//! RFC 0018 case 7: an arbitrary OIDC callback query and ID token payload.
//! Never panics.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    dvarapala_l7::fuzz_oidc_callback(data);
});
