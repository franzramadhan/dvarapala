//! RFC 0013 case 13: host and path rules and the request they are matched
//! against, all arbitrary. Never panics.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    dvarapala_l7::fuzz_route_match(data);
});
