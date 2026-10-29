//! RFC 0012 case 15: the verify query and the pass cookie, both from the
//! client. Never panics.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: (&str, &str)| {
    dvarapala_l7::fuzz_verify(data.0, data.1);
});
