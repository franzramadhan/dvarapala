//! RFC 0017: an arbitrary frame from the agent. Never panics, never
//! reads past the frame.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    dvarapala_l7::fuzz_waf_frame(data);
});
