//! RFC 0016 case 11: an arbitrary access log line. Never panics.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    dvarapala_l7::fuzz_replay_line(data);
});
