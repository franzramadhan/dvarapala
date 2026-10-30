//! RFC 0023 case 8: an arbitrary model answer, both protocols. Never
//! panics; what passes is one of the labels, bounded.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    dvarapala_l7::fuzz_llm_reply(data);
});
