//! RFC 0014 case 12: an arbitrary admin method, path, query and
//! authorization header. Never panics.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    dvarapala_l7::fuzz_admin_query(data);
});
