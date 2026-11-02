//! RFC 0031 case 3: a MaxMind DB file from arbitrary bytes, then lookups.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dvarapala_l7::fuzz_geoip(data));
