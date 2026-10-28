//! RFC 0011 case 2: the XDP parser on arbitrary frames never panics and
//! never reads past the end (the slice reader checks every access).
#![no_main]

use dvarapala_xdp_common::parse;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(p) = parse(data) {
        assert!(data.len() >= 14 + 20 + 4, "a port needs headers");
        let _ = p.dst_port;
    }
});
