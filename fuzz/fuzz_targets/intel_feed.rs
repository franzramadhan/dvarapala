//! RFC 0031 case 3: feed bodies come from third parties. Never panic,
//! never more entries than the cap, and every parsed network is in the
//! set built from it.
#![no_main]

use dvarapala_engine::{PrefixSet, parse_feed};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|body: &str| {
    let Ok(nets) = parse_feed(body, 64) else {
        return;
    };
    assert!(nets.len() <= 64);
    let set = PrefixSet::new(nets.iter().copied());
    assert!(set.len() <= nets.len());
    for n in &nets {
        assert!(set.contains(n.addr()));
    }
});
