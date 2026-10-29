//! RFC 0019 case 11: arbitrary route JSON and label values through the
//! route rewrite. Never panics, and a rewritten route rewrites to itself.
#![no_main]

use dvarapala_operator::routes::{self, Kind};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&k, rest)) = data.split_first() else { return };
    let (label, json) = match rest.iter().position(|&b| b == 0) {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (&[][..], rest),
    };
    let Ok(route) = serde_json::from_slice::<serde_json::Value>(json) else { return };
    let kind = [Kind::Ingress, Kind::HttpRoute, Kind::GrpcRoute][usize::from(k % 3)];
    let label = String::from_utf8_lossy(label);
    let policy = routes::policy(Some(&label), None);
    let exists = |g: &str| g.len() % 2 == 0;
    let _ = routes::backends(kind, &route, "shop");
    let once = routes::rewrite(kind, &route, "shop", policy, &exists);
    let twice = routes::rewrite(kind, &once, "shop", policy, &exists);
    assert_eq!(once, twice);
});
