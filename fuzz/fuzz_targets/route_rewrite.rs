//! RFC 0019 case 11 and RFC 0025 case 15: arbitrary route JSON, label
//! values and `rules` annotations through the route rewrite. Never panics,
//! and a rewritten route rewrites to itself.
#![no_main]

use dvarapala_operator::routes::{self, Kind};
use libfuzzer_sys::fuzz_target;

/// Splits at the first 0 byte; all of `b` when there is none.
fn field(b: &[u8]) -> (&[u8], &[u8]) {
    match b.iter().position(|&x| x == 0) {
        Some(i) => (&b[..i], &b[i + 1..]),
        None => (&[][..], b),
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&k, rest)) = data.split_first() else { return };
    let (label, rest) = field(rest);
    let (rules, json) = field(rest);
    let Ok(mut route) = serde_json::from_slice::<serde_json::Value>(json) else { return };
    if !rules.is_empty() {
        if let Some(meta) = route.get_mut("metadata").and_then(|m| m.as_object_mut()) {
            let rules = String::from_utf8_lossy(rules).into_owned();
            meta.insert("annotations".into(), serde_json::json!({ routes::RULES: rules }));
        }
    }
    let kind = [Kind::Ingress, Kind::HttpRoute, Kind::GrpcRoute][usize::from(k % 3)];
    let label = String::from_utf8_lossy(label);
    let policy = routes::policy(Some(&label), None);
    let exists = |g: &str| g.len() % 2 == 0;
    let _ = routes::backends(kind, &route, "shop");
    let _ = routes::unknown_rules(kind, &route);
    let once = routes::rewrite(kind, &route, "shop", policy, &exists);
    let twice = routes::rewrite(kind, &once, "shop", policy, &exists);
    assert_eq!(once, twice);
});
