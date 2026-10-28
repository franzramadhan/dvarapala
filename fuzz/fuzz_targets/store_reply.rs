//! RFC 0010 case 14: Redis replies come from the network. Decoding any
//! reply for a batch never panics.
#![no_main]

use std::net::{IpAddr, Ipv4Addr};

use dvarapala_engine::{Batch, ClientKey};
use dvarapala_store::decode;
use libfuzzer_sys::fuzz_target;
use redis::Value;

fuzz_target!(|data: &[u8]| {
    let Some((&n, resp)) = data.split_first() else {
        return;
    };
    let batch = Batch {
        counts: (0..n % 8)
            .map(|i| (ClientKey::from(IpAddr::V4(Ipv4Addr::new(192, 0, 2, i))), 1))
            .collect(),
        ..Batch::default()
    };
    if let Ok(v) = redis::parse_redis_value(resp) {
        let values = match v {
            Value::Array(values) => values,
            other => vec![other],
        };
        let _ = decode(values, &batch);
    }
});
