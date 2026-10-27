//! Attacker-controlled `X-Forwarded-For` and config-controlled CIDRs: never
//! panic, and an untrusted peer always keys on itself.
#![no_main]

use std::net::{IpAddr, Ipv4Addr};

use dvarapala_engine::{Cidr, ClientKey, TrustedProxies, client_key};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: (&str, &str)| {
    let (xff, cidr) = data;
    let trusted = TrustedProxies::new(cidr.parse::<Cidr>().into_iter().collect());

    let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let key = client_key(peer, Some(xff), &trusted);
    if !trusted.contains(peer) {
        assert_eq!(key, ClientKey::from(peer));
    }
    let _ = key.to_string();
});
