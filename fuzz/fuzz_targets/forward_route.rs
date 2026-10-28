//! Attacker-controlled request targets in forward mode (RFC 0007): never
//! panic, and only a listed host and port ever match.
#![no_main]

use dvarapala_proxy::Routes;
use http::{Method, Uri};
use libfuzzer_sys::fuzz_target;

const ORIGINS: [&str; 2] = ["https://api.example", "http://192.0.2.1:8080"];
const LISTED: [(&str, u16); 2] = [("api.example", 443), ("192.0.2.1", 8080)];

fuzz_target!(|data: &[u8]| {
    let Ok(uri) = Uri::try_from(data) else {
        return;
    };
    let routes = Routes::new(ORIGINS).unwrap();
    for method in [Method::GET, Method::CONNECT] {
        if let Some(i) = routes.find(&method, &uri) {
            let a = uri.authority().unwrap();
            let (host, port) = LISTED[i];
            assert!(a.host().eq_ignore_ascii_case(host), "{uri}");
            assert!(!a.as_str().contains('@'), "{uri}");
            if let Some(p) = a.port_u16() {
                assert_eq!(p, port, "{uri}");
            }
        }
    }
});
