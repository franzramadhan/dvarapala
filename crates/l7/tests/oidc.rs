//! RFC 0018: discovery and ID token checks through the public API.
#![cfg(feature = "ui")]

use dvarapala_l7::{Denied, OidcConfig, check_id_token, provider};

const ISS: &str = "https://idp.example";

#[test]
fn discovery_needs_both_endpoints() {
    let doc =
        br#"{"issuer":"https://idp.example","authorization_endpoint":"https://idp.example/a"}"#;
    assert_eq!(
        provider(doc, ISS),
        Err("discovery: no token_endpoint".into())
    );
    assert!(provider(b"not json", ISS).is_err());
}

#[test]
fn audience_of_another_type_is_refused() {
    let cfg = OidcConfig {
        issuer: ISS.into(),
        client_id: "dvarapala".into(),
        ..OidcConfig::default()
    };
    // {"iss":"https://idp.example","aud":7,"exp":2000,"nonce":"n"}
    let payload =
        "eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwiYXVkIjo3LCJleHAiOjIwMDAsIm5vbmNlIjoibiJ9";
    assert_eq!(
        check_id_token(&cfg, &format!("e30.{payload}.c2ln"), "n", 1000),
        Err(Denied::Invalid("aud mismatch".into()))
    );
}
