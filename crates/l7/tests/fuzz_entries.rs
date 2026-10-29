//! The `fuzz_*` entry points behind `fuzz/fuzz_targets/`: valid,
//! truncated and garbage inputs never panic.

/// A valid input, every prefix of it, and bytes no parser expects.
fn inputs(valid: &[&[u8]]) -> Vec<Vec<u8>> {
    let mut all = Vec::new();
    for v in valid {
        for n in 0..=v.len() {
            all.push(v[..n].to_vec());
        }
    }
    all.push(vec![0xff; 64]);
    all.push(vec![0; 64]);
    all.push(b"\n\n\n\n".to_vec());
    all
}

// RFC 0013: host and path rules, then a request
#[test]
fn route_match_never_panics() {
    for i in inputs(&[
        b"app.example\n/api/\n/api/v1?x=1\nGET app.example",
        b"*.example\n=/login\nhttp://a.example/login\nPOST a.example:8443",
        b"[2001:db8::1]\n~^/u/[0-9]+$\n/u/42\nDELETE [2001:db8::1]:443",
        b"bad host!\n\nnot a uri\n\x7f",
    ]) {
        dvarapala_l7::fuzz_route_match(&i);
    }
}

// RFC 0014 case 12
#[test]
fn admin_query_never_panics() {
    for i in inputs(&[
        b"GET\n/status\n\nBearer 0123456789abcdef0123456789abcdef",
        b"POST\n/blocks\nnet=192.0.2.0%2F24&ttl=60\nBearer <token>",
        b"DELETE\n/blocks/192.0.2.0%2F24\n%zz\nBasic \x01",
    ]) {
        dvarapala_l7::fuzz_admin_query(&i);
    }
}

// RFC 0012 case 15
#[test]
fn verify_never_panics() {
    let long = format!("r=/{}", "a".repeat(7000));
    for (q, c) in [
        ("t=999990&s=x&n=1&r=%2Fa%3Fb%3D1", "dvarapala_pass=4600.ab"),
        ("t=1&t=2&s=&n=-1&r=//evil.example", "a=1; dvarapala_pass="),
        ("t=99999999999999999999999&n=1", "dvarapala_pass=1.zz"),
        ("r=%zz&r=%2", "\u{7f}"),
        (long.as_str(), ""),
        ("", ""),
    ] {
        dvarapala_l7::fuzz_verify(q, c);
    }
}

// RFC 0017 case 2
#[cfg(feature = "waf")]
#[test]
fn waf_frame_never_panics() {
    // AGENT-HELLO, ACK with a set-var, AGENT-DISCONNECT
    let hello = b"\x65\0\0\0\x01\0\0\x07version\x08\x032.0\x0emax-frame-size\x03\xf0\x0c";
    let ack = b"\x67\0\0\0\x01\x07\x01\x01\x03\x02\x06action\x08\x04deny";
    let bye = b"\x66\0\0\0\x01\0\0\x0bstatus-code\x03\x03\x07message\x08\x03bye";
    for i in inputs(&[
        hello,
        ack,
        bye,
        b"\x67\0\0\0\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
    ]) {
        dvarapala_l7::fuzz_waf_frame(&i);
    }
}

// RFC 0016 case 11
#[cfg(feature = "replay")]
#[test]
fn replay_line_never_panics() {
    for i in inputs(&[
        br#"{"ts":1700000000.5,"client":"192.0.2.7","method":"POST","path":"/a?b=1","xff":"198.51.100.1","headers":{"x-k":"v"},"status":200}"#,
        br#"{"ts":0,"client":"2001:db8::1","ja4":"nope"}"#,
        br#"{"ts":"x","client":"not an ip"}"#,
    ]) {
        dvarapala_l7::fuzz_replay_line(&i);
    }
}

// RFC 0018 case 7
#[cfg(feature = "ui")]
#[test]
fn oidc_callback_never_panics() {
    let claims =
        r#"{"iss":"https://idp.example","aud":["c"],"exp":1,"nonce":"n","sub":"1","groups":["g"]}"#;
    let disco = r#"{"issuer":"https://idp.example","authorization_endpoint":"https://idp.example/a","token_endpoint":"http://idp.example/t"}"#;
    let ok = format!("code=a%2Fb&state=s\n{claims}");
    let disco = format!("state=s\n{disco}");
    for i in inputs(&[
        ok.as_bytes(),
        disco.as_bytes(),
        b"error=access_denied&error_description=no%20way\n{\"id_token\":\"x.y.z\"}",
        b"code=%zz\n{\"aud\":7}",
    ]) {
        dvarapala_l7::fuzz_oidc_callback(&i);
    }
}
