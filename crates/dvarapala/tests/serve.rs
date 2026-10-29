//! `serve` end to end: the metrics listener, forward mode and the
//! warnings for keys that have no effect.
#![cfg(unix)]

#[allow(dead_code)]
mod proc;
mod stop;

use proc::{get, port, serve, wait_port};

const TOKEN: &str = "0123456789abcdef0123456789abcdef";

// the config from the environment alone, as `serve` without --config
#[test]
fn metrics_listener_serves_the_text_format() {
    let (listen, metrics) = (port(), port());
    let (l, m) = (
        format!("127.0.0.1:{listen}"),
        format!("127.0.0.1:{metrics}"),
    );
    let p = serve(
        "metrics",
        None,
        &[
            ("DVARAPALA__LISTEN", &l),
            ("DVARAPALA__UPSTREAM", "http://127.0.0.1:1"),
            ("DVARAPALA__UPSTREAM_PROTOCOL", "http2"),
            ("DVARAPALA__METRICS__LISTEN", &m),
        ],
    );
    p.logged(&["proxy listening", "Http2"]);
    wait_port(listen);
    // the upstream refuses connections
    assert_eq!(get(listen, "GET", "/", &[]).0, 502);
    let (status, body) = get(metrics, "GET", "/metrics", &[]);
    assert_eq!(status, 200);
    assert!(
        body.contains("dvarapala_requests_total{verdict=\"allow\""),
        "{body}"
    );
    assert_eq!(get(metrics, "GET", "/other", &[]).0, 404);
    let (code, log) = p.stop();
    assert_eq!(code, Some(0), "{log}");
    assert!(log.contains("shutting down, draining connections"), "{log}");
    assert!(log.contains("stopped"), "{log}");
}

// RFC 0007: forward mode, with the admin API in front of no limiter
#[test]
fn forward_mode_shapes_listed_destinations_only() {
    let (listen, admin) = (port(), port());
    let toml = format!(
        "mode = \"forward\"\nlisten = \"127.0.0.1:{listen}\"\n\
         [metrics]\nlisten = \"\"\n\
         [admin]\nlisten = \"127.0.0.1:{admin}\"\ntoken = \"{TOKEN}\"\n\
         [[forward.destinations]]\nname = \"local\"\norigin = \"http://127.0.0.1:1\"\nrate = 100\n"
    );
    let p = serve("forward", Some(&toml), &[]);
    p.logged(&["forward proxy listening", "local"]);
    wait_port(listen);
    assert_eq!(get(listen, "GET", "http://127.0.0.1:1/", &[]).0, 502);
    assert_eq!(get(listen, "GET", "http://192.0.2.1/", &[]).0, 403);
    wait_port(admin);
    let auth = format!("Authorization: Bearer {TOKEN}");
    let (status, body) = get(admin, "GET", "/status", &[&auth]);
    assert_eq!(status, 200);
    assert!(body.contains("\"mode\":\"forward\""), "{body}");
    assert!(body.contains("\"clients\":0"), "{body}");
    // no rate limiter in forward mode: nothing to list or block
    let (status, body) = get(admin, "GET", "/top", &[&auth]);
    assert_eq!(status, 503);
    assert!(body.contains("rate limiter is off"), "{body}");
    let (code, log) = p.stop();
    assert_eq!(code, Some(0), "{log}");
    assert!(log.contains("stopped"), "{log}");
}

// keys that only work inside the reverse proxy's rate limiter
#[test]
fn keys_without_the_rate_limiter_warn() {
    let listen = port();
    let toml = format!(
        "listen = \"127.0.0.1:{listen}\"\nupstream = \"http://127.0.0.1:1\"\n\
         upstream_protocol = \"auto\"\n\
         [metrics]\nlisten = \"\"\n\
         [rate_limit]\nenabled = false\n\
         [challenge]\nmode = \"always\"\n\
         [store]\nbackend = \"redis\"\nurl = \"redis://127.0.0.1:1/0\"\n"
    );
    let p = serve("warn", Some(&toml), &[]);
    p.logged(&["proxy listening", "Auto"]);
    for warning in [
        "challenge, fingerprint and routes run inside the reverse proxy's rate limiter, which is off",
        "challenge.secret is empty: passes from one replica fail on the others",
        "store shares the rate limiter's counts, which is off",
        "detection and scoring run inside the rate limiter, which is off",
    ] {
        p.logged(&["WARN", warning]);
    }
    wait_port(listen);
    // no limiter, so no challenge page: the request goes to the upstream
    assert_eq!(get(listen, "GET", "/", &[]).0, 502);
}
