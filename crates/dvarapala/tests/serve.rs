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

// RFC 0032 cases 3 and 11: a fixed limit sheds past it, a route bypasses it
#[test]
fn a_fixed_concurrency_limit_sheds() {
    // an upstream that takes connections and never answers
    let up = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream = up.local_addr().unwrap().port();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for c in up.incoming() {
            let _ = tx.send(c.is_ok());
            held.push(c);
        }
    });
    let (listen, metrics) = (port(), port());
    let toml = format!(
        "listen = \"127.0.0.1:{listen}\"\nupstream = \"http://127.0.0.1:{upstream}\"\n\
         [metrics]\nlisten = \"127.0.0.1:{metrics}\"\n\
         [concurrency]\nmode = \"fixed\"\nlimit = 1\nreserve = 0.0\n\
         [[routes]]\nname = \"health\"\npath = \"/healthz\"\nconcurrency = false\n"
    );
    let p = serve("concurrency", Some(&toml), &[]);
    wait_port(listen);
    std::thread::spawn(move || get(listen, "GET", "/slow", &[]));
    assert!(rx.recv().unwrap(), "the first request reached the upstream");
    assert_eq!(get(listen, "GET", "/", &[]).0, 503);
    // the bypassing route still reaches the (silent) upstream
    std::thread::spawn(move || get(listen, "GET", "/healthz", &[]));
    assert!(
        rx.recv().unwrap(),
        "the bypassing route reached the upstream"
    );
    let (_, body) = get(metrics, "GET", "/metrics", &[]);
    assert!(
        body.contains("dvarapala_concurrency_shed_total{class=\"normal\"} 1"),
        "{body}"
    );
    assert!(body.contains("dvarapala_concurrency_limit 1"), "{body}");
    p.logged(&["WARN", "concurrency shedding"]);
}

/// The value of the `name` series whose labels include all of `labels`.
fn series(body: &str, name: &str, labels: &[&str]) -> Option<String> {
    body.lines()
        .filter(|l| l.starts_with(&format!("{name}{{")))
        .find(|l| labels.iter().all(|x| l.contains(x)))
        .and_then(|l| l.rsplit(' ').next())
        .map(str::to_owned)
}

// handles registered while the layers are built bind to the recorder that
// exists then: it must be installed first
#[test]
fn route_metrics_reach_the_exporter() {
    let (listen, metrics) = (port(), port());
    let toml = format!(
        "listen = \"127.0.0.1:{listen}\"\nupstream = \"http://127.0.0.1:1\"\n\
         [metrics]\nlisten = \"127.0.0.1:{metrics}\"\n\
         [[routes]]\nname = \"login\"\npath = \"/login\"\nrate = 100\n"
    );
    let p = serve("route-metrics", Some(&toml), &[]);
    wait_port(listen);
    assert_eq!(get(listen, "GET", "/login", &[]).0, 502);
    let (_, body) = get(metrics, "GET", "/metrics", &[]);
    let allow = ["route=\"login\"", "verdict=\"allow\""];
    assert_eq!(
        series(&body, "dvarapala_route_requests_total", &allow).as_deref(),
        Some("1"),
        "{body}"
    );
    assert_eq!(
        series(&body, "dvarapala_route_keys", &["route=\"login\""]).as_deref(),
        Some("1"),
        "{body}"
    );
    let (code, log) = p.stop();
    assert_eq!(code, Some(0), "{log}");
}

// the shapers are built once, before the listener, and never on reload
#[test]
fn egress_metrics_reach_the_exporter() {
    let (listen, metrics) = (port(), port());
    let toml = format!(
        "mode = \"forward\"\nlisten = \"127.0.0.1:{listen}\"\n\
         [metrics]\nlisten = \"127.0.0.1:{metrics}\"\n\
         [[forward.destinations]]\nname = \"local\"\norigin = \"http://127.0.0.1:1\"\nrate = 100\n"
    );
    let p = serve("egress-metrics", Some(&toml), &[]);
    wait_port(listen);
    assert_eq!(get(listen, "GET", "http://127.0.0.1:1/", &[]).0, 502);
    let (_, body) = get(metrics, "GET", "/metrics", &[]);
    let local = "destination=\"local\"";
    assert_eq!(
        series(
            &body,
            "dvarapala_egress_requests_total",
            &[local, "result=\"sent\""]
        )
        .as_deref(),
        Some("1"),
        "{body}"
    );
    for gauge in ["dvarapala_egress_queue", "dvarapala_egress_in_flight"] {
        assert_eq!(
            series(&body, gauge, &[local]).as_deref(),
            Some("0"),
            "{body}"
        );
    }
    let (code, log) = p.stop();
    assert_eq!(code, Some(0), "{log}");
}
