//! RFC 0022 cases 6 to 9 and 11 against the running binary.
#![cfg(unix)]

#[allow(dead_code)]
mod proc;
mod stop;

use std::time::Duration;

use proc::{get, port, run, serve, temp, wait_port};

const TOKEN: &str = "0123456789abcdef0123456789abcdef";

fn toml(listen: u16, admin: u16, extra: &str) -> String {
    format!(
        "listen = \"127.0.0.1:{listen}\"\nupstream = \"http://127.0.0.1:1\"\n{extra}\n\
         [metrics]\nlisten = \"\"\n\
         [admin]\nlisten = \"127.0.0.1:{admin}\"\ntoken = \"{TOKEN}\"\n\
         [history]\ninterval = \"1s\"\n"
    )
}

fn auth() -> String {
    format!("Authorization: Bearer {TOKEN}")
}

// RFC 0022 cases 7, 8 and 9
#[test]
#[ignore = "rfc 0022"]
fn history_answers_from_memory() {
    let (listen, admin) = (port(), port());
    let p = serve("history", Some(&toml(listen, admin, "")), &[]);
    wait_port(admin);
    for _ in 0..5 {
        get(listen, "GET", "/", &[]);
    }
    // two samples need three ticks of 1 s
    std::thread::sleep(Duration::from_millis(3_200));
    let (status, body) = get(admin, "GET", "/history", &[&auth()]);
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["source"], "memory");
    assert_eq!(v["interval_ms"], 1000);
    let samples = v["samples"].as_array().unwrap();
    assert!(samples.len() >= 2, "{body}");
    for k in [
        "t",
        "allow",
        "throttle",
        "challenge",
        "drop",
        "error",
        "detection",
    ] {
        assert!(samples[0].get(k).is_some(), "{k} missing in {body}");
    }
    // a range past the ring without a store: still memory
    let (_, body) = get(admin, "GET", "/history?range=24h", &[&auth()]);
    assert!(body.contains("\"source\":\"memory\""), "{body}");

    let (status, _) = get(admin, "GET", "/history", &[]);
    assert_eq!(status, 401);
    let (status, body) = get(admin, "GET", "/history?range=2d", &[&auth()]);
    assert_eq!(status, 400);
    assert!(body.contains("15m, 1h, 6h, 24h, 7d"), "{body}");
    drop(p);
}

// RFC 0022 case 6
#[test]
#[ignore = "rfc 0022"]
fn persist_needs_postgres() {
    let path = temp("history-persist.toml");
    let extra = "[store]\nbackend = \"memory\"";
    let t = toml(port(), port(), extra).replace("[history]\n", "[history]\npersist = true\n");
    std::fs::write(&path, t).unwrap();
    let o = run(&["serve", "--config", path.to_str().unwrap()], &[]);
    let _ = std::fs::remove_file(&path);
    assert_ne!(o.status.code(), Some(0));
    let err = String::from_utf8_lossy(&o.stderr) + String::from_utf8_lossy(&o.stdout);
    assert!(err.contains("history.persist"), "{err}");
}

// RFC 0022 case 11: an unreachable store answers from memory, logged once
#[cfg(feature = "postgres")]
#[test]
#[ignore = "rfc 0022"]
fn a_lost_store_answers_from_memory() {
    let (listen, admin) = (port(), port());
    let extra = "[store]\nbackend = \"postgres\"\nurl = \"postgres://dvarapala@127.0.0.1:1/dvarapala?sslmode=disable\"";
    let t = toml(listen, admin, extra).replace("[history]\n", "[history]\npersist = true\n");
    let p = serve("history-lost", Some(&t), &[]);
    wait_port(admin);
    for _ in 0..2 {
        let (status, body) = get(admin, "GET", "/history?range=1h", &[&auth()]);
        assert_eq!(status, 200, "{body}");
        assert!(body.contains("\"source\":\"memory\""), "{body}");
    }
    p.logged(&["history store unavailable"]);
    let (_, log) = p.stop();
    assert_eq!(log.matches("history store unavailable").count(), 1, "{log}");
}
