//! RFC 0021 cases 1, 3, 5, 7 to 12, 15 and 16 against the running binary:
//! the config view, the WAF view, the mode switch and the metrics.
#![cfg(unix)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

#[cfg(feature = "waf")]
#[path = "../../l7/tests/fake_agent/mod.rs"]
#[allow(dead_code)]
mod fake_agent;
#[allow(dead_code)]
mod proc;
mod ready;
use ready::port;
mod stop;

const TOKEN: &str = "0123456789abcdef0123456789abcdef";

struct Answer {
    status: u16,
    headers: HashMap<String, String>,
    body: String,
}

/// One request on a new connection; `headers` as `name: value` lines.
fn call(port: u16, method: &str, target: &str, headers: &[String]) -> Answer {
    let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let extra: String = headers.iter().map(|h| format!("{h}\r\n")).collect();
    write!(
        c,
        "{method} {target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{extra}\r\n"
    )
    .unwrap();
    let mut r = BufReader::new(c);
    let mut line = String::new();
    r.read_line(&mut line).unwrap();
    let status = line.split(' ').nth(1).unwrap().parse().unwrap();
    let mut headers = HashMap::new();
    loop {
        line.clear();
        r.read_line(&mut line).unwrap();
        if line == "\r\n" || line.is_empty() {
            break;
        }
        let (k, v) = line.split_once(':').unwrap();
        headers.insert(k.to_ascii_lowercase(), v.trim().to_owned());
    }
    let mut body = Vec::new();
    match headers.get("content-length") {
        Some(l) => {
            body.resize(l.parse().unwrap(), 0);
            r.read_exact(&mut body).unwrap();
        }
        None => {
            let _ = r.read_to_end(&mut body);
        }
    }
    Answer {
        status,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

fn bearer() -> String {
    format!("Authorization: Bearer {TOKEN}")
}

/// A gateway with an admin listener; `extra` is appended to the file.
struct Gw {
    p: proc::Proc,
    listen: u16,
    admin: u16,
}

/// `admin` keys go in `[admin]`; `rest` follows as more sections.
fn start(name: &str, admin: &str, rest: &str, env: &[(&str, &str)]) -> Gw {
    let (listen, adm) = (port(), port());
    let toml = format!(
        "listen = \"127.0.0.1:{listen}\"\nupstream = \"http://127.0.0.1:1\"\n\
         [metrics]\nlisten = \"\"\n[rate_limit]\nrate = 1000\nburst = 1000\n\
         [admin]\nlisten = \"127.0.0.1:{adm}\"\ntoken = \"{TOKEN}\"\n{admin}\n{rest}"
    );
    let p = proc::serve(name, Some(&toml), env);
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready::answers(adm) {
        assert!(Instant::now() < deadline, "admin listener did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
    Gw {
        p,
        listen,
        admin: adm,
    }
}

/// The entry for `key` in a `GET /config` body.
fn key(body: &str, key: &str) -> serde_json::Value {
    let v: serde_json::Value = serde_json::from_str(body).unwrap();
    v["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["key"] == key)
        .unwrap_or_else(|| panic!("no {key} in {body}"))
        .clone()
}

// cases 1 and 3
#[test]
fn config_redacted_with_flags() {
    let challenge = "c".repeat(40);
    let g = start(
        "view-config",
        "[admin.oidc]\nclient_secret = \"\"\n",
        &format!(
            "[challenge]\nsecret = \"{challenge}\"\n[store]\nurl = \"redis://:hunter2@192.0.2.1:6379/0\"\n"
        ),
        &[
            ("DVARAPALA__RATE_LIMIT__BURST", "7"),
            ("DVARAPALA__RATE_LIMIT__RATE", "50"),
        ],
    );
    assert_eq!(call(g.admin, "GET", "/config", &[]).status, 401);
    let a = call(g.admin, "GET", "/config", &[bearer()]);
    assert_eq!(a.status, 200, "{}", a.body);
    for secret in [TOKEN, challenge.as_str(), "hunter2"] {
        assert!(!a.body.contains(secret), "{secret} in {}", a.body);
    }
    assert_eq!(key(&a.body, "admin.token")["value"], "<redacted>");
    assert_eq!(key(&a.body, "store.url")["value"], "<redacted>");
    assert_eq!(key(&a.body, "admin.oidc.client_secret")["value"], "");
    let rate = key(&a.body, "rate_limit.rate");
    assert_eq!(
        (&rate["value"], &rate["reload"], &rate["default"]),
        (&50.into(), &true.into(), &false.into())
    );
    assert_eq!(key(&a.body, "rate_limit.burst")["value"], 7);
    assert_eq!(key(&a.body, "listen")["reload"], false);
}

// case 8
#[test]
fn mode_switch_off_by_default() {
    let g = start("view-off", "", "", &[]);
    let a = call(
        g.admin,
        "POST",
        "/mode?layer=detection&mode=enforce",
        &[bearer()],
    );
    assert_eq!(a.status, 403, "{}", a.body);
    assert!(a.body.contains("admin.mode_switch"), "{}", a.body);
}

// case 11 (the switch applied and the table kept; the flood itself is
// RFC 0014's reload path, tested there)
#[test]
fn detection_switch_keeps_the_table() {
    let g = start("view-detect", "mode_switch = true", "", &[]);
    for _ in 0..3 {
        call(g.listen, "GET", "/", &[]);
    }
    let before = call(g.admin, "GET", "/status", &[bearer()]).body;
    let a = call(
        g.admin,
        "POST",
        "/mode?layer=detection&mode=enforce",
        &[bearer()],
    );
    assert_eq!(a.status, 200, "{}", a.body);
    assert!(a.body.contains("\"previous\":\"observe\""), "{}", a.body);
    g.p.logged(&["mode switched", "layer=\"detection\"", "actor=\"token\""]);
    g.p.logged(&["admin action", "actor=\"token\"", "/mode"]);
    let after = call(g.admin, "GET", "/status", &[bearer()]).body;
    let clients = |s: &str| {
        s.split("\"clients\":")
            .nth(1)
            .unwrap()
            .split(',')
            .next()
            .unwrap()
            .to_owned()
    };
    assert_eq!(clients(&before), clients(&after));
    assert!(
        after.contains("\"layer\":\"detection\",\"mode\":\"enforce\""),
        "{after}"
    );
}

// case 13 (the gateway part): a layer that is off
#[test]
fn switching_a_layer_that_is_off() {
    let g = start("view-conflict", "mode_switch = true", "", &[]);
    let a = call(g.admin, "POST", "/mode?layer=waf&mode=enforce", &[bearer()]);
    assert_eq!(a.status, 409, "{}", a.body);
    assert_eq!(
        call(
            g.admin,
            "POST",
            "/mode?layer=nope&mode=enforce",
            &[bearer()]
        )
        .status,
        400
    );
}

// case 12
#[cfg(feature = "ui")]
#[test]
fn cookie_switch_needs_the_csrf_header() {
    let g = start(
        "view-csrf",
        "mode_switch = true\nui_enabled = true",
        "",
        &[],
    );
    let a = call(g.admin, "POST", "/session", &[bearer()]);
    let cookie = format!(
        "Cookie: {}",
        a.headers["set-cookie"].split(';').next().unwrap()
    );
    let a = call(
        g.admin,
        "POST",
        "/mode?layer=detection&mode=enforce",
        &[cookie],
    );
    assert_eq!(a.status, 403, "{}", a.body);
}

// case 15
#[test]
fn metrics_on_the_admin_listener() {
    let g = start("view-metrics", "", "", &[]);
    call(g.listen, "GET", "/", &[]);
    assert_eq!(call(g.admin, "GET", "/metrics", &[]).status, 401);
    let a = call(g.admin, "GET", "/metrics", &[bearer()]);
    assert_eq!(a.status, 200);
    assert!(
        a.headers["content-type"].starts_with("text/plain"),
        "{:?}",
        a.headers
    );
    assert!(a.body.contains("dvarapala_requests_total"), "{}", a.body);
}

// case 16
#[test]
fn same_series_on_both_listeners() {
    let m = port();
    let listen = format!("127.0.0.1:{m}");
    let g = start(
        "view-both",
        "",
        "",
        &[("DVARAPALA__METRICS__LISTEN", &listen)],
    );
    call(g.listen, "GET", "/", &[]);
    proc::wait_port(m);
    let names = |body: &str| {
        let mut n: Vec<String> = body
            .lines()
            .filter(|l| l.starts_with("dvarapala_"))
            .map(|l| l.split(['{', ' ']).next().unwrap().to_owned())
            .collect();
        n.sort();
        n.dedup();
        n
    };
    let admin = names(&call(g.admin, "GET", "/metrics", &[bearer()]).body);
    let scrape = names(&call(m, "GET", "/metrics", &[]).body);
    assert!(
        admin.iter().any(|n| n == "dvarapala_requests_total"),
        "{admin:?}"
    );
    assert_eq!(admin, scrape);
}

#[cfg(feature = "waf")]
mod waf {
    use fake_agent::{Behavior, Reply};

    use super::*;

    fn waf_toml(endpoint: &str, rules_files: &str) -> String {
        format!(
            "[waf]\nenabled = true\nmode = \"enforce\"\nendpoint = \"{endpoint}\"\nrules_files = [{rules_files}]\n"
        )
    }

    // cases 9 and 10
    #[test]
    fn switch_to_observe_until_the_reload() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (deny, _) = rt.block_on(fake_agent::spawn(Behavior::reply(Reply::Deny(403, 942100))));
        let g = start(
            "view-waf-switch",
            "mode_switch = true",
            &waf_toml(&deny.to_string(), ""),
            &[],
        );
        assert_eq!(call(g.listen, "GET", "/?q=x", &[]).status, 403);
        let a = call(g.admin, "POST", "/mode?layer=waf&mode=observe", &[bearer()]);
        assert_eq!(a.status, 200, "{}", a.body);
        // observe forwards: the upstream refuses, 502
        assert_eq!(call(g.listen, "GET", "/?q=x", &[]).status, 502);
        let m = call(g.admin, "GET", "/metrics", &[bearer()]).body;
        assert!(m.contains("verdict=\"would_block\""), "{m}");
        assert!(
            m.contains("dvarapala_mode_switched{layer=\"waf\"} 1"),
            "{m}"
        );
        let s = call(g.admin, "GET", "/status", &[bearer()]).body;
        assert!(s.contains("\"waf\":\"observe\""), "{s}");
        g.p.logged(&["admin action", "actor=\"token\"", "/mode"]);

        assert_eq!(call(g.admin, "POST", "/reload", &[bearer()]).status, 200);
        g.p.logged(&["mode switch cleared", "layer=\"waf\"", "file=\"enforce\""]);
        assert_eq!(call(g.listen, "GET", "/?q=x", &[]).status, 403);
        let m = call(g.admin, "GET", "/metrics", &[bearer()]).body;
        assert!(
            m.contains("dvarapala_mode_switched{layer=\"waf\"} 0"),
            "{m}"
        );
    }

    // cases 5 and 7
    #[test]
    fn matched_rules_and_rule_files() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (a942, _) = rt.block_on(fake_agent::spawn(Behavior::reply(Reply::Deny(403, 942100))));
        let (a941, _) = rt.block_on(fake_agent::spawn(Behavior::reply(Reply::Deny(403, 941100))));
        let dir = proc::temp("rules");
        std::fs::create_dir_all(&dir).unwrap();
        let ok = dir.join("coraza.yaml");
        std::fs::write(&ok, "directives: |\n  SecRuleRemoveById 920350\n").unwrap();
        let big = dir.join("big.conf");
        std::fs::write(&big, vec![b'#'; 256 * 1024 + 1]).unwrap();
        let missing = dir.join("missing.conf");
        let files = [&ok, &missing, &big]
            .map(|p| format!("\"{}\"", p.display()))
            .join(", ");
        let g = start(
            "view-waf-rules",
            "",
            &waf_toml(&a942.to_string(), &files),
            &[],
        );
        call(g.listen, "GET", "/a?q=1", &[]);
        call(g.listen, "GET", "/a?q=2", &[]);
        let next = std::fs::read_to_string(g.p.config())
            .unwrap()
            .replace(&a942.to_string(), &a941.to_string());
        std::fs::write(g.p.config(), next).unwrap();
        assert_eq!(call(g.admin, "POST", "/reload", &[bearer()]).status, 200);
        call(g.listen, "POST", "/b?secret=x", &[]);

        let a = call(g.admin, "GET", "/waf", &[bearer()]);
        assert_eq!(a.status, 200, "{}", a.body);
        let v: serde_json::Value = serde_json::from_str(&a.body).unwrap();
        let rule = |id: i64| {
            v["rules"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["rule"] == id)
                .unwrap_or_else(|| panic!("no {id} in {}", a.body))
                .clone()
        };
        assert_eq!(rule(942100)["count"], 2);
        assert_eq!(rule(941100)["count"], 1);
        assert_eq!(rule(941100)["path"], "/b");
        assert!(rule(941100)["last_seen"].as_u64().unwrap() > 0);
        assert!(!a.body.contains("secret=x"), "{}", a.body);
        let files = v["files"].as_array().unwrap();
        assert!(
            files[0]["content"]
                .as_str()
                .unwrap()
                .contains("SecRuleRemoveById")
        );
        assert!(files[1]["error"].is_string(), "{}", a.body);
        assert!(
            files[2]["error"].as_str().unwrap().contains("256 KiB"),
            "{}",
            a.body
        );
        g.p.logged(&["waf rules file unreadable"]);
        let _ = std::fs::remove_dir_all(dir);
    }
}
