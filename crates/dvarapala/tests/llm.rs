//! RFC 0023 against the running binary and a fake model endpoint.
#![cfg(all(unix, feature = "llm"))]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
mod ready;
use ready::port;
mod stop;

const TOKEN: &str = "0123456789abcdef0123456789abcdef";

/// What the fake endpoint answers.
#[derive(Clone)]
enum Reply {
    Json(String),
    Status(u16),
    Hang,
}

/// The fake endpoint: the request heads and bodies it got.
struct Fake {
    port: u16,
    got: Arc<Mutex<Vec<(String, String)>>>,
}

fn fake(reply: Reply) -> Fake {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let got = Arc::new(Mutex::new(Vec::new()));
    let g = got.clone();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            let (g, reply) = (g.clone(), reply.clone());
            std::thread::spawn(move || {
                let mut r = BufReader::new(c.try_clone().unwrap());
                let (mut head, mut len) = (String::new(), 0);
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap();
                    }
                    if line == "\r\n" {
                        break;
                    }
                    head.push_str(&line);
                }
                let mut body = vec![0; len];
                r.read_exact(&mut body).unwrap();
                g.lock()
                    .unwrap()
                    .push((head, String::from_utf8(body).unwrap()));
                let (status, body) = match reply {
                    Reply::Json(b) => (200, b),
                    Reply::Status(s) => (s, "{}".into()),
                    Reply::Hang => {
                        std::thread::sleep(Duration::from_secs(120));
                        return;
                    }
                };
                let mut c = c;
                let _ = write!(
                    c,
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
                    body.len()
                );
            });
        }
    });
    Fake { port, got }
}

struct Proxy {
    child: Child,
    listen: u16,
    admin: u16,
    config: PathBuf,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        stop::stop(&mut self.child);
        let _ = std::fs::remove_file(&self.config);
    }
}

/// `llm` goes at the end of `[ml.llm]`, after a `route` trigger on `/login`.
fn start(name: &str, fake: &Fake, llm: &str, admin_extra: &str, env: &[(&str, &str)]) -> Proxy {
    let (listen, admin) = (port(), port());
    let config =
        std::env::temp_dir().join(format!("dvarapala-llm-{name}-{}.toml", std::process::id()));
    let text = format!(
        "listen = \"127.0.0.1:{listen}\"\nupstream = \"http://127.0.0.1:1\"\ntrusted_proxies = [\"127.0.0.1/32\"]\n\
         [metrics]\nlisten = \"\"\n[rate_limit]\nrate = 1000\nburst = 1000\n\
         [admin]\nlisten = \"127.0.0.1:{admin}\"\ntoken = \"{TOKEN}\"\n{admin_extra}\n\
         [[routes]]\nname = \"login\"\npath = \"/login\"\n\
         [ml.llm]\nendpoint = \"http://127.0.0.1:{}/v1/systemone\"\nmodel = \"clef\"\n{llm}\n\
         [[ml.llm.triggers]]\non = \"route\"\nroute = \"login\"\n",
        fake.port
    );
    std::fs::write(&config, text).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_dvarapala"))
        .args(["serve", "--config"])
        .arg(&config)
        .envs(env.iter().copied())
        .spawn()
        .unwrap();
    let p = Proxy {
        child,
        listen,
        admin,
        config,
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready::answers(p.admin) || !ready::answers(p.listen) {
        assert!(Instant::now() < deadline, "listeners did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
    p
}

/// One request, `Connection: close`; the status and the body.
fn http(port: u16, req: &str) -> (u16, String) {
    let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.write_all(req.as_bytes()).unwrap();
    let mut out = String::new();
    c.read_to_string(&mut out).unwrap();
    let status = out.split(' ').nth(1).unwrap().parse().unwrap();
    let body = out.split_once("\r\n\r\n").map_or("", |b| b.1).to_owned();
    (status, body)
}

fn admin(p: &Proxy, method: &str, target: &str) -> (u16, String) {
    http(
        p.admin,
        &format!(
            "{method} {target} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {TOKEN}\r\nConnection: close\r\n\r\n"
        ),
    )
}

/// `GET /login` from `client`, with `extra` header lines.
fn login(p: &Proxy, client: &str, extra: &str) -> u16 {
    http(
        p.listen,
        &format!("GET /login HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: {client}\r\n{extra}Connection: close\r\n\r\n"),
    )
    .0
}

fn metric(p: &Proxy, line: &str) -> u64 {
    let m = admin(p, "GET", "/metrics").1;
    m.lines()
        .find(|l| l.starts_with(line))
        .and_then(|l| l.rsplit(' ').next()?.parse().ok())
        .unwrap_or(0)
}

fn wait(what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ok() {
        assert!(Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn system_one(wrapped: bool) -> String {
    let a = r#"{"answers":{"label":{"probabilities":{"benign":0.1,"scanner":0.7,"other":0.2}}}}"#;
    if wrapped {
        format!(r#"{{"result":{a},"success":true}}"#)
    } else {
        a.into()
    }
}

// RFC 0023 cases 2, 6 and 7b
#[test]
#[ignore = "rfc 0023"]
fn samples_while_on_redacted_and_labeled() {
    let f = fake(Reply::Json(system_one(true)));
    let p = start("on", &f, "", "mode_switch = true", &[]);
    // off: answered as usual, nothing sent
    assert_eq!(login(&p, "192.0.2.1", ""), 502);
    assert!(f.got.lock().unwrap().is_empty());
    assert_eq!(admin(&p, "POST", "/llm?on=5m").0, 200);
    let extra =
        "Cookie: sid=cookie-marker\r\nAuthorization: Bearer auth-marker\r\nUser-Agent: curl/8\r\n";
    let req = format!(
        "POST /login?token=abc HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 192.0.2.2\r\n{extra}Content-Length: 11\r\nConnection: close\r\n\r\nbody-marker"
    );
    let t = Instant::now();
    assert_eq!(http(p.listen, &req).0, 502);
    assert!(t.elapsed() < Duration::from_secs(1));
    wait("one call", || f.got.lock().unwrap().len() == 1);
    let (_, body) = f.got.lock().unwrap()[0].clone();
    assert!(!body.contains("marker") && !body.contains("abc"), "{body}");
    assert!(
        body.contains("/login?token=_") && body.contains("curl/8"),
        "{body}"
    );
    assert!(
        body.contains(r#""type":"choice""#) && body.contains(r#""scanner""#),
        "{body}"
    );
    wait("labeled", || {
        admin(&p, "GET", "/llm").1.contains("\"scanner\"")
    });
    let (_, j) = admin(&p, "GET", "/llm");
    assert!(
        j.contains(r#""confidence":0.7"#) && j.contains(r#""sampling":true"#),
        "{j}"
    );
}

// RFC 0023 case 5
#[test]
#[ignore = "rfc 0023"]
fn a_full_queue_drops_and_requests_stay_fast() {
    let f = fake(Reply::Hang);
    let p = start(
        "queue",
        &f,
        "enabled = true\nqueue = 4\nconcurrency = 1\ntimeout = \"60s\"\n",
        "",
        &[],
    );
    let t = Instant::now();
    for i in 0..100 {
        assert_eq!(login(&p, &format!("198.51.100.{i}"), ""), 502);
    }
    assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    let sent = r#"dvarapala_llm_samples_total{trigger="route",result="sent"}"#;
    let dropped = r#"dvarapala_llm_samples_total{trigger="route",result="dropped"}"#;
    assert_eq!((metric(&p, sent), metric(&p, dropped)), (5, 95));
}

// RFC 0023 cases 7 and 15
#[test]
#[ignore = "rfc 0023"]
fn chat_label_logged_counted_and_key_redacted() {
    let content = r#"{\"label\":\"scanner\",\"confidence\":0.8,\"pattern\":\"probes logins\"}"#;
    let f = fake(Reply::Json(format!(
        r#"{{"choices":[{{"message":{{"content":"{content}"}}}}],"usage":{{"prompt_tokens":90,"completion_tokens":12}}}}"#
    )));
    let p = start(
        "chat",
        &f,
        "protocol = \"chat\"\nenabled = true\n",
        "",
        &[("DVARAPALA__ML__LLM__API_KEY", "key-marker")],
    );
    // the endpoint is a base URL for chat
    login(&p, "192.0.2.3", "");
    wait("labeled", || {
        metric(
            &p,
            r#"dvarapala_llm_labels_total{label="scanner",trigger="route"}"#,
        ) == 1
    });
    let (head, _) = f.got.lock().unwrap()[0].clone();
    assert!(
        head.starts_with("POST /v1/systemone/chat/completions "),
        "{head}"
    );
    assert!(head.contains("Bearer key-marker"), "{head}");
    assert!(admin(&p, "GET", "/llm").1.contains("probes logins"));
    assert_eq!(
        metric(&p, r#"dvarapala_llm_tokens_total{kind="prompt"}"#),
        90
    );
    assert!(!admin(&p, "GET", "/config").1.contains("key-marker"));
}

// RFC 0023 case 10
#[test]
#[ignore = "rfc 0023"]
fn limited_is_counted_without_retry() {
    let f = fake(Reply::Status(429));
    let p = start("limited", &f, "enabled = true\n", "", &[]);
    login(&p, "192.0.2.4", "");
    wait("limited", || {
        metric(&p, r#"dvarapala_llm_calls_total{result="limited"}"#) == 1
    });
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(f.got.lock().unwrap().len(), 1);
}

// RFC 0023 cases 12 and 13
#[test]
#[ignore = "rfc 0023"]
fn switch_needs_mode_switch_and_ends_at_reload() {
    let f = fake(Reply::Json(system_one(false)));
    let p = start("off", &f, "", "", &[]);
    assert_eq!(admin(&p, "POST", "/llm?on=5m").0, 403);
    let p = start("reload", &f, "", "mode_switch = true", &[]);
    assert_eq!(admin(&p, "POST", "/llm?on=99h").0, 400);
    assert_eq!(admin(&p, "POST", "/llm?on").0, 200);
    assert!(admin(&p, "GET", "/llm").1.contains(r#""sampling":true"#));
    assert_eq!(admin(&p, "POST", "/reload").0, 200);
    assert!(admin(&p, "GET", "/llm").1.contains(r#""sampling":false"#));
}

// RFC 0023 case 14
#[test]
#[ignore = "rfc 0023"]
fn export_writes_one_line_per_label() {
    let f = fake(Reply::Json(system_one(false)));
    let out =
        std::env::temp_dir().join(format!("dvarapala-llm-export-{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&out);
    let p = start(
        "export",
        &f,
        &format!("enabled = true\nexport = \"{}\"\n", out.display()),
        "",
        &[],
    );
    for c in ["192.0.2.10", "192.0.2.11", "192.0.2.12"] {
        login(&p, c, "");
    }
    let lines = || std::fs::read_to_string(&out).unwrap_or_default();
    wait("three lines", || lines().lines().count() == 3);
    for l in lines().lines() {
        let v: serde_json::Value = serde_json::from_str(l).unwrap();
        assert_eq!(
            (v["label"].as_str(), v["confidence"].as_f64()),
            (Some("scanner"), Some(0.7))
        );
        for k in ["window_requests", "rate_ewma", "source_entropy"] {
            assert!(v[k].is_number(), "{k} in {l}");
        }
    }
    drop(p);
    let _ = std::fs::remove_file(&out);
}
