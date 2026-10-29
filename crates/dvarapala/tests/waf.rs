//! RFC 0017 case 11 against the running binary.
#![cfg(all(unix, feature = "waf"))]

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

#[path = "../../l7/tests/fake_agent/mod.rs"]
#[allow(dead_code)]
mod fake_agent;

use fake_agent::{Behavior, Reply};

const TOKEN: &str = "0123456789abcdef0123456789abcdef";

struct Proxy {
    child: Child,
    listen: u16,
    admin: u16,
    config: PathBuf,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.config);
    }
}

fn port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn toml(listen: u16, admin: u16, endpoint: &str) -> String {
    // the upstream refuses connections: a request the agent passes is 502
    format!(
        "listen = \"127.0.0.1:{listen}\"\nupstream = \"http://127.0.0.1:1\"\n\
         [metrics]\nlisten = \"\"\n[rate_limit]\nrate = 1000\nburst = 1000\n\
         [admin]\nlisten = \"127.0.0.1:{admin}\"\ntoken = \"{TOKEN}\"\n\
         [waf]\nenabled = true\nmode = \"enforce\"\nendpoint = \"{endpoint}\"\n"
    )
}

fn start(endpoint: SocketAddr) -> Proxy {
    let (listen, admin) = (port(), port());
    let config = std::env::temp_dir().join(format!("dvarapala-waf-{}.toml", std::process::id()));
    std::fs::write(&config, toml(listen, admin, &endpoint.to_string())).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_dvarapala"))
        .args(["serve", "--config"])
        .arg(&config)
        .spawn()
        .unwrap();
    let p = Proxy {
        child,
        listen,
        admin,
        config,
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(("127.0.0.1", p.admin)).is_err() {
        assert!(Instant::now() < deadline, "admin listener did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
    p
}

/// One request on a new connection; the status and the body.
fn send(port: u16, method: &str, target: &str, auth: bool) -> (u16, String) {
    let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let auth = if auth {
        format!("Authorization: Bearer {TOKEN}\r\n")
    } else {
        String::new()
    };
    write!(
        c,
        "{method} {target} HTTP/1.1\r\nHost: x\r\n{auth}Connection: close\r\n\r\n"
    )
    .unwrap();
    let mut r = BufReader::new(c);
    let mut line = String::new();
    r.read_line(&mut line).unwrap();
    let status = line.split(' ').nth(1).unwrap().parse().unwrap();
    let mut rest = String::new();
    while r.read_line(&mut rest).unwrap_or(0) > 0 {}
    (status, rest)
}

fn reload(p: &Proxy, endpoint: &str) -> (u16, String) {
    std::fs::write(&p.config, toml(p.listen, p.admin, endpoint)).unwrap();
    send(p.admin, "POST", "/reload", true)
}

// case 11
#[test]
#[ignore = "rfc 0017"]
fn reload_moves_the_endpoint_and_refuses_a_bad_one() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (deny, _) = rt.block_on(fake_agent::spawn(Behavior::reply(Reply::Deny(403, 941100))));
    let (pass, seen) = rt.block_on(fake_agent::spawn(Behavior::reply(Reply::Pass)));
    let p = start(deny);
    assert_eq!(send(p.listen, "GET", "/?q=x", false).0, 403);

    let (status, body) = reload(&p, &pass.to_string());
    assert_eq!(status, 200, "{body}");
    assert_eq!(send(p.listen, "GET", "/?q=x", false).0, 502);
    assert_eq!(seen.notifies(), 1);

    let (status, body) = reload(&p, "nonsense");
    assert_ne!(status, 200, "{body}");
    assert!(body.contains("waf.endpoint"), "{body}");
    let (_, body) = send(p.admin, "GET", "/status", true);
    assert!(body.contains("\"result\":\"failed\""), "{body}");
    // the agent from the last good file still answers
    assert_eq!(send(p.listen, "GET", "/?q=x", false).0, 502);
    assert_eq!(seen.notifies(), 2);
}
