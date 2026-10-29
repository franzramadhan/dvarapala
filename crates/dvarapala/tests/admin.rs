//! RFC 0014 cases 9, 10 and 13 against the running binary.
#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

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

fn toml(listen: u16, admin: u16, rate: u32) -> String {
    // the upstream refuses connections: the proxy answers 502, the limiter
    // still runs first
    format!(
        "listen = \"127.0.0.1:{listen}\"\nupstream = \"http://127.0.0.1:1\"\n\
         [metrics]\nlisten = \"\"\n[rate_limit]\nrate = {rate}\nburst = {rate}\n\
         [admin]\nlisten = \"127.0.0.1:{admin}\"\ntoken = \"{TOKEN}\"\n"
    )
}

fn start(name: &str, rate: u32) -> Proxy {
    let (listen, admin) = (port(), port());
    let config = std::env::temp_dir().join(format!("dvarapala-{name}-{}.toml", std::process::id()));
    std::fs::write(&config, toml(listen, admin, rate)).unwrap();
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

/// One request on `conn`, keep-alive; the status and the body.
fn send(conn: &mut TcpStream, method: &str, target: &str, auth: Option<&str>) -> (u16, String) {
    let auth = auth.map_or(String::new(), |a| format!("Authorization: {a}\r\n"));
    write!(conn, "{method} {target} HTTP/1.1\r\nHost: x\r\n{auth}\r\n").unwrap();
    let mut r = BufReader::new(conn);
    let mut line = String::new();
    r.read_line(&mut line).unwrap();
    let status = line.split(' ').nth(1).unwrap().parse().unwrap();
    let mut len = 0;
    loop {
        line.clear();
        r.read_line(&mut line).unwrap();
        if line == "\r\n" {
            break;
        }
        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            len = v.trim().parse().unwrap();
        }
    }
    let mut body = vec![0; len];
    r.read_exact(&mut body).unwrap();
    (status, String::from_utf8(body).unwrap())
}

fn admin(p: &Proxy, method: &str, target: &str, auth: Option<&str>) -> (u16, String) {
    let mut c = TcpStream::connect(("127.0.0.1", p.admin)).unwrap();
    send(&mut c, method, target, auth)
}

fn bearer() -> String {
    format!("Bearer {TOKEN}")
}

// case 9
#[test]
#[ignore = "rfc 0014"]
fn every_call_needs_the_token() {
    let p = start("auth", 100);
    assert_eq!(admin(&p, "GET", "/status", None).0, 401);
    let wrong = format!("Bearer {}", "f".repeat(TOKEN.len()));
    assert_eq!(admin(&p, "GET", "/status", Some(&wrong)).0, 401);
    let (status, body) = admin(&p, "GET", "/status", Some(&bearer()));
    assert_eq!(status, 200);
    assert!(body.contains("\"mode\":\"reverse\""), "{body}");
}

// case 10
#[test]
#[ignore = "rfc 0014"]
fn block_listed_and_enforced() {
    let p = start("block", 100);
    let mut c = TcpStream::connect(("127.0.0.1", p.listen)).unwrap();
    assert_eq!(send(&mut c, "GET", "/", None).0, 502);
    let b = bearer();
    let (status, _) = admin(&p, "POST", "/blocks?cidr=127.0.0.0/8&ttl=10m", Some(&b));
    assert_eq!(status, 200);
    let (_, body) = admin(&p, "GET", "/blocks", Some(&b));
    assert!(body.contains("\"cidr\":\"127.0.0.0/8\""), "{body}");
    assert!(
        body.contains("\"ttl_secs\":599") || body.contains("\"ttl_secs\":600"),
        "{body}"
    );
    let mut c = TcpStream::connect(("127.0.0.1", p.listen)).unwrap();
    assert_eq!(send(&mut c, "GET", "/", None).0, 403);
    assert_eq!(
        admin(&p, "DELETE", "/blocks?cidr=127.0.0.0/8", Some(&b)).0,
        200
    );
    assert_eq!(
        admin(&p, "DELETE", "/blocks?cidr=127.0.0.0/8", Some(&b)).0,
        404
    );
}

// case 13
#[test]
#[ignore = "rfc 0014"]
fn hangup_applies_the_rate_without_dropping_connections() {
    let p = start("hup", 1000);
    let mut c = TcpStream::connect(("127.0.0.1", p.listen)).unwrap();
    assert_eq!(send(&mut c, "GET", "/", None).0, 502);
    std::fs::write(&p.config, toml(p.listen, p.admin, 1)).unwrap();
    let pid = p.child.id().to_string();
    assert!(
        Command::new("kill")
            .args(["-HUP", &pid])
            .status()
            .unwrap()
            .success()
    );
    // the same connection, until the new burst of 1 is spent
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if send(&mut c, "GET", "/", None).0 == 429 {
            break;
        }
        assert!(Instant::now() < deadline, "the new rate never applied");
        std::thread::sleep(Duration::from_millis(50));
    }
    let (_, body) = admin(&p, "GET", "/status", Some(&bearer()));
    assert!(body.contains("\"result\":\"ok\""), "{body}");
}
