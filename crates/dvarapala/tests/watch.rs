//! RFC 0019 cases 12, 13 and 14: `config_watch` against the running binary.
#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Proxy {
    child: Child,
    listen: u16,
    dir: PathBuf,
}

impl Proxy {
    /// Stops the proxy and returns what it logged.
    fn stop(mut self) -> String {
        let _ = self.child.kill();
        let mut out = String::new();
        self.child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut out)
            .unwrap();
        out
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn toml(listen: u16, rate: u32) -> String {
    // the upstream refuses connections: allowed requests get 502, the
    // limiter still runs first
    format!(
        "listen = \"127.0.0.1:{listen}\"\nupstream = \"http://127.0.0.1:1\"\n\
         config_watch = \"100ms\"\n[metrics]\nlisten = \"\"\n\
         [detection]\nenabled = false\n[rate_limit]\nrate = {rate}\nburst = {rate}\n"
    )
}

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("dvarapala-watch-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Starts the proxy on `config`, a file or a symlink in `dir`.
fn start(dir: PathBuf, config: &Path, listen: u16) -> Proxy {
    let child = Command::new(env!("CARGO_BIN_EXE_dvarapala"))
        .args(["serve", "--config"])
        .arg(config)
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let p = Proxy { child, listen, dir };
    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(("127.0.0.1", p.listen)).is_err() {
        assert!(Instant::now() < deadline, "proxy did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
    p
}

/// The status of one request on a new connection.
fn status(p: &Proxy) -> u16 {
    let mut c = TcpStream::connect(("127.0.0.1", p.listen)).unwrap();
    write!(c, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
    let mut line = String::new();
    BufReader::new(c).read_line(&mut line).unwrap();
    line.split(' ').nth(1).unwrap().parse().unwrap()
}

/// Waits up to `limit` for two requests in a row to give `429`.
fn limited_within(p: &Proxy, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if status(p) == 429 || status(p) == 429 {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

// case 12
#[test]
fn rewritten_file_applies_without_a_restart() {
    let d = dir("rate");
    let config = d.join("d.toml");
    let listen = port();
    std::fs::write(&config, toml(listen, 100)).unwrap();
    let p = start(d, &config, listen);
    // a kept-alive connection must survive the reload
    let mut kept = TcpStream::connect(("127.0.0.1", listen)).unwrap();
    assert_eq!(status(&p), 502);
    assert_eq!(status(&p), 502);
    std::fs::write(&config, toml(listen, 1)).unwrap();
    assert!(limited_within(&p, Duration::from_secs(1)));
    write!(kept, "GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let mut line = String::new();
    BufReader::new(&mut kept).read_line(&mut line).unwrap();
    assert!(line.starts_with("HTTP/1.1 "), "{line}");
    let log = p.stop();
    assert!(log.contains("config changed on disk"), "{log}");
}

// case 13
#[test]
fn invalid_file_keeps_the_running_config() {
    let d = dir("invalid");
    let config = d.join("d.toml");
    let listen = port();
    std::fs::write(&config, toml(listen, 100)).unwrap();
    let p = start(d, &config, listen);
    let bad = format!("{}[[routes]]\nname = \"x\"\npath = \"\"\n", toml(listen, 1));
    std::fs::write(&config, bad).unwrap();
    assert!(!limited_within(&p, Duration::from_millis(800)));
    let log = p.stop();
    assert!(log.contains("config reload failed"), "{log}");
}

// case 14
#[test]
fn symlink_swap_reloads_once() {
    let d = dir("swap");
    let listen = port();
    // kubelet's layout: d.toml -> ..data/d.toml, ..data -> a timestamped dir
    for (v, rate) in [("v1", 100), ("v2", 1)] {
        std::fs::create_dir(d.join(v)).unwrap();
        std::fs::write(d.join(v).join("d.toml"), toml(listen, rate)).unwrap();
    }
    std::os::unix::fs::symlink("v1", d.join("..data")).unwrap();
    std::os::unix::fs::symlink("..data/d.toml", d.join("d.toml")).unwrap();
    let config = d.join("d.toml");
    let p = start(d.clone(), &config, listen);
    assert_eq!(status(&p), 502);
    std::os::unix::fs::symlink("v2", d.join("..data_tmp")).unwrap();
    std::fs::rename(d.join("..data_tmp"), d.join("..data")).unwrap();
    assert!(limited_within(&p, Duration::from_secs(1)));
    // a few more intervals: no second reload of the same content
    std::thread::sleep(Duration::from_millis(500));
    let log = p.stop();
    assert_eq!(log.matches("config changed on disk").count(), 1, "{log}");
}
