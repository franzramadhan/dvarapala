//! Runs `dvarapala serve` with a config, collects its log and stops it
//! with SIGTERM on drop (see `stop`).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::stop;

pub struct Proc {
    child: Child,
    config: Option<PathBuf>,
    log: Arc<Mutex<String>>,
    /// set by [`Proc::stop`], so drop does not signal a reaped pid
    stopped: bool,
}

impl Drop for Proc {
    fn drop(&mut self) {
        if !self.stopped {
            stop::stop(&mut self.child);
        }
        if let Some(c) = &self.config {
            let _ = std::fs::remove_file(c);
        }
    }
}

pub fn port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A file in the temp dir named after the test and this process.
pub fn temp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("dvarapala-{name}-{}", std::process::id()))
}

fn command(args: &[&str], env: &[(&str, &str)]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_dvarapala"));
    c.args(args)
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .envs(env.iter().copied());
    c
}

/// Runs the binary to its exit.
pub fn run(args: &[&str], env: &[(&str, &str)]) -> Output {
    command(args, env).output().unwrap()
}

/// `serve --config` with `toml` written to a temp file, or `serve` alone
/// (the environment only) when `toml` is `None`.
pub fn serve(name: &str, toml: Option<&str>, env: &[(&str, &str)]) -> Proc {
    let config = toml.map(|t| {
        let p = temp(&format!("{name}.toml"));
        std::fs::write(&p, t).unwrap();
        p
    });
    let mut args = vec!["serve"];
    if let Some(c) = &config {
        args.extend(["--config", c.to_str().unwrap()]);
    }
    let mut child = command(&args, env)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let log = Arc::new(Mutex::new(String::new()));
    for out in [
        Box::new(child.stdout.take().unwrap()) as Box<dyn Read + Send>,
        Box::new(child.stderr.take().unwrap()),
    ] {
        let l = log.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                let mut l = l.lock().unwrap();
                l.push_str(&line);
                l.push('\n');
            }
        });
    }
    Proc {
        child,
        config,
        log,
        stopped: false,
    }
}

impl Proc {
    /// Waits until the log has a line with every one of `parts`.
    pub fn logged(&self, parts: &[&str]) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let log = self.log.lock().unwrap().clone();
            if log.lines().any(|l| parts.iter().all(|p| l.contains(p))) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "no line with {parts:?} in\n{log}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn config(&self) -> &Path {
        self.config.as_deref().unwrap()
    }

    pub fn signal(&self, sig: &str) {
        let pid = self.child.id().to_string();
        let ok = Command::new("kill")
            .args([&format!("-{sig}"), &pid])
            .status()
            .unwrap()
            .success();
        assert!(ok, "kill -{sig} {pid}");
    }

    /// SIGTERM, then the exit status and the whole log.
    pub fn stop(mut self) -> (Option<i32>, String) {
        stop::stop(&mut self.child);
        self.stopped = true;
        let code = self.child.wait().unwrap().code();
        // the reader threads drain the pipes after the exit
        std::thread::sleep(Duration::from_millis(100));
        (code, self.log.lock().unwrap().clone())
    }
}

/// Waits until `port` on loopback accepts.
pub fn wait_port(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "port {port} did not open");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// One request on a new connection, `Connection: close`: the status and
/// the body.
pub fn get(port: u16, method: &str, target: &str, headers: &[&str]) -> (u16, String) {
    let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut req = format!("{method} {target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n");
    for h in headers {
        req.push_str(h);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    c.write_all(req.as_bytes()).unwrap();
    let mut raw = Vec::new();
    let _ = c.read_to_end(&mut raw);
    let raw = String::from_utf8_lossy(&raw).into_owned();
    let status = raw
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no status in {raw:?}"));
    let body = raw
        .split_once("\r\n\r\n")
        .map_or(String::new(), |(_, b)| b.to_owned());
    (status, body)
}
