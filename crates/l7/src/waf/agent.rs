//! RFC 0017: connections to the inspection agent. One `NOTIFY` in flight
//! per connection, at most `max_concurrent` connections, reused.
#![allow(unused_variables, unused_imports, dead_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use super::frame::{self, Agent as Frame, MIN_FRAME, Value};

/// Where the agent listens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// `host:port`, resolved on every dial.
    Tcp(String),
    Unix(PathBuf),
}

impl Endpoint {
    /// `host:port` or `unix:/path`.
    pub fn parse(s: &str) -> Result<Self, String> {
        todo!("rfc 0017")
    }

    /// Loopback or a Unix socket: the SPOP connection carries request
    /// bodies in plaintext.
    pub fn is_local(&self) -> bool {
        todo!("rfc 0017")
    }
}

/// Why an inspection got no answer: the `reason` label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    Connect,
    Timeout,
    Protocol,
    Disconnect,
}

impl Failure {
    pub fn label(self) -> &'static str {
        todo!("rfc 0017")
    }
}

/// The variables of one `ACK`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Answer {
    /// `deny`, `drop`, `redirect`; `None` passes.
    pub action: Option<String>,
    pub status: Option<i64>,
    pub rule: Option<i64>,
    pub rule_ids: Option<String>,
    pub anomaly_score: Option<i64>,
    pub id: Option<String>,
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

struct Conn {
    io: Box<dyn Io>,
    /// what the agent agreed to in its hello
    max_frame: u32,
}

pub struct Pool {
    endpoint: Endpoint,
    /// proposed in the hello
    max_frame: u32,
    slots: Semaphore,
    idle: Mutex<Vec<Conn>>,
    stream: AtomicU64,
}

impl Pool {
    pub fn new(endpoint: Endpoint, max_frame: u32, max_concurrent: usize) -> Self {
        todo!("rfc 0017")
    }

    /// Sends one message and reads its `ACK`. The caller bounds the time;
    /// a dropped call drops its connection.
    pub async fn ask(&self, name: &str, args: &[(&str, Value<'_>)]) -> Result<Answer, Failure> {
        todo!("rfc 0017")
    }

    async fn dial(&self) -> Result<Conn, Failure> {
        todo!("rfc 0017")
    }
}

async fn exchange(conn: &mut Conn, notify: &[u8], stream: u64) -> Result<Answer, Failure> {
    todo!("rfc 0017")
}

/// One frame body, bounded by the negotiated size.
async fn read(conn: &mut Conn) -> Result<Vec<u8>, Failure> {
    todo!("rfc 0017")
}

fn answer(vars: &[(&[u8], Value<'_>)]) -> Answer {
    todo!("rfc 0017")
}

/// `msg="waf agent"`, at most one line per second.
fn log_agent(what: std::fmt::Arguments<'_>) {
    todo!("rfc 0017")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "rfc 0017"]
    fn endpoints() {
        assert_eq!(
            Endpoint::parse("unix:/run/spoa/coraza.sock"),
            Ok(Endpoint::Unix("/run/spoa/coraza.sock".into()))
        );
        assert!(Endpoint::parse("unix:rel").is_err());
        assert!(Endpoint::parse("nonsense").is_err());
        assert!(Endpoint::parse(":9000").is_err());
        assert!(Endpoint::parse("coraza:99999").is_err());
        for (s, local) in [
            ("127.0.0.1:9000", true),
            ("[::1]:9000", true),
            ("localhost:9000", true),
            ("unix:/x", true),
            ("192.0.2.1:9000", false),
            ("coraza:9000", false),
        ] {
            assert_eq!(Endpoint::parse(s).unwrap().is_local(), local, "{s}");
        }
    }
}
