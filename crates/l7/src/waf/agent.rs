//! RFC 0017: connections to the inspection agent. One `NOTIFY` in flight
//! per connection, at most `max_concurrent` connections, reused.

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
        if let Some(p) = s.strip_prefix("unix:") {
            if !p.starts_with('/') {
                return Err(format!("{s:?}: unix:/absolute/path"));
            }
            return Ok(Self::Unix(p.into()));
        }
        match s.rsplit_once(':') {
            Some((host, port)) if !host.is_empty() && port.parse::<u16>().is_ok() => {
                Ok(Self::Tcp(s.into()))
            }
            _ => Err(format!("{s:?}: host:port or unix:/path")),
        }
    }

    /// Loopback or a Unix socket: the SPOP connection carries request
    /// bodies in plaintext.
    pub fn is_local(&self) -> bool {
        match self {
            Self::Unix(_) => true,
            Self::Tcp(a) => {
                let host = a.rsplit_once(':').map_or("", |(h, _)| h);
                let host = host.trim_start_matches('[').trim_end_matches(']');
                host == "localhost"
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            }
        }
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
        match self {
            Self::Connect => "connect",
            Self::Timeout => "timeout",
            Self::Protocol => "protocol",
            Self::Disconnect => "disconnect",
        }
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
        Self {
            endpoint,
            max_frame: max_frame.max(MIN_FRAME),
            slots: Semaphore::new(max_concurrent.max(1)),
            idle: Mutex::new(Vec::new()),
            stream: AtomicU64::new(1),
        }
    }

    /// Sends one message and reads its `ACK`. The caller bounds the time;
    /// a dropped call drops its connection.
    pub async fn ask(&self, name: &str, args: &[(&str, Value<'_>)]) -> Result<Answer, Failure> {
        let _slot = self.slots.acquire().await.map_err(|_| Failure::Connect)?;
        let stream = self.stream.fetch_add(1, Ordering::Relaxed);
        let notify = frame::notify(stream, 0, name, args);
        let pooled = self
            .idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop();
        let (mut conn, reused) = match pooled {
            Some(c) => (c, true),
            None => (self.dial().await?, false),
        };
        let answer = match exchange(&mut conn, &notify, stream).await {
            // an idle connection the agent closed: once more on a new one
            Err(Failure::Disconnect | Failure::Connect) if reused => {
                conn = self.dial().await?;
                exchange(&mut conn, &notify, stream).await?
            }
            r => r?,
        };
        self.idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(conn);
        Ok(answer)
    }

    async fn dial(&self) -> Result<Conn, Failure> {
        let io: Box<dyn Io> = match &self.endpoint {
            Endpoint::Tcp(a) => {
                let s = TcpStream::connect(a.as_str()).await.map_err(|e| {
                    log_agent(format_args!("connect {a}: {e}"));
                    Failure::Connect
                })?;
                let _ = s.set_nodelay(true);
                Box::new(s)
            }
            #[cfg(unix)]
            Endpoint::Unix(p) => {
                Box::new(tokio::net::UnixStream::connect(p).await.map_err(|e| {
                    log_agent(format_args!("connect {}: {e}", p.display()));
                    Failure::Connect
                })?)
            }
            #[cfg(not(unix))]
            Endpoint::Unix(_) => return Err(Failure::Connect),
        };
        let mut conn = Conn {
            io,
            max_frame: self.max_frame,
        };
        conn.io
            .write_all(&frame::hello(self.max_frame))
            .await
            .map_err(|_| Failure::Connect)?;
        let buf = read(&mut conn).await?;
        match frame::decode(&buf) {
            Ok(Frame::Hello {
                version,
                max_frame_size,
            }) if version.starts_with(b"2.")
                && (MIN_FRAME..=self.max_frame).contains(&max_frame_size) =>
            {
                conn.max_frame = max_frame_size;
                Ok(conn)
            }
            Ok(Frame::Disconnect { status, message }) => {
                log_agent(format_args!("hello refused: {status} {message}"));
                Err(Failure::Disconnect)
            }
            other => {
                log_agent(format_args!("bad hello: {other:?}"));
                Err(Failure::Protocol)
            }
        }
    }
}

async fn exchange(conn: &mut Conn, notify: &[u8], stream: u64) -> Result<Answer, Failure> {
    if notify.len() - 4 > conn.max_frame as usize {
        log_agent(format_args!(
            "request of {} bytes over the agent's frame size {}",
            notify.len() - 4,
            conn.max_frame
        ));
        return Err(Failure::Protocol);
    }
    conn.io
        .write_all(notify)
        .await
        .map_err(|_| Failure::Disconnect)?;
    let buf = read(conn).await?;
    match frame::decode(&buf) {
        Ok(Frame::Ack {
            stream: s, vars, ..
        }) if s == stream => Ok(answer(&vars)),
        Ok(Frame::Disconnect { status, message }) => {
            log_agent(format_args!("disconnect: {status} {message}"));
            Err(Failure::Disconnect)
        }
        other => {
            log_agent(format_args!("unexpected frame: {other:?}"));
            Err(Failure::Protocol)
        }
    }
}

/// One frame body, bounded by the negotiated size.
async fn read(conn: &mut Conn) -> Result<Vec<u8>, Failure> {
    let mut len = [0; 4];
    conn.io
        .read_exact(&mut len)
        .await
        .map_err(|_| Failure::Disconnect)?;
    let len = u32::from_be_bytes(len);
    if len > conn.max_frame {
        log_agent(format_args!("frame of {len} bytes over {}", conn.max_frame));
        return Err(Failure::Protocol);
    }
    let mut buf = vec![0; len as usize];
    conn.io
        .read_exact(&mut buf)
        .await
        .map_err(|_| Failure::Disconnect)?;
    Ok(buf)
}

fn answer(vars: &[(&[u8], Value<'_>)]) -> Answer {
    let mut a = Answer::default();
    for (k, v) in vars {
        match *k {
            b"action" => a.action = v.text().filter(|s| !s.is_empty()),
            b"status" => a.status = v.int(),
            b"ruleid" => a.rule = v.int(),
            b"rule_ids" => a.rule_ids = v.text(),
            b"anomaly_score" => a.anomaly_score = v.int(),
            b"id" => a.id = v.text(),
            _ => {}
        }
    }
    a
}

/// `msg="waf agent"`, at most one line per second.
fn log_agent(what: std::fmt::Arguments<'_>) {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = crate::unix_now();
    if LAST.swap(now, Ordering::Relaxed) != now {
        tracing::warn!(msg = "waf agent", error = %what);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
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
