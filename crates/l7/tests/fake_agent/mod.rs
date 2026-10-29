//! RFC 0017: a fake SPOP agent for the WAF tests and bench. Its decoder
//! is written apart from `waf::frame` so each checks the other.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Clone, PartialEq)]
pub enum Arg {
    Bool(bool),
    Int(u64),
    Ip(IpAddr),
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone)]
pub enum Reply {
    Pass,
    /// `action=deny`, the status and the rule ID.
    Deny(i64, i64),
    /// reads, never answers
    Silent,
    /// `AGENT-DISCONNECT` instead of the hello
    RefuseHello,
}

#[derive(Debug, Clone)]
pub struct Behavior {
    pub reply: Reply,
    pub delay: Duration,
    /// the frame size the hello answers; `None` repeats ours
    pub max_frame: Option<u32>,
}

impl Behavior {
    pub fn reply(reply: Reply) -> Self {
        Self {
            reply,
            delay: Duration::ZERO,
            max_frame: None,
        }
    }
}

/// The arguments of one `NOTIFY`, in order.
pub type Message = Vec<(String, Arg)>;

#[derive(Clone, Default)]
pub struct Seen {
    pub messages: Arc<Mutex<Vec<Message>>>,
    pub connections: Arc<AtomicUsize>,
    /// the frame size each hello agreed to
    pub frame_sizes: Arc<Mutex<Vec<u32>>>,
}

impl Seen {
    pub fn notifies(&self) -> usize {
        self.messages.lock().unwrap().len()
    }

    pub fn last(&self) -> Message {
        self.messages
            .lock()
            .unwrap()
            .last()
            .cloned()
            .unwrap_or_default()
    }
}

/// Listens on loopback until the runtime stops.
pub async fn spawn(b: Behavior) -> (SocketAddr, Seen) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let seen = Seen::default();
    let s = seen.clone();
    tokio::spawn(async move {
        while let Ok((c, _)) = l.accept().await {
            s.connections.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(serve(c, b.clone(), s.clone()));
        }
    });
    (addr, seen)
}

async fn serve(mut c: TcpStream, b: Behavior, seen: Seen) {
    let mut agreed = 0;
    loop {
        let mut len = [0; 4];
        if c.read_exact(&mut len).await.is_err() {
            return;
        }
        let mut buf = vec![0; u32::from_be_bytes(len) as usize];
        if c.read_exact(&mut buf).await.is_err() {
            return;
        }
        let mut r = R(&buf);
        let kind = r.byte();
        r.take(4);
        let (stream, frame) = (r.varint(), r.varint());
        match kind {
            1 => {
                let mut ours = 0;
                while !r.0.is_empty() {
                    let (k, v) = r.kv();
                    if let ("max-frame-size", Arg::Int(n)) = (k.as_str(), v) {
                        ours = n as u32;
                    }
                }
                if let Reply::RefuseHello = b.reply {
                    let mut out = head(102, 0, 0);
                    kv(&mut out, "status-code", |o| int(o, 3, 2));
                    kv(&mut out, "message", |o| text(o, 8, b"no"));
                    send(&mut c, out).await;
                    return;
                }
                agreed = b.max_frame.unwrap_or(ours);
                seen.frame_sizes.lock().unwrap().push(agreed);
                let mut out = head(101, 0, 0);
                kv(&mut out, "version", |o| text(o, 8, b"2.0"));
                kv(&mut out, "max-frame-size", |o| int(o, 3, agreed.into()));
                kv(&mut out, "capabilities", |o| text(o, 8, b""));
                send(&mut c, out).await;
            }
            3 => {
                assert!(buf.len() <= agreed as usize, "NOTIFY over {agreed}");
                assert_eq!(r.bytes(), b"coraza-req");
                let n = r.byte();
                let args = (0..n).map(|_| r.kv()).collect();
                seen.messages.lock().unwrap().push(args);
                // a zero sleep still waits for the next 1 ms timer tick
                if !b.delay.is_zero() {
                    tokio::time::sleep(b.delay).await;
                }
                let mut out = head(103, stream, frame);
                match b.reply {
                    Reply::Silent => {
                        tokio::time::sleep(Duration::from_secs(3600)).await;
                        return;
                    }
                    Reply::Deny(status, rule) => {
                        set(&mut out, "id", |o| text(o, 8, b"tx-1"));
                        set(&mut out, "status", |o| int(o, 4, status as u64));
                        set(&mut out, "action", |o| text(o, 8, b"deny"));
                        set(&mut out, "ruleid", |o| int(o, 4, rule as u64));
                    }
                    _ => set(&mut out, "id", |o| text(o, 8, b"tx-1")),
                }
                send(&mut c, out).await;
            }
            _ => return,
        }
    }
}

fn head(kind: u8, stream: u64, frame: u64) -> Vec<u8> {
    let mut b = vec![kind, 0, 0, 0, 1];
    varint(&mut b, stream);
    varint(&mut b, frame);
    b
}

async fn send(c: &mut TcpStream, out: Vec<u8>) {
    let mut f = (out.len() as u32).to_be_bytes().to_vec();
    f.extend(out);
    let _ = c.write_all(&f).await;
}

fn kv(b: &mut Vec<u8>, k: &str, v: impl FnOnce(&mut Vec<u8>)) {
    varint(b, k.len() as u64);
    b.extend_from_slice(k.as_bytes());
    v(b);
}

/// A `set-var` in the transaction scope.
fn set(b: &mut Vec<u8>, k: &str, v: impl FnOnce(&mut Vec<u8>)) {
    b.extend_from_slice(&[1, 3, 2]);
    kv(b, k, v);
}

fn int(b: &mut Vec<u8>, t: u8, n: u64) {
    b.push(t);
    varint(b, n);
}

fn text(b: &mut Vec<u8>, t: u8, s: &[u8]) {
    b.push(t);
    varint(b, s.len() as u64);
    b.extend_from_slice(s);
}

fn varint(b: &mut Vec<u8>, mut n: u64) {
    if n < 240 {
        b.push(n as u8);
        return;
    }
    b.push(n as u8 | 240);
    n = (n - 240) >> 4;
    while n >= 128 {
        b.push(n as u8 | 128);
        n = (n - 128) >> 7;
    }
    b.push(n as u8);
}

struct R<'a>(&'a [u8]);

impl R<'_> {
    fn take(&mut self, n: usize) -> Vec<u8> {
        let (h, t) = self.0.split_at(n);
        self.0 = t;
        h.to_vec()
    }

    fn byte(&mut self) -> u8 {
        self.take(1)[0]
    }

    fn varint(&mut self) -> u64 {
        let mut n = u64::from(self.byte());
        if n < 240 {
            return n;
        }
        let mut shift = 4;
        loop {
            let b = self.byte();
            n += u64::from(b) << shift;
            if b < 128 {
                return n;
            }
            shift += 7;
        }
    }

    fn bytes(&mut self) -> Vec<u8> {
        let n = self.varint() as usize;
        self.take(n)
    }

    fn kv(&mut self) -> (String, Arg) {
        let k = String::from_utf8(self.bytes()).unwrap();
        let t = self.byte();
        let v = match t & 0x0f {
            1 => Arg::Bool(t & 0x10 != 0),
            2..=5 => Arg::Int(self.varint()),
            6 => Arg::Ip(<[u8; 4]>::try_from(self.take(4)).unwrap().into()),
            7 => Arg::Ip(<[u8; 16]>::try_from(self.take(16)).unwrap().into()),
            8 | 9 => Arg::Bytes(self.bytes()),
            t => panic!("type {t}"),
        };
        (k, v)
    }
}
