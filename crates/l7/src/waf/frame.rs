//! RFC 0017: the SPOP 2.0 frames a client sends and reads (HAProxy
//! `doc/SPOE.txt`, section 3). Pure, no I/O.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const VERSION: &str = "2.0";
/// The smallest frame size a peer may announce.
pub const MIN_FRAME: u32 = 256;

const HAPROXY_HELLO: u8 = 1;
const NOTIFY: u8 = 3;
const AGENT_HELLO: u8 = 101;
const AGENT_DISCONNECT: u8 = 102;
const ACK: u8 = 103;
/// Every frame is final: fragmentation is deprecated.
const FIN: u32 = 1;
const SET_VAR: u8 = 1;
const UNSET_VAR: u8 = 2;
/// A `u64` takes 10 varint bytes at most.
const MAX_VARINT: usize = 10;

/// Typed data (section 3.1). Strings and binaries borrow the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value<'a> {
    Null,
    Bool(bool),
    Int32(i32),
    Uint32(u32),
    Int64(i64),
    Uint64(u64),
    Ip(IpAddr),
    Str(&'a [u8]),
    Bin(&'a [u8]),
}

impl Value<'_> {
    /// Any integer type as `i64`; `None` for the rest or out of range.
    pub fn int(&self) -> Option<i64> {
        match *self {
            Self::Int32(v) => Some(v.into()),
            Self::Uint32(v) => Some(v.into()),
            Self::Int64(v) => Some(v),
            Self::Uint64(v) => v.try_into().ok(),
            _ => None,
        }
    }

    /// A string or binary as UTF-8, lossy.
    pub fn text(&self) -> Option<String> {
        match self {
            Self::Str(b) | Self::Bin(b) => Some(String::from_utf8_lossy(b).into_owned()),
            _ => None,
        }
    }
}

/// A frame from the agent.
#[derive(Debug, PartialEq, Eq)]
pub enum Agent<'a> {
    Hello {
        version: &'a [u8],
        max_frame_size: u32,
    },
    /// `set-var` actions as (name, value); `unset-var` is skipped.
    Ack {
        stream: u64,
        frame: u64,
        vars: Vec<(&'a [u8], Value<'a>)>,
    },
    Disconnect {
        status: u32,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub &'static str);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Error {}

/// `HAPROXY-HELLO` with its 4-byte length.
pub fn hello(max_frame_size: u32) -> Vec<u8> {
    let mut b = header(HAPROXY_HELLO, 0, 0);
    kv(&mut b, "supported-versions", Value::Str(VERSION.as_bytes()));
    kv(&mut b, "max-frame-size", Value::Uint32(max_frame_size));
    kv(&mut b, "capabilities", Value::Str(b""));
    finish(b)
}

/// `NOTIFY` with one message, with its 4-byte length.
pub fn notify(stream: u64, frame: u64, name: &str, args: &[(&str, Value<'_>)]) -> Vec<u8> {
    let size = args.iter().map(|(_, v)| value_len(v) + 32).sum::<usize>();
    let mut b = header(NOTIFY, stream, frame);
    b.reserve(size + name.len() + 8);
    bytes(&mut b, name.as_bytes());
    // the message list counts arguments in one byte
    b.push(args.len().min(255) as u8);
    for (k, v) in args.iter().take(255) {
        kv(&mut b, k, *v);
    }
    finish(b)
}

/// One frame from the agent, without its 4-byte length.
pub fn decode(buf: &[u8]) -> Result<Agent<'_>, Error> {
    let mut r = Reader(buf);
    let kind = r.byte()?;
    let _flags = r.take(4)?;
    let stream = r.varint()?;
    let frame = r.varint()?;
    match kind {
        AGENT_HELLO => {
            let (mut version, mut max) = (None, None);
            while !r.0.is_empty() {
                let (k, v) = r.kv()?;
                match (k, v) {
                    (b"version", Value::Str(s)) => version = Some(s),
                    (b"max-frame-size", v) => {
                        max = v.int().and_then(|n| u32::try_from(n).ok());
                    }
                    _ => {}
                }
            }
            Ok(Agent::Hello {
                version: version.ok_or(Error("AGENT-HELLO without version"))?,
                max_frame_size: max.ok_or(Error("AGENT-HELLO without max-frame-size"))?,
            })
        }
        ACK => {
            let mut vars = Vec::new();
            while !r.0.is_empty() {
                let action = r.byte()?;
                let _nb_args = r.byte()?;
                let _scope = r.byte()?;
                let name = r.bytes()?;
                match action {
                    SET_VAR => vars.push((name, r.value()?)),
                    UNSET_VAR => {}
                    _ => return Err(Error("unknown action")),
                }
            }
            Ok(Agent::Ack {
                stream,
                frame,
                vars,
            })
        }
        AGENT_DISCONNECT => {
            let (mut status, mut message) = (0, String::new());
            while !r.0.is_empty() {
                match r.kv()? {
                    (b"status-code", v) => {
                        status = v.int().and_then(|n| u32::try_from(n).ok()).unwrap_or(0);
                    }
                    (b"message", v) => message = v.text().unwrap_or_default(),
                    _ => {}
                }
            }
            Ok(Agent::Disconnect { status, message })
        }
        _ => Err(Error("unknown frame type")),
    }
}

fn header(kind: u8, stream: u64, frame: u64) -> Vec<u8> {
    let mut b = vec![0; 4];
    b.push(kind);
    b.extend_from_slice(&FIN.to_be_bytes());
    varint(&mut b, stream);
    varint(&mut b, frame);
    b
}

/// Writes the frame length in front.
fn finish(mut b: Vec<u8>) -> Vec<u8> {
    let len = u32::try_from(b.len() - 4).unwrap_or(u32::MAX);
    b[..4].copy_from_slice(&len.to_be_bytes());
    b
}

fn kv(b: &mut Vec<u8>, name: &str, v: Value<'_>) {
    bytes(b, name.as_bytes());
    value(b, v);
}

fn bytes(b: &mut Vec<u8>, s: &[u8]) {
    varint(b, s.len() as u64);
    b.extend_from_slice(s);
}

fn value_len(v: &Value<'_>) -> usize {
    match v {
        Value::Str(s) | Value::Bin(s) => s.len() + MAX_VARINT + 1,
        _ => 17,
    }
}

fn value(b: &mut Vec<u8>, v: Value<'_>) {
    match v {
        Value::Null => b.push(0),
        Value::Bool(t) => b.push(1 | (u8::from(t) << 4)),
        Value::Int32(n) => typed_int(b, 2, n as i64 as u64),
        Value::Uint32(n) => typed_int(b, 3, n.into()),
        Value::Int64(n) => typed_int(b, 4, n as u64),
        Value::Uint64(n) => typed_int(b, 5, n),
        Value::Ip(IpAddr::V4(a)) => {
            b.push(6);
            b.extend_from_slice(&a.octets());
        }
        Value::Ip(IpAddr::V6(a)) => {
            b.push(7);
            b.extend_from_slice(&a.octets());
        }
        Value::Str(s) => {
            b.push(8);
            bytes(b, s);
        }
        Value::Bin(s) => {
            b.push(9);
            bytes(b, s);
        }
    }
}

fn typed_int(b: &mut Vec<u8>, kind: u8, n: u64) {
    b.push(kind);
    varint(b, n);
}

/// HAProxy's varint (`encode_varint` in `include/haproxy/intops.h`).
pub fn varint(b: &mut Vec<u8>, mut n: u64) {
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

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.0.len() < n {
            return Err(Error("truncated frame"));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    /// `decode_varint` in `include/haproxy/intops.h`, bounded to 10 bytes.
    fn varint(&mut self) -> Result<u64, Error> {
        let mut n = u64::from(self.byte()?);
        if n < 240 {
            return Ok(n);
        }
        let mut shift = 4;
        for _ in 1..MAX_VARINT {
            let b = self.byte()?;
            n = u64::from(b)
                .checked_shl(shift)
                .and_then(|v| n.checked_add(v))
                .ok_or(Error("varint overflow"))?;
            if b < 128 {
                return Ok(n);
            }
            shift += 7;
        }
        Err(Error("varint too long"))
    }

    fn bytes(&mut self) -> Result<&'a [u8], Error> {
        let n = self.varint()?;
        self.take(usize::try_from(n).map_err(|_| Error("length overflow"))?)
    }

    fn kv(&mut self) -> Result<(&'a [u8], Value<'a>), Error> {
        Ok((self.bytes()?, self.value()?))
    }

    fn value(&mut self) -> Result<Value<'a>, Error> {
        let t = self.byte()?;
        Ok(match t & 0x0f {
            0 => Value::Null,
            1 => Value::Bool(t & 0x10 != 0),
            2 => Value::Int32(self.varint()? as i64 as i32),
            3 => Value::Uint32(self.varint()? as u32),
            4 => Value::Int64(self.varint()? as i64),
            5 => Value::Uint64(self.varint()?),
            6 => {
                let o: [u8; 4] = self.take(4)?.try_into().map_err(|_| Error("ipv4"))?;
                Value::Ip(Ipv4Addr::from(o).into())
            }
            7 => {
                let o: [u8; 16] = self.take(16)?.try_into().map_err(|_| Error("ipv6"))?;
                Value::Ip(Ipv6Addr::from(o).into())
            }
            8 => Value::Str(self.bytes()?),
            9 => Value::Bin(self.bytes()?),
            _ => return Err(Error("unknown data type")),
        })
    }
}

/// Fuzz entry (RFC 0017 case 2): any bytes, never a panic.
pub fn fuzz_waf_frame(data: &[u8]) {
    let _ = decode(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(n: u64) -> (usize, u64) {
        let mut b = Vec::new();
        varint(&mut b, n);
        (b.len(), Reader(&b).varint().unwrap())
    }

    // RFC 0017 case 1
    #[test]
    fn varints_match_the_boundaries() {
        for (n, len) in [
            (0, 1),
            (239, 1),
            (240, 2),
            (2287, 2),
            (2288, 3),
            (264_431, 3),
            (264_432, 4),
            (33_818_863, 4),
            (33_818_864, 5),
            (u64::MAX, 10),
        ] {
            assert_eq!(roundtrip(n), (len, n), "{n}");
        }
        let mut b = Vec::new();
        varint(&mut b, 1000);
        // [1111 XXXX] [0XXX XXXX]: 1000 = 0xf8 + (0x2f << 4)
        assert_eq!(b, [0xf8, 0x2f]);
    }

    /// An agent frame as `coraza-spoa` writes it.
    fn agent(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut b = vec![kind];
        b.extend_from_slice(&FIN.to_be_bytes());
        b.extend_from_slice(&[7, 1]);
        b.extend_from_slice(body);
        b
    }

    // RFC 0017 case 1
    #[test]
    fn frames_round_trip() {
        let h = hello(70_000);
        assert_eq!(
            u32::from_be_bytes(h[..4].try_into().unwrap()) as usize,
            h.len() - 4
        );
        assert_eq!(&h[4..10], &[HAPROXY_HELLO, 0, 0, 0, 1, 0]);

        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let args = [
            ("app", Value::Str(b"app")),
            ("src-ip", Value::Ip(ip)),
            ("src-port", Value::Uint32(443)),
            ("n", Value::Int64(-5)),
            ("body", Value::Bin(&[0, 255, 10])),
            ("x", Value::Bool(true)),
            ("z", Value::Null),
        ];
        let n = notify(7, 1, "coraza-req", &args);
        // read it back with the agent's reader: header, name, count, kvs
        let mut r = Reader(&n[4..]);
        assert_eq!(r.byte().unwrap(), NOTIFY);
        r.take(4).unwrap();
        assert_eq!((r.varint().unwrap(), r.varint().unwrap()), (7, 1));
        assert_eq!(r.bytes().unwrap(), b"coraza-req");
        assert_eq!(r.byte().unwrap() as usize, args.len());
        for (k, v) in args {
            assert_eq!(r.kv().unwrap(), (k.as_bytes(), v));
        }
        assert!(r.0.is_empty());

        let mut body = Vec::new();
        kv(&mut body, "version", Value::Str(b"2.0"));
        kv(&mut body, "max-frame-size", Value::Uint32(16_384));
        kv(&mut body, "capabilities", Value::Str(b""));
        assert_eq!(
            decode(&agent(AGENT_HELLO, &body)),
            Ok(Agent::Hello {
                version: b"2.0",
                max_frame_size: 16_384
            })
        );

        let mut acts = vec![SET_VAR, 3, 2];
        bytes(&mut acts, b"action");
        value(&mut acts, Value::Str(b"deny"));
        acts.extend_from_slice(&[UNSET_VAR, 2, 2]);
        bytes(&mut acts, b"gone");
        acts.extend_from_slice(&[SET_VAR, 3, 2]);
        bytes(&mut acts, b"status");
        value(&mut acts, Value::Int64(403));
        assert_eq!(
            decode(&agent(ACK, &acts)),
            Ok(Agent::Ack {
                stream: 7,
                frame: 1,
                vars: vec![
                    (&b"action"[..], Value::Str(b"deny")),
                    (b"status", Value::Int64(403))
                ]
            })
        );

        let mut body = Vec::new();
        kv(&mut body, "status-code", Value::Uint32(3));
        kv(&mut body, "message", Value::Str(b"bye"));
        assert_eq!(
            decode(&agent(AGENT_DISCONNECT, &body)),
            Ok(Agent::Disconnect {
                status: 3,
                message: "bye".into()
            })
        );
    }

    // RFC 0017 case 2
    #[test]
    fn bad_frames_are_errors() {
        let mut ok = Vec::new();
        kv(&mut ok, "version", Value::Str(b"2.0"));
        kv(&mut ok, "max-frame-size", Value::Uint32(1024));
        let full = agent(AGENT_HELLO, &ok);
        for n in 0..full.len() {
            assert!(decode(&full[..n]).is_err(), "truncated at {n}");
        }
        assert_eq!(decode(&agent(42, &[])), Err(Error("unknown frame type")));
        assert_eq!(
            decode(&agent(ACK, &[9, 0, 2, 0])),
            Err(Error("unknown action"))
        );
        let mut bad = agent(ACK, &[SET_VAR, 3, 2, 1, b'x']);
        bad.push(0x0e);
        assert_eq!(decode(&bad), Err(Error("unknown data type")));
        let long = agent(
            ACK,
            &[
                SET_VAR, 3, 2, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            ],
        );
        assert!(decode(&long).is_err());
        assert!(decode(&agent(AGENT_HELLO, &[])).is_err());
    }
}
