//! RFC 0017: the SPOP 2.0 frames a client sends and reads (HAProxy
//! `doc/SPOE.txt`, section 3). Pure, no I/O.
// rfc 0017: the stubs do not push yet
#![allow(clippy::ptr_arg)]
#![allow(unused_variables, unused_imports, dead_code)]

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
        todo!("rfc 0017")
    }

    /// A string or binary as UTF-8, lossy.
    pub fn text(&self) -> Option<String> {
        todo!("rfc 0017")
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
        todo!("rfc 0017")
    }
}

impl std::error::Error for Error {}

/// `HAPROXY-HELLO` with its 4-byte length.
pub fn hello(max_frame_size: u32) -> Vec<u8> {
    todo!("rfc 0017")
}

/// `NOTIFY` with one message, with its 4-byte length.
pub fn notify(stream: u64, frame: u64, name: &str, args: &[(&str, Value<'_>)]) -> Vec<u8> {
    todo!("rfc 0017")
}

/// One frame from the agent, without its 4-byte length.
pub fn decode(buf: &[u8]) -> Result<Agent<'_>, Error> {
    todo!("rfc 0017")
}

fn header(kind: u8, stream: u64, frame: u64) -> Vec<u8> {
    todo!("rfc 0017")
}

/// Writes the frame length in front.
fn finish(b: Vec<u8>) -> Vec<u8> {
    todo!("rfc 0017")
}

fn kv(b: &mut Vec<u8>, name: &str, v: Value<'_>) {
    todo!("rfc 0017")
}

fn bytes(b: &mut Vec<u8>, s: &[u8]) {
    todo!("rfc 0017")
}

fn value_len(v: &Value<'_>) -> usize {
    todo!("rfc 0017")
}

fn value(b: &mut Vec<u8>, v: Value<'_>) {
    todo!("rfc 0017")
}

fn typed_int(b: &mut Vec<u8>, kind: u8, n: u64) {
    todo!("rfc 0017")
}

/// HAProxy's varint (`encode_varint` in `include/haproxy/intops.h`).
pub fn varint(b: &mut Vec<u8>, n: u64) {
    todo!("rfc 0017")
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        todo!("rfc 0017")
    }

    fn byte(&mut self) -> Result<u8, Error> {
        todo!("rfc 0017")
    }

    /// `decode_varint` in `include/haproxy/intops.h`, bounded to 10 bytes.
    fn varint(&mut self) -> Result<u64, Error> {
        todo!("rfc 0017")
    }

    fn bytes(&mut self) -> Result<&'a [u8], Error> {
        todo!("rfc 0017")
    }

    fn kv(&mut self) -> Result<(&'a [u8], Value<'a>), Error> {
        todo!("rfc 0017")
    }

    fn value(&mut self) -> Result<Value<'a>, Error> {
        todo!("rfc 0017")
    }
}

/// Fuzz entry (RFC 0017 case 2): any bytes, never a panic.
pub fn fuzz_waf_frame(data: &[u8]) {
    todo!("rfc 0017")
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
    #[ignore = "rfc 0017"]
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
    #[ignore = "rfc 0017"]
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
    #[ignore = "rfc 0017"]
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
