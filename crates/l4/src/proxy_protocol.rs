//! The PROXY protocol header a TCP load balancer sends before the client's
//! bytes (RFC 0030): version 1 (text) and version 2 (binary). Parsing only,
//! no I/O; TLVs are skipped.
#![allow(unused_variables, unused_imports, dead_code)]

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The longest v1 line, `\r\n` included.
pub const MAX_V1: usize = 107;
/// The longest v2 header accepted: the 16-byte prefix and 216 bytes of
/// addresses and TLVs.
pub const MAX_V2: usize = 16 + 216;

const SIG_V2: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";
const SIG_V1: &[u8; 6] = b"PROXY ";

/// Which versions a listener accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    V1,
    V2,
    /// Either, told apart by the first byte.
    Any,
}

/// What a complete header says about the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The client the balancer proxies.
    Client(SocketAddr),
    /// `LOCAL` (v2), `UNKNOWN` (v1) or an address family without one: the
    /// balancer speaks for itself, keyed by its own address.
    Local,
}

/// The parse of the bytes read so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parsed {
    /// At least this many more bytes are needed.
    Incomplete(usize),
    /// A complete header of `len` bytes.
    Done { source: Source, len: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Invalid(pub &'static str);

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!("rfc 0030")
    }
}

impl std::error::Error for Invalid {}

/// Parses the start of a connection. Asks for more bytes rather than
/// guessing, and never for more than the header can hold, so a reader
/// that reads exactly what is asked never reads past the header.
pub fn parse(buf: &[u8], version: Version) -> Result<Parsed, Invalid> {
    todo!("rfc 0030")
}

fn v1(buf: &[u8]) -> Result<Parsed, Invalid> {
    todo!("rfc 0030")
}

fn v2(buf: &[u8]) -> Result<Parsed, Invalid> {
    todo!("rfc 0030")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn done(buf: &[u8], v: Version) -> (Source, usize) {
        match parse(buf, v) {
            Ok(Parsed::Done { source, len }) => (source, len),
            other => panic!("{other:?}"),
        }
    }

    fn client(s: &str) -> Source {
        Source::Client(s.parse().unwrap())
    }

    fn v2_header(cmd: u8, family: u8, addrs: &[u8]) -> Vec<u8> {
        let mut h = SIG_V2.to_vec();
        h.push(0x20 | cmd);
        h.push(family);
        h.extend_from_slice(&(addrs.len() as u16).to_be_bytes());
        h.extend_from_slice(addrs);
        h
    }

    /// RFC 0030 case 1
    #[test]
    #[ignore = "rfc 0030"]
    fn v1_lines() {
        let l = b"PROXY TCP4 192.0.2.10 198.51.100.1 4000 443\r\nGET";
        assert_eq!(done(l, Version::V1), (client("192.0.2.10:4000"), 45));
        let l = b"PROXY TCP6 2001:db8::1 2001:db8::2 4000 443\r\n";
        assert_eq!(
            done(l, Version::Any),
            (client("[2001:db8::1]:4000"), l.len())
        );
        let l = b"PROXY UNKNOWN ffff::1 ffff::2 1 2\r\n";
        assert_eq!(done(l, Version::V1), (Source::Local, l.len()));
        assert_eq!(done(b"PROXY UNKNOWN\r\n", Version::V1).0, Source::Local);
    }

    /// RFC 0030 case 2
    #[test]
    #[ignore = "rfc 0030"]
    fn v2_headers() {
        let mut a = vec![192, 0, 2, 10, 198, 51, 100, 1];
        a.extend_from_slice(&4000u16.to_be_bytes());
        a.extend_from_slice(&443u16.to_be_bytes());
        // a TLV after the addresses is skipped
        a.extend_from_slice(&[0x01, 0x00, 0x02, b'h', b'2']);
        let h = v2_header(1, 0x11, &a);
        let mut wire = h.clone();
        wire.extend_from_slice(b"GET / HTTP/1.1\r\n");
        assert_eq!(
            done(&wire, Version::V2),
            (client("192.0.2.10:4000"), h.len())
        );
        let mut a = "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets().to_vec();
        a.extend_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        a.extend_from_slice(&[0x0f, 0xa0, 0x01, 0xbb]);
        let h = v2_header(1, 0x21, &a);
        assert_eq!(
            done(&h, Version::Any),
            (client("[2001:db8::1]:4000"), h.len())
        );
        let h = v2_header(0, 0x00, &[]);
        assert_eq!(done(&h, Version::V2), (Source::Local, 16));
    }

    /// RFC 0030 case 3
    #[test]
    #[ignore = "rfc 0030"]
    fn bad_and_oversized_headers() {
        let mut long = v2_header(1, 0x11, &[]);
        long[14..16].copy_from_slice(&217u16.to_be_bytes());
        assert_eq!(
            parse(&long, Version::V2),
            Err(Invalid("v2 header too long"))
        );
        let mut sig = v2_header(1, 0x11, &[0; 12]);
        sig[5] = b'X';
        assert!(parse(&sig, Version::V2).is_err());
        let mut line = b"PROXY TCP4 192.0.2.10 198.51.100.1 4000 443".to_vec();
        line.resize(MAX_V1, b' ');
        assert_eq!(parse(&line, Version::V1), Err(Invalid("v1 line too long")));
        // the version must be the one configured
        assert!(parse(&v2_header(0, 0, &[]), Version::V1).is_err());
        assert!(parse(b"PROXY UNKNOWN\r\n", Version::V2).is_err());
        assert!(parse(b"GET / HTTP/1.1\r\n", Version::Any).is_err());
        for bad in [
            &b"PROXY TCP4 2001:db8::1 192.0.2.1 1 2\r\n"[..],
            b"PROXY TCP4 192.0.2.1 192.0.2.2 01 2\r\n",
            b"PROXY TCP4 192.0.2.1 192.0.2.2 1 2 3\r\n",
            b"PROXY TCP4 192.0.2.1 192.0.2.2 1\r\n",
            b"PROXY UDP4 192.0.2.1 192.0.2.2 1 2\r\n",
        ] {
            assert!(parse(bad, Version::V1).is_err(), "{bad:?}");
        }
        // a short v2 address block for its family
        assert!(parse(&v2_header(1, 0x11, &[0; 8]), Version::V2).is_err());
    }

    /// Asks for exactly what is missing, never past the header.
    #[test]
    #[ignore = "rfc 0030"]
    fn incomplete_asks_for_the_rest() {
        assert_eq!(parse(&[], Version::Any), Ok(Parsed::Incomplete(1)));
        assert_eq!(parse(b"\r\n\r", Version::V2), Ok(Parsed::Incomplete(13)));
        let h = v2_header(1, 0x11, &[0; 12]);
        assert_eq!(parse(&h[..16], Version::V2), Ok(Parsed::Incomplete(12)));
        assert_eq!(parse(b"PROX", Version::V1), Ok(Parsed::Incomplete(1)));
        assert_eq!(
            parse(b"PROXY TCP4 1", Version::V1),
            Ok(Parsed::Incomplete(1))
        );
    }
}
