//! JA4 of a TLS ClientHello (RFC 0012), from the FoxIO spec: protocol,
//! version, SNI, counts and ALPN, then truncated SHA-256 of the sorted
//! ciphers and of the sorted extensions with the signature algorithms.

use std::fmt::Write;

use dvarapala_l7::Ja4;
use ring::digest;

/// The JA4 of a ClientHello handshake message (type 1, its length, the
/// body). `None` for anything that is not one.
pub fn from_handshake(h: &[u8]) -> Option<Ja4> {
    let mut r = Reader(h);
    if r.u8()? != 1 {
        return None;
    }
    let len = r.u24()?;
    let mut r = Reader(r.take(len)?);
    let legacy = r.u16()?;
    r.take(32)?;
    let sid = r.u8()?;
    r.take(sid.into())?;
    let ciphers: Vec<u16> = pairs(r.vec16()?)?
        .into_iter()
        .filter(|c| !grease(*c))
        .collect();
    let comp = r.u8()?;
    r.take(comp.into())?;
    let (mut exts, mut sni, mut alpn, mut sigs, mut version) =
        (Vec::new(), false, None, Vec::new(), legacy);
    if !r.0.is_empty() {
        let mut e = Reader(r.vec16()?);
        while !e.0.is_empty() {
            let t = e.u16()?;
            let data = e.vec16()?;
            if grease(t) {
                continue;
            }
            exts.push(t);
            let mut d = Reader(data);
            match t {
                0x0000 => sni = true,
                0x0010 => {
                    let mut list = Reader(d.vec16()?);
                    let n = list.u8()?;
                    alpn = Some(list.take(n.into())?);
                }
                0x000d => sigs = pairs(d.vec16()?)?,
                0x002b => {
                    let n = d.u8()?;
                    version = pairs(d.take(n.into())?)?
                        .into_iter()
                        .filter(|v| !grease(*v))
                        .max()
                        .unwrap_or(legacy);
                }
                _ => {}
            }
        }
    }
    sigs.retain(|s| !grease(*s));
    let mut a = String::with_capacity(36);
    a.push('t');
    a.push_str(match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    });
    a.push(if sni { 'd' } else { 'i' });
    let _ = write!(a, "{:02}{:02}", ciphers.len().min(99), exts.len().min(99));
    a.push_str(&alpn_chars(alpn.unwrap_or_default()));
    a.push('_');
    let mut sorted = ciphers;
    sorted.sort_unstable();
    a.push_str(&hash(&hex_list(&sorted)));
    a.push('_');
    let mut rest: Vec<u16> = exts
        .into_iter()
        .filter(|e| !matches!(e, 0x0000 | 0x0010))
        .collect();
    rest.sort_unstable();
    let mut c = hex_list(&rest);
    if !rest.is_empty() && !sigs.is_empty() {
        c.push('_');
        c.push_str(&hex_list(&sigs));
    }
    a.push_str(&hash(&c));
    Ja4::new(a.into_bytes().try_into().ok()?)
}

/// First and last character of the first ALPN value, or of its hex when
/// either is not alphanumeric; `00` without one.
fn alpn_chars(v: &[u8]) -> String {
    match (v.first(), v.last()) {
        (Some(f), Some(l)) if f.is_ascii_alphanumeric() && l.is_ascii_alphanumeric() => {
            format!("{}{}", *f as char, *l as char)
        }
        (Some(f), Some(l)) => format!("{:x}{:x}", f >> 4, l & 0xf),
        _ => "00".into(),
    }
}

/// GREASE values (RFC 8701): `0x?a?a` with both bytes equal.
fn grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff
}

fn hex_list(v: &[u16]) -> String {
    let mut s = String::with_capacity(v.len() * 5);
    for (i, x) in v.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let _ = write!(s, "{x:04x}");
    }
    s
}

/// First 12 hex characters of SHA-256, or twelve zeros for an empty list.
fn hash(s: &str) -> String {
    if s.is_empty() {
        return "000000000000".into();
    }
    let d = digest::digest(&digest::SHA256, s.as_bytes());
    d.as_ref()[..6]
        .iter()
        .fold(String::with_capacity(12), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

fn pairs(b: &[u8]) -> Option<Vec<u16>> {
    let (chunks, rest) = b.as_chunks::<2>();
    rest.is_empty()
        .then(|| chunks.iter().map(|c| u16::from_be_bytes(*c)).collect())
}

/// Bounds-checked reads; every miss is `None`.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.0.split_at_checked(n)?;
        self.0 = tail;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }

    /// A `u16` length, then that many bytes.
    fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()?;
        self.take(n.into())
    }

    fn u24(&mut self) -> Option<usize> {
        let b = self.take(3)?;
        Some(usize::from(b[0]) << 16 | usize::from(b[1]) << 8 | usize::from(b[2]))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A ClientHello handshake message from its parts.
    pub(crate) fn hello(version: u16, ciphers: &[u16], exts: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&version.to_be_bytes());
        body.extend_from_slice(&[7; 32]);
        body.push(0);
        body.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
        for c in ciphers {
            body.extend_from_slice(&c.to_be_bytes());
        }
        body.extend_from_slice(&[1, 0]);
        if !exts.is_empty() {
            let mut e = Vec::new();
            for (t, d) in exts {
                e.extend_from_slice(&t.to_be_bytes());
                e.extend_from_slice(&(d.len() as u16).to_be_bytes());
                e.extend_from_slice(d);
            }
            body.extend_from_slice(&(e.len() as u16).to_be_bytes());
            body.extend_from_slice(&e);
        }
        let mut h = vec![1];
        h.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        h.extend_from_slice(&body);
        h
    }

    fn list16(v: &[u16]) -> Vec<u8> {
        let mut d = ((v.len() * 2) as u16).to_be_bytes().to_vec();
        for x in v {
            d.extend_from_slice(&x.to_be_bytes());
        }
        d
    }

    /// The spec's Chrome example, with GREASE and shuffled extensions.
    pub(crate) fn chrome() -> Vec<u8> {
        let ciphers = [
            0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
            0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ];
        let sigs = [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ];
        let mut sni = vec![0, 14, 0, 0, 11];
        sni.extend_from_slice(b"example.com");
        let alpn = vec![
            0, 12, 2, b'h', b'2', 8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
        ];
        let exts = vec![
            (0x2a2a, vec![]),
            (0x0033, vec![0, 0]),
            (0x0000, sni),
            (0x0010, alpn),
            (0x002b, vec![4, 0x3a, 0x3a, 0x03, 0x04]),
            (0x000d, list16(&sigs)),
            (0x0005, vec![]),
            (0x000a, vec![]),
            (0x000b, vec![]),
            (0x0012, vec![]),
            (0x0015, vec![]),
            (0x0017, vec![]),
            (0x001b, vec![]),
            (0x0023, vec![]),
            (0x002d, vec![]),
            (0x4469, vec![]),
            (0xff01, vec![]),
            (0xfafa, vec![]),
        ];
        hello(0x0303, &ciphers, &exts)
    }

    #[test]
    fn spec_chrome_example() {
        let f = from_handshake(&chrome()).unwrap();
        assert_eq!(f.as_str(), "t13d1516h2_8daaf6152771_e5627efa2ab1");
    }

    #[test]
    fn bare_tls12_hello() {
        let f = from_handshake(&hello(0x0303, &[0x002f], &[])).unwrap();
        assert_eq!(&f.as_str()[..11], "t12i010000_");
        assert!(f.as_str().ends_with("_000000000000"));
        let f = from_handshake(&hello(0x0303, &[], &[])).unwrap();
        assert_eq!(f.as_str(), "t12i000000_000000000000_000000000000");
    }

    #[test]
    fn alpn_falls_back_to_hex() {
        assert_eq!(alpn_chars(b"h2"), "h2");
        assert_eq!(alpn_chars(b"h"), "hh");
        assert_eq!(alpn_chars(&[0xab, b'x']), "a8");
        assert_eq!(alpn_chars(b""), "00");
    }

    #[test]
    fn truncated_or_wrong_is_none() {
        let h = chrome();
        for n in [0, 1, 4, 40, h.len() - 1] {
            assert!(from_handshake(&h[..n]).is_none(), "{n}");
        }
        let mut wrong = h.clone();
        wrong[0] = 2;
        assert!(from_handshake(&wrong).is_none());
    }

    #[test]
    fn grease_values() {
        assert!(grease(0x0a0a) && grease(0xfafa) && grease(0x3a3a));
        assert!(!grease(0x0a1a) && !grease(0x1301));
    }
}
