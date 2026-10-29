#![allow(unused_variables, unused_imports, dead_code)]
use std::io;

use dvarapala_l7::Ja4;
use tokio::io::{AsyncRead, AsyncReadExt};

use super::ja4;

/// Largest ClientHello fingerprinted; a bigger one is served without.
const MAX_HELLO: usize = 16 * 1024;

/// Reads the ClientHello records off `io` (RFC 0012). Returns every byte
/// read, to be replayed to rustls, and the JA4 when the records hold a
/// whole ClientHello of at most [`MAX_HELLO`] bytes.
pub(crate) async fn read<IO: AsyncRead + Unpin>(io: &mut IO) -> io::Result<(Vec<u8>, Option<Ja4>)> {
    todo!("rfc 0012")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::ja4::tests::chrome;

    fn records(h: &[u8], split: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for part in [&h[..split], &h[split..]] {
            if part.is_empty() {
                continue;
            }
            out.extend_from_slice(&[0x16, 3, 1]);
            out.extend_from_slice(&(part.len() as u16).to_be_bytes());
            out.extend_from_slice(part);
        }
        out
    }

    #[tokio::test]
    #[ignore = "rfc 0012"]
    async fn one_record_or_two() {
        let h = chrome();
        for split in [h.len(), 2, 60] {
            let wire = records(&h, split);
            let mut with_tail = wire.clone();
            with_tail.extend_from_slice(b"next");
            let (seen, f) = read(&mut &with_tail[..]).await.unwrap();
            assert_eq!(seen, wire, "only the hello is read ({split})");
            assert_eq!(f.unwrap().as_str(), "t13d1516h2_8daaf6152771_e5627efa2ab1");
        }
    }

    #[tokio::test]
    #[ignore = "rfc 0012"]
    async fn oversized_or_not_tls_is_not_fingerprinted() {
        let mut big = vec![1, 0, 0x50, 0];
        big.resize(4 + 0x5000, 0);
        let wire = records(&big, 0x3000);
        let (seen, f) = read(&mut &wire[..]).await.unwrap();
        assert!(f.is_none());
        assert!(seen.len() <= MAX_HELLO + 10);
        let (seen, f) = read(&mut &b"GET / HTTP/1.1\r\n"[..]).await.unwrap();
        assert_eq!((seen.as_slice(), f), (&b"GET /"[..], None));
    }
}
