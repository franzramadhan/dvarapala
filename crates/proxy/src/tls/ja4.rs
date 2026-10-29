//! JA4 of a TLS ClientHello (RFC 0012), from the FoxIO spec: protocol,
//! version, SNI, counts and ALPN, then truncated SHA-256 of the sorted
//! ciphers and of the sorted extensions with the signature algorithms.
#![allow(unused_variables, unused_imports, dead_code)]

use std::fmt::Write;

use dvarapala_l7::Ja4;
use ring::digest;

/// The JA4 of a ClientHello handshake message (type 1, its length, the
/// body). `None` for anything that is not one.
pub fn from_handshake(h: &[u8]) -> Option<Ja4> {
    todo!("rfc 0012")
}

/// First and last character of the first ALPN value, or of its hex when
/// either is not alphanumeric; `00` without one.
fn alpn_chars(v: &[u8]) -> String {
    todo!("rfc 0012")
}

/// GREASE values (RFC 8701): `0x?a?a` with both bytes equal.
fn grease(v: u16) -> bool {
    todo!("rfc 0012")
}

fn hex_list(v: &[u16]) -> String {
    todo!("rfc 0012")
}

/// First 12 hex characters of SHA-256, or twelve zeros for an empty list.
fn hash(s: &str) -> String {
    todo!("rfc 0012")
}

fn pairs(b: &[u8]) -> Option<Vec<u16>> {
    todo!("rfc 0012")
}

/// Bounds-checked reads; every miss is `None`.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        todo!("rfc 0012")
    }

    fn u8(&mut self) -> Option<u8> {
        todo!("rfc 0012")
    }

    fn u16(&mut self) -> Option<u16> {
        todo!("rfc 0012")
    }

    /// A `u16` length, then that many bytes.
    fn vec16(&mut self) -> Option<&'a [u8]> {
        todo!("rfc 0012")
    }

    fn u24(&mut self) -> Option<usize> {
        todo!("rfc 0012")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A ClientHello handshake message from its parts.
    pub(crate) fn hello(version: u16, ciphers: &[u16], exts: &[(u16, Vec<u8>)]) -> Vec<u8> {
        todo!("rfc 0012")
    }

    fn list16(v: &[u16]) -> Vec<u8> {
        todo!("rfc 0012")
    }

    /// The spec's Chrome example, with GREASE and shuffled extensions.
    pub(crate) fn chrome() -> Vec<u8> {
        todo!("rfc 0012")
    }

    #[test]
    #[ignore = "rfc 0012"]
    fn spec_chrome_example() {
        todo!("rfc 0012")
    }

    #[test]
    #[ignore = "rfc 0012"]
    fn bare_tls12_hello() {
        todo!("rfc 0012")
    }

    #[test]
    #[ignore = "rfc 0012"]
    fn alpn_falls_back_to_hex() {
        todo!("rfc 0012")
    }

    #[test]
    #[ignore = "rfc 0012"]
    fn truncated_or_wrong_is_none() {
        todo!("rfc 0012")
    }

    #[test]
    #[ignore = "rfc 0012"]
    fn grease_values() {
        todo!("rfc 0012")
    }
}
