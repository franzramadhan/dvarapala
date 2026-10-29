#![allow(unused_variables, unused_imports, dead_code)]
use std::fmt::Write;

use dvarapala_engine::ClientKey;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};

/// MACs are cut to 128 bits: enough against forgery for an hour-long pass,
/// and short in a cookie.
const MAC_LEN: usize = 16;

/// HMAC-SHA256 seeds and passes, bound to a client key. No server state.
pub(crate) struct Keys(hmac::Key);

impl Keys {
    /// An empty secret gets a random key for this process.
    pub(crate) fn new(secret: &[u8]) -> Self {
        todo!("rfc 0012")
    }

    fn mac(&self, label: &[u8], key: ClientKey, t: u64) -> [u8; MAC_LEN] {
        todo!("rfc 0012")
    }

    /// The seed a client solves, issued at `issued` (Unix seconds).
    pub(crate) fn seed(&self, key: ClientKey, issued: u64) -> String {
        todo!("rfc 0012")
    }

    pub(crate) fn check_seed(&self, key: ClientKey, issued: u64, seed: &str) -> bool {
        todo!("rfc 0012")
    }

    /// The cookie value of a pass that expires at `expires`.
    pub(crate) fn pass(&self, key: ClientKey, expires: u64) -> String {
        todo!("rfc 0012")
    }

    pub(crate) fn check_pass(&self, key: ClientKey, value: &str, now: u64) -> bool {
        todo!("rfc 0012")
    }
}

/// A key as bytes: the family, then the IPv4 address or the /64.
fn key_bytes(key: ClientKey) -> [u8; 9] {
    todo!("rfc 0012")
}

/// A decimal number of at most 19 digits (fits in `u64`), nothing else.
pub(crate) fn digits(s: &str) -> Option<u64> {
    todo!("rfc 0012")
}

fn hex(b: &[u8]) -> String {
    todo!("rfc 0012")
}

fn unhex(s: &str) -> Option<[u8; MAC_LEN]> {
    todo!("rfc 0012")
}

/// Constant time in the content.
fn same(a: &[u8; MAC_LEN], b: &[u8; MAC_LEN]) -> bool {
    todo!("rfc 0012")
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    fn key(s: &str) -> ClientKey {
        s.parse::<IpAddr>().unwrap().into()
    }

    #[test]
    #[ignore = "rfc 0012"]
    fn pass_bound_to_key_and_expiry() {
        let k = Keys::new(&[7; 32]);
        let (a, b) = (key("192.0.2.1"), key("192.0.2.2"));
        let p = k.pass(a, 1000);
        assert!(k.check_pass(a, &p, 999));
        assert!(!k.check_pass(b, &p, 999), "another key");
        assert!(!k.check_pass(a, &p, 1000), "expired");
        let mut tampered = p.clone().into_bytes();
        let last = tampered.len() - 1;
        tampered[last] = if tampered[last] == b'0' { b'1' } else { b'0' };
        assert!(!k.check_pass(a, std::str::from_utf8(&tampered).unwrap(), 999));
        // a later expiry with the old MAC
        let mac = p.split_once('.').unwrap().1;
        assert!(!k.check_pass(a, &format!("2000.{mac}"), 999));
        for bad in ["", ".", "1000", "1000.", "x.00", "1000.zz", "+1000.00"] {
            assert!(!k.check_pass(a, bad, 0), "{bad:?}");
        }
    }

    #[test]
    #[ignore = "rfc 0012"]
    fn seeds_differ_by_key_time_and_secret() {
        let (k, other) = (Keys::new(&[7; 32]), Keys::new(&[8; 32]));
        let a = key("2001:db8::1");
        let s = k.seed(a, 5);
        assert!(k.check_seed(a, 5, &s));
        assert!(k.check_seed(key("2001:db8::2"), 5, &s), "same /64");
        assert!(!k.check_seed(key("2001:db8:1::1"), 5, &s));
        assert!(!k.check_seed(a, 6, &s));
        assert!(!other.check_seed(a, 5, &s));
        assert_ne!(
            Keys::new(&[]).seed(a, 5),
            Keys::new(&[]).seed(a, 5),
            "random keys"
        );
    }
}
