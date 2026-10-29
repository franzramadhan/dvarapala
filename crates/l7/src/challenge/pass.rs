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
        let mut random = [0u8; 32];
        let secret = if secret.is_empty() {
            SystemRandom::new()
                .fill(&mut random)
                .expect("system random source");
            &random[..]
        } else {
            secret
        };
        Self(hmac::Key::new(hmac::HMAC_SHA256, secret))
    }

    fn mac(&self, label: &[u8], key: ClientKey, t: u64) -> [u8; MAC_LEN] {
        let mut ctx = hmac::Context::with_key(&self.0);
        ctx.update(label);
        ctx.update(&key_bytes(key));
        ctx.update(&t.to_be_bytes());
        let tag = ctx.sign();
        let mut out = [0u8; MAC_LEN];
        out.copy_from_slice(&tag.as_ref()[..MAC_LEN]);
        out
    }

    /// The seed a client solves, issued at `issued` (Unix seconds).
    pub(crate) fn seed(&self, key: ClientKey, issued: u64) -> String {
        hex(&self.mac(b"seed", key, issued))
    }

    pub(crate) fn check_seed(&self, key: ClientKey, issued: u64, seed: &str) -> bool {
        unhex(seed).is_some_and(|s| same(&s, &self.mac(b"seed", key, issued)))
    }

    /// The cookie value of a pass that expires at `expires`.
    pub(crate) fn pass(&self, key: ClientKey, expires: u64) -> String {
        format!("{expires}.{}", hex(&self.mac(b"pass", key, expires)))
    }

    pub(crate) fn check_pass(&self, key: ClientKey, value: &str, now: u64) -> bool {
        let Some((expires, mac)) = value.split_once('.') else {
            return false;
        };
        let (Some(expires), Some(mac)) = (digits(expires), unhex(mac)) else {
            return false;
        };
        expires > now && same(&mac, &self.mac(b"pass", key, expires))
    }
}

/// A key as bytes: the family, then the IPv4 address or the /64.
fn key_bytes(key: ClientKey) -> [u8; 9] {
    let mut b = [0u8; 9];
    match key {
        ClientKey::V4(a) => {
            b[0] = 4;
            b[1..5].copy_from_slice(&a.octets());
        }
        ClientKey::V6(p) => {
            b[0] = 6;
            b[1..].copy_from_slice(&p.to_be_bytes());
        }
    }
    b
}

/// A decimal number of at most 19 digits (fits in `u64`), nothing else.
pub(crate) fn digits(s: &str) -> Option<u64> {
    (!s.is_empty() && s.len() <= 19 && s.bytes().all(|b| b.is_ascii_digit()))
        .then(|| s.parse().ok())?
}

fn hex(b: &[u8]) -> String {
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
}

fn unhex(s: &str) -> Option<[u8; MAC_LEN]> {
    let s = s.as_bytes();
    if s.len() != MAC_LEN * 2 {
        return None;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; MAC_LEN];
    for (i, o) in out.iter_mut().enumerate() {
        *o = nib(s[2 * i])? << 4 | nib(s[2 * i + 1])?;
    }
    Some(out)
}

/// Constant time in the content.
fn same(a: &[u8; MAC_LEN], b: &[u8; MAC_LEN]) -> bool {
    a.iter().zip(b).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    fn key(s: &str) -> ClientKey {
        s.parse::<IpAddr>().unwrap().into()
    }

    #[test]
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
