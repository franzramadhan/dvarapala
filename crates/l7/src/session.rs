//! Admin console sessions (RFC 0018): random ids behind a cookie, bounded,
//! expiring, in memory only.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};

/// How a session was opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Token,
    Oidc,
}

impl Method {
    pub fn name(self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::Oidc => "oidc",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// `token`, or the email or OIDC `sub`.
    pub subject: String,
    pub method: Method,
    /// The `X-Dvarapala-Csrf` value state changing calls must carry.
    pub csrf: String,
    pub expires: Instant,
}

/// Sessions keyed by the SHA-256 of their id: a lookup hashes the cookie
/// first, so its timing says nothing about the ids held.
pub struct Sessions {
    max: usize,
    ttl: Duration,
    map: Mutex<HashMap<[u8; 32], Session>>,
}

impl Sessions {
    pub fn new(max: usize, ttl: Duration) -> Self {
        Self {
            max: max.max(1),
            ttl,
            map: Mutex::new(HashMap::new()),
        }
    }

    /// Opens a session; returns its id for the cookie. Drops the expired
    /// sessions, then the oldest one when full.
    pub fn create(&self, subject: String, method: Method, now: Instant) -> (String, Session) {
        let id = random_hex();
        let s = Session {
            subject,
            method,
            csrf: random_hex(),
            expires: now + self.ttl,
        };
        let mut map = self.lock();
        map.retain(|_, s| s.expires > now);
        if map.len() >= self.max {
            // ponytail: O(n) scan over at most `max` (64 by default)
            if let Some(k) = map.iter().min_by_key(|(_, s)| s.expires).map(|(k, _)| *k) {
                map.remove(&k);
            }
        }
        map.insert(key(&id), s.clone());
        (id, s)
    }

    /// The session behind `id`, if alive.
    pub fn get(&self, id: &str, now: Instant) -> Option<Session> {
        let k = key(id);
        let mut map = self.lock();
        match map.get(&k) {
            Some(s) if s.expires > now => Some(s.clone()),
            Some(_) => {
                map.remove(&k);
                None
            }
            None => None,
        }
    }

    pub fn remove(&self, id: &str) -> bool {
        self.lock().remove(&key(id)).is_some()
    }

    /// Sessions alive at `now`.
    pub fn len(&self, now: Instant) -> usize {
        self.lock().values().filter(|s| s.expires > now).count()
    }

    pub fn is_empty(&self, now: Instant) -> bool {
        self.len(now) == 0
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 32], Session>> {
        self.map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn key(id: &str) -> [u8; 32] {
    let mut k = [0; 32];
    k.copy_from_slice(digest(&SHA256, id.as_bytes()).as_ref());
    k
}

/// 256 random bits, hex encoded.
pub(crate) fn random_hex() -> String {
    hex(&random::<32>())
}

pub(crate) fn random<const N: usize>() -> [u8; N] {
    let mut b = [0; N];
    // the system RNG failing leaves nothing safe to hand out: fail closed
    SystemRandom::new()
        .fill(&mut b)
        .expect("system random generator");
    b
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Equal in time that depends only on the lengths.
pub fn same(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y));
    std::hint::black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 0018 case 1
    #[test]
    fn bounded_and_expiring() {
        let now = Instant::now();
        let s = Sessions::new(2, Duration::from_secs(3600));
        let (a, _) = s.create("a".into(), Method::Token, now);
        let (b, _) = s.create("b".into(), Method::Token, now + Duration::from_secs(1));
        let (c, _) = s.create("c".into(), Method::Oidc, now + Duration::from_secs(2));
        assert_eq!(s.get(&a, now), None, "the oldest is dropped");
        assert_eq!(s.get(&b, now).unwrap().subject, "b");
        assert_eq!(s.get(&c, now).unwrap().method, Method::Oidc);
        let later = now + Duration::from_secs(3601);
        assert_eq!(s.get(&b, later), None, "expired");
        assert_eq!(s.len(later), 1);
        assert!(s.remove(&c));
        assert!(s.is_empty(now));
    }

    // RFC 0018 case 2
    #[test]
    fn lookup_needs_the_exact_id() {
        let now = Instant::now();
        let s = Sessions::new(4, Duration::from_secs(60));
        let (id, made) = s.create("a".into(), Method::Token, now);
        assert_eq!(id.len(), 64);
        assert_eq!(made.csrf.len(), 64);
        assert_ne!(made.csrf, id);
        assert_eq!(s.get(&id, now), Some(made));
        let mut flipped = id.clone().into_bytes();
        flipped[10] ^= 1;
        assert_eq!(s.get(std::str::from_utf8(&flipped).unwrap(), now), None);
        assert_eq!(s.get(&id[..63], now), None);
        assert_eq!(s.get("", now), None);
        assert!(same(b"abc", b"abc"));
        assert!(!same(b"abc", b"abd"));
        assert!(!same(b"abc", b"ab"));
    }
}
