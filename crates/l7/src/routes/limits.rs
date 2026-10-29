use std::hash::{BuildHasher, RandomState};
use std::num::NonZeroUsize;
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use dvarapala_engine::{ClientKey, Limit, Table, Verdict};
use http::HeaderMap;
use http::header::HeaderName;

use crate::Ja4;

/// What a route's bucket counts per.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum RouteKey {
    /// The client key, as the global bucket.
    #[default]
    Client,
    /// The first value of this header (an API key, a tenant id); the
    /// client without it.
    Header(HeaderName),
    /// The JA4 fingerprint (RFC 0012); the client without one.
    Ja4,
}

impl RouteKey {
    /// `"client"`, `"header:<name>"` or `"ja4"`.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "client" => Ok(Self::Client),
            "ja4" => Ok(Self::Ja4),
            _ => {
                let name = s.strip_prefix("header:").filter(|n| !n.is_empty());
                let name = name.and_then(|n| HeaderName::from_bytes(n.as_bytes()).ok());
                name.map(Self::Header)
                    .ok_or_else(|| format!("key {s:?}: \"client\", \"header:<name>\" or \"ja4\""))
            }
        }
    }
}

/// A key in a route's table. Header values and fingerprints are hashed
/// with a per-process seed, so an attacker cannot pick colliding values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Key {
    Client(ClientKey),
    Value(u64),
}

/// A route's buckets, bounded by `max_keys`, least recently seen evicted.
pub(crate) struct Limits {
    limit: Limit,
    key: RouteKey,
    seed: RandomState,
    table: Mutex<Table<Key>>,
}

impl Limits {
    pub(crate) fn new(limit: Limit, key: RouteKey, max_keys: NonZeroUsize) -> Self {
        Self {
            limit,
            key,
            seed: RandomState::new(),
            table: Mutex::new(Table::new(max_keys)),
        }
    }

    /// Takes a token for this request; returns the verdict and the keys
    /// now in the table.
    pub(crate) fn take(
        &self,
        headers: &HeaderMap,
        client: ClientKey,
        ja4: Option<Ja4>,
        now: Instant,
    ) -> (Verdict, usize) {
        let value = match &self.key {
            RouteKey::Client => None,
            RouteKey::Header(h) => headers.get(h).map(|v| self.seed.hash_one(v.as_bytes())),
            RouteKey::Ja4 => ja4.map(|j| self.seed.hash_one(j.as_str())),
        };
        let key = value.map_or(Key::Client(client), Key::Value);
        // a panic mid-take leaves a consistent table, as in the global one
        let mut t = self.table.lock().unwrap_or_else(PoisonError::into_inner);
        (t.take(key, &self.limit, now), t.len())
    }
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;

    use super::*;

    fn client(n: u8) -> ClientKey {
        ClientKey::from(std::net::IpAddr::from([192, 0, 2, n]))
    }

    // RFC 0013 case 12
    #[test]
    fn table_stays_at_max_keys() {
        let key = RouteKey::parse("header:x-api-key").unwrap();
        let l = Limits::new(
            Limit::new(1, 1).unwrap(),
            key,
            NonZeroUsize::new(100).unwrap(),
        );
        let now = Instant::now();
        let mut len = 0;
        for i in 0..10_000 {
            let mut h = HeaderMap::new();
            h.insert("x-api-key", HeaderValue::from(i));
            len = l.take(&h, client(1), None, now).1;
        }
        assert_eq!(len, 100);
    }

    #[test]
    fn missing_value_falls_back_to_the_client() {
        let l = Limits::new(
            Limit::new(1, 1).unwrap(),
            RouteKey::Ja4,
            NonZeroUsize::new(10).unwrap(),
        );
        let now = Instant::now();
        let h = HeaderMap::new();
        assert_eq!(l.take(&h, client(1), None, now).0, Verdict::Allow);
        assert!(matches!(
            l.take(&h, client(1), None, now).0,
            Verdict::Throttle { .. }
        ));
        assert_eq!(l.take(&h, client(2), None, now).0, Verdict::Allow);
    }

    #[test]
    fn parse_keys() {
        assert_eq!(RouteKey::parse("client"), Ok(RouteKey::Client));
        assert_eq!(RouteKey::parse("ja4"), Ok(RouteKey::Ja4));
        assert!(matches!(
            RouteKey::parse("header:X-Api-Key"),
            Ok(RouteKey::Header(_))
        ));
        assert!(RouteKey::parse("header:").is_err());
        assert!(RouteKey::parse("header:bad name").is_err());
        assert!(RouteKey::parse("ip").is_err());
    }
}
