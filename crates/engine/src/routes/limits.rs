use std::hash::{BuildHasher, RandomState};
use std::num::NonZeroUsize;
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use super::matcher::is_token;
use crate::{ClientKey, Limit, Table, Verdict};

/// What a route's bucket counts per.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum RouteKey {
    /// The client key, as the global bucket.
    #[default]
    Client,
    /// The first value of this header, lower case (an API key, a tenant
    /// id); the client without it.
    Header(String),
    /// The JA4 fingerprint (RFC 0012); the client without one.
    Ja4,
}

impl RouteKey {
    /// `"client"`, `"header:<name>"` or `"ja4"`.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "client" => Ok(Self::Client),
            "ja4" => Ok(Self::Ja4),
            _ => s
                .strip_prefix("header:")
                .filter(|n| is_token(n))
                .map(|n| Self::Header(n.to_ascii_lowercase()))
                .ok_or_else(|| format!("key {s:?}: \"client\", \"header:<name>\" or \"ja4\"")),
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
pub struct RouteLimits {
    limit: Limit,
    seed: RandomState,
    table: Mutex<Table<Key>>,
}

impl RouteLimits {
    pub fn new(limit: Limit, max_keys: NonZeroUsize) -> Self {
        Self {
            limit,
            seed: RandomState::new(),
            table: Mutex::new(Table::new(max_keys)),
        }
    }

    /// Takes a token for this request: from `value`'s bucket (the header
    /// or fingerprint the route's [`RouteKey`] names), else `client`'s.
    /// Returns the verdict and the keys now in the table.
    pub fn take(&self, value: Option<&[u8]>, client: ClientKey, now: Instant) -> (Verdict, usize) {
        let key = value.map_or(Key::Client(client), |v| Key::Value(self.seed.hash_one(v)));
        // a panic mid-take leaves a consistent table, as in the global one
        let mut t = self.table.lock().unwrap_or_else(PoisonError::into_inner);
        (t.take(key, &self.limit, now), t.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(n: u8) -> ClientKey {
        ClientKey::from(std::net::IpAddr::from([192, 0, 2, n]))
    }

    // RFC 0013 case 12
    #[test]
    fn table_stays_at_max_keys() {
        let l = RouteLimits::new(Limit::new(1, 1).unwrap(), NonZeroUsize::new(100).unwrap());
        let now = Instant::now();
        let mut len = 0;
        for i in 0..10_000 {
            len = l.take(Some(i.to_string().as_bytes()), client(1), now).1;
        }
        assert_eq!(len, 100);
    }

    #[test]
    fn missing_value_falls_back_to_the_client() {
        let l = RouteLimits::new(Limit::new(1, 1).unwrap(), NonZeroUsize::new(10).unwrap());
        let now = Instant::now();
        assert_eq!(l.take(None, client(1), now).0, Verdict::Allow);
        assert!(matches!(
            l.take(None, client(1), now).0,
            Verdict::Throttle { .. }
        ));
        assert_eq!(l.take(None, client(2), now).0, Verdict::Allow);
    }

    #[test]
    fn parse_keys() {
        assert_eq!(RouteKey::parse("client"), Ok(RouteKey::Client));
        assert_eq!(RouteKey::parse("ja4"), Ok(RouteKey::Ja4));
        assert_eq!(
            RouteKey::parse("header:X-Api-Key"),
            Ok(RouteKey::Header("x-api-key".into()))
        );
        assert!(RouteKey::parse("header:").is_err());
        assert!(RouteKey::parse("header:bad name").is_err());
        assert!(RouteKey::parse("ip").is_err());
    }
}
