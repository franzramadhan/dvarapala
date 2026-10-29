use std::fmt;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::time::Instant;

use crate::{Cidr, Limit, Table, Verdict};

/// Per-client connection limits (RFC 0009).
#[derive(Debug, Clone, PartialEq)]
pub struct ConnsConfig {
    /// Open connections per client; 0 off.
    pub max_per_client: u32,
    /// New connections per client; `None` off.
    pub accept: Option<Limit>,
    pub prefix_v4: u8,
    pub prefix_v6: u8,
    pub max_clients: NonZeroUsize,
    /// Never limited.
    pub exempt: Vec<Cidr>,
}

impl Default for ConnsConfig {
    fn default() -> Self {
        Self {
            max_per_client: 256,
            accept: None,
            prefix_v4: 32,
            prefix_v6: 64,
            max_clients: NonZeroUsize::new(100_000).expect("non-zero"),
            exempt: Vec::new(),
        }
    }
}

/// Why a connection was refused; the `reason` metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    PerClient,
    Rate,
}

impl Refused {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PerClient => "per_client",
            Self::Rate => "rate",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnsError(pub String);

impl fmt::Display for ConnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConnsError {}

/// The client an open connection counts against; `None` when exempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnKey(pub Option<Cidr>);

/// Open connections and new-connection buckets per client prefix, in a
/// bounded table. Time is an input; not thread-safe, callers lock.
pub struct Conns {
    config: ConnsConfig,
    /// open connections per client prefix
    table: Table<Cidr, u32>,
    /// `accept`, or a placeholder that only fills new buckets when it is off
    limit: Limit,
}

impl Conns {
    pub fn new(config: ConnsConfig) -> Result<Self, ConnsError> {
        if !(1..=32).contains(&config.prefix_v4) || !(1..=128).contains(&config.prefix_v6) {
            return Err(ConnsError(format!(
                "prefix_v4 must be 1 to 32 and prefix_v6 1 to 128, got {} and {}",
                config.prefix_v4, config.prefix_v6
            )));
        }
        let limit = match config.accept {
            Some(l) => l,
            None => Limit::new(1, 1).map_err(|e| ConnsError(e.to_string()))?,
        };
        Ok(Self {
            table: Table::new(config.max_clients),
            limit,
            config,
        })
    }

    /// Counts a new connection from `ip` at `now`, or refuses it. The open
    /// cap is checked first, so a refused connection takes no token.
    pub fn open(&mut self, ip: IpAddr, now: Instant) -> Result<ConnKey, Refused> {
        if self.config.exempt.iter().any(|c| c.contains(ip)) {
            return Ok(ConnKey(None));
        }
        let prefix = match ip.to_canonical() {
            IpAddr::V4(_) => self.config.prefix_v4,
            IpAddr::V6(_) => self.config.prefix_v6,
        };
        let key = Cidr::of(ip, prefix);
        let limit = self.limit;
        let (bucket, open) = self.table.entry(key, &limit, now);
        let max = self.config.max_per_client;
        if max > 0 && *open >= max {
            return Err(Refused::PerClient);
        }
        if self.config.accept.is_some() && bucket.take(&limit, now) != Verdict::Allow {
            return Err(Refused::Rate);
        }
        *open += 1;
        Ok(ConnKey(Some(key)))
    }

    /// Frees the place `key` took; a client evicted since is a no-op.
    pub fn close(&mut self, key: ConnKey) {
        if let Some(open) = key.0.and_then(|k| self.table.get_mut(&k)) {
            *open = open.saturating_sub(1);
        }
    }

    /// Entries in the table.
    pub fn clients(&self) -> usize {
        self.table.len()
    }

    pub fn evictions(&self) -> u64 {
        self.table.evictions()
    }

    pub fn config(&self) -> &ConnsConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn conns(config: ConnsConfig) -> Conns {
        Conns::new(config).unwrap()
    }

    #[test]
    fn rejects_bad_prefixes() {
        for (v4, v6) in [(33, 64), (32, 129), (0, 64)] {
            let c = ConnsConfig {
                prefix_v4: v4,
                prefix_v6: v6,
                ..ConnsConfig::default()
            };
            let e = Conns::new(c).err().expect("refused").to_string();
            assert!(e.contains("prefix_v4"), "{v4} {v6}: {e}");
        }
    }

    #[test]
    fn reasons_label_metrics() {
        assert_eq!(Refused::PerClient.as_str(), "per_client");
        assert_eq!(Refused::Rate.as_str(), "rate");
    }

    #[test]
    fn v6_clients_group_by_prefix_v6() {
        let mut c = conns(ConnsConfig {
            max_per_client: 1,
            ..ConnsConfig::default()
        });
        let t = Instant::now();
        assert!(c.open(ip("2001:db8::1"), t).is_ok());
        // same /64
        assert_eq!(c.open(ip("2001:db8::2"), t), Err(Refused::PerClient));
        assert!(c.open(ip("2001:db8:0:1::1"), t).is_ok());
        assert_eq!(c.config().prefix_v6, 64);
    }

    /// RFC 0009 case 1
    #[test]
    fn per_client_cap_frees_on_close() {
        let mut c = conns(ConnsConfig {
            max_per_client: 2,
            ..ConnsConfig::default()
        });
        let t = Instant::now();
        let a = c.open(ip("192.0.2.1"), t).unwrap();
        c.open(ip("192.0.2.1"), t).unwrap();
        assert_eq!(c.open(ip("192.0.2.1"), t), Err(Refused::PerClient));
        c.close(a);
        assert!(c.open(ip("192.0.2.1"), t).is_ok());
    }

    /// RFC 0009 case 2
    #[test]
    fn accept_bucket_refills() {
        let mut c = conns(ConnsConfig {
            max_per_client: 0,
            accept: Some(Limit::new(10, 2).unwrap()),
            ..ConnsConfig::default()
        });
        let t = Instant::now();
        let got: Vec<_> = (0..5).map(|_| c.open(ip("192.0.2.1"), t).is_ok()).collect();
        assert_eq!(got, [true, true, false, false, false]);
        assert_eq!(c.open(ip("192.0.2.1"), t), Err(Refused::Rate));
        assert!(
            c.open(ip("192.0.2.1"), t + Duration::from_millis(100))
                .is_ok()
        );
    }

    /// RFC 0009 case 3
    #[test]
    fn clients_group_by_prefix() {
        let mut c = conns(ConnsConfig {
            max_per_client: 1,
            prefix_v4: 24,
            ..ConnsConfig::default()
        });
        let t = Instant::now();
        assert!(c.open(ip("192.0.2.1"), t).is_ok());
        assert_eq!(c.open(ip("192.0.2.2"), t), Err(Refused::PerClient));
        assert!(c.open(ip("198.51.100.1"), t).is_ok());
    }

    /// RFC 0009 case 4
    #[test]
    fn table_is_bounded() {
        let mut c = conns(ConnsConfig {
            max_per_client: 1,
            max_clients: NonZeroUsize::new(2).unwrap(),
            ..ConnsConfig::default()
        });
        let t = Instant::now();
        let first = c.open(ip("192.0.2.1"), t).unwrap();
        c.open(ip("192.0.2.2"), t).unwrap();
        c.open(ip("192.0.2.3"), t).unwrap();
        assert_eq!(c.clients(), 2);
        assert_eq!(c.evictions(), 1);
        // the oldest was evicted, its count reset; closing it is a no-op
        assert!(c.open(ip("192.0.2.1"), t).is_ok());
        c.close(first);
        assert_eq!(c.clients(), 2);
    }

    /// RFC 0009 case 5
    #[test]
    fn exempt_is_never_limited() {
        let mut c = conns(ConnsConfig {
            max_per_client: 1,
            accept: Some(Limit::new(1, 1).unwrap()),
            exempt: vec!["192.0.2.0/24".parse().unwrap()],
            ..ConnsConfig::default()
        });
        let t = Instant::now();
        for _ in 0..10 {
            assert_eq!(c.open(ip("192.0.2.1"), t), Ok(ConnKey(None)));
        }
        assert_eq!(c.clients(), 0);
    }
}
