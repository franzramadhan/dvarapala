use std::fmt;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::time::Instant;

use crate::{Cidr, Limit};

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
}

impl Conns {
    pub fn new(config: ConnsConfig) -> Result<Self, ConnsError> {
        let _ = config;
        todo!("rfc 0009")
    }

    /// Counts a new connection from `ip` at `now`, or refuses it.
    pub fn open(&mut self, ip: IpAddr, now: Instant) -> Result<ConnKey, Refused> {
        let _ = (ip, now);
        todo!("rfc 0009")
    }

    /// Frees the place `key` took; a client evicted since is a no-op.
    pub fn close(&mut self, key: ConnKey) {
        let _ = key;
        todo!("rfc 0009")
    }

    /// Entries in the table.
    pub fn clients(&self) -> usize {
        todo!("rfc 0009")
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
    #[ignore = "rfc 0009"]
    fn rejects_bad_prefixes() {
        for (v4, v6) in [(33, 64), (32, 129), (0, 64)] {
            let c = ConnsConfig {
                prefix_v4: v4,
                prefix_v6: v6,
                ..ConnsConfig::default()
            };
            assert!(Conns::new(c).is_err(), "{v4} {v6}");
        }
    }

    /// RFC 0009 case 1
    #[test]
    #[ignore = "rfc 0009"]
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
    #[ignore = "rfc 0009"]
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
    #[ignore = "rfc 0009"]
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
    #[ignore = "rfc 0009"]
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
        // the oldest was evicted, its count reset; closing it is a no-op
        assert!(c.open(ip("192.0.2.1"), t).is_ok());
        c.close(first);
        assert_eq!(c.clients(), 2);
    }

    /// RFC 0009 case 5
    #[test]
    #[ignore = "rfc 0009"]
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
