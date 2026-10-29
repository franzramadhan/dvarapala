#![allow(unused_variables, unused_imports, dead_code, unreachable_code)]
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::time::Instant;

use crate::Cidr;

/// Networks blocked by hand (RFC 0014), each until its expiry, at most
/// `max` at once. Not thread-safe; callers wrap it in a lock.
pub struct Blocks {
    max: usize,
    entries: HashMap<Cidr, Instant>,
    /// networks per prefix length, IPv4 then IPv6, so a lookup only tries
    /// the lengths in use
    prefixes: [u32; 33 + 129],
}

/// The block list holds `max` networks already.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlocksFull(pub usize);

impl fmt::Display for BlocksFull {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the block list is full ({} networks)", self.0)
    }
}

impl std::error::Error for BlocksFull {}

impl Blocks {
    pub fn new(max: usize) -> Self {
        Self {
            max,
            entries: HashMap::new(),
            prefixes: [0; 33 + 129],
        }
    }

    /// Blocks `net` until `until`; blocking a listed network again moves
    /// its expiry. Expired entries are dropped first.
    pub fn add(&mut self, net: Cidr, until: Instant, now: Instant) -> Result<(), BlocksFull> {
        todo!("rfc 0014")
    }

    /// `true` when `net` was listed.
    pub fn remove(&mut self, net: Cidr) -> bool {
        todo!("rfc 0014")
    }

    /// Whether a block in force at `now` holds `ip`.
    pub fn contains(&self, ip: IpAddr, now: Instant) -> bool {
        if self.entries.is_empty() {
            return false;
        }
        let ip = ip.to_canonical();
        let (base, max) = if ip.is_ipv4() { (0, 32) } else { (33, 128) };
        (0..=max).any(|p| {
            self.prefixes[base + usize::from(p)] > 0
                && self.entries.get(&Cidr::of(ip, p)).is_some_and(|u| *u > now)
        })
    }

    /// The blocks in force at `now`, with their expiry.
    pub fn list(&mut self, now: Instant) -> Vec<(Cidr, Instant)> {
        todo!("rfc 0014")
    }

    fn expire(&mut self, now: Instant) {
        todo!("rfc 0014")
    }
}

fn slot(net: Cidr) -> usize {
    let base = if net.addr().is_ipv4() { 0 } else { 33 };
    base + usize::from(net.prefix())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn net(s: &str) -> Cidr {
        s.parse().unwrap()
    }

    // RFC 0014 case 3
    #[test]
    #[ignore = "rfc 0014"]
    fn bounded_and_expiring() {
        let mut b = Blocks::new(2);
        let t = Instant::now();
        let later = t + Duration::from_secs(60);
        b.add(net("192.0.2.0/24"), later, t).unwrap();
        b.add(net("198.51.100.0/24"), t + Duration::from_secs(1), t)
            .unwrap();
        assert_eq!(b.add(net("203.0.113.0/24"), later, t), Err(BlocksFull(2)));
        // re-blocking a listed network fits
        b.add(net("192.0.2.0/24"), later, t).unwrap();
        assert!(b.contains("192.0.2.7".parse().unwrap(), t));
        assert!(!b.contains("203.0.113.7".parse().unwrap(), t));
        // the short block expires and frees its slot
        let t2 = t + Duration::from_secs(2);
        assert!(!b.contains("198.51.100.7".parse().unwrap(), t2));
        b.add(net("203.0.113.0/24"), later, t2).unwrap();
        assert_eq!(b.list(t2).len(), 2);
        assert!(b.remove(net("203.0.113.0/24")));
        assert!(!b.remove(net("203.0.113.0/24")));
        assert_eq!(b.list(t2).len(), 1);
    }
}
