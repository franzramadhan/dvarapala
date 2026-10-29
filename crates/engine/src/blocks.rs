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
        self.expire(now);
        let net = Cidr::of(net.addr(), net.prefix());
        if let Some(u) = self.entries.get_mut(&net) {
            *u = until;
            return Ok(());
        }
        if self.entries.len() >= self.max {
            return Err(BlocksFull(self.max));
        }
        self.entries.insert(net, until);
        self.prefixes[slot(net)] += 1;
        Ok(())
    }

    /// `true` when `net` was listed.
    pub fn remove(&mut self, net: Cidr) -> bool {
        let net = Cidr::of(net.addr(), net.prefix());
        let removed = self.entries.remove(&net).is_some();
        if removed {
            self.prefixes[slot(net)] -= 1;
        }
        removed
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
        self.expire(now);
        self.entries.iter().map(|(n, u)| (*n, *u)).collect()
    }

    fn expire(&mut self, now: Instant) {
        let prefixes = &mut self.prefixes;
        self.entries.retain(|n, u| {
            let keep = *u > now;
            if !keep {
                prefixes[slot(*n)] -= 1;
            }
            keep
        });
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
    fn bounded_and_expiring() {
        let mut b = Blocks::new(2);
        let t = Instant::now();
        let later = t + Duration::from_secs(60);
        b.add(net("192.0.2.0/24"), later, t).unwrap();
        b.add(net("198.51.100.0/24"), t + Duration::from_secs(1), t)
            .unwrap();
        assert_eq!(b.add(net("203.0.113.0/24"), later, t), Err(BlocksFull(2)));
        assert_eq!(
            BlocksFull(2).to_string(),
            "the block list is full (2 networks)"
        );
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
