use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use dvarapala_engine::Cidr;

/// The LPM trie key of `net`: IPv4 mapped into IPv6, as the program
/// parses it.
pub fn key(net: Cidr) -> (u32, [u8; 16]) {
    let net = Cidr::of(net.addr(), net.prefix());
    match net.addr() {
        IpAddr::V4(a) => (96 + u32::from(net.prefix()), a.to_ipv6_mapped().octets()),
        IpAddr::V6(a) => (u32::from(net.prefix()), a.octets()),
    }
}

/// What a dynamic block needs in the trie.
#[derive(Debug, PartialEq, Eq)]
pub enum Add {
    /// Already listed for more than half the TTL, or static, or no room
    /// for dynamic entries at all: no write.
    Skip,
    /// Write `net`, after removing `evicted` when the trie is full.
    Write { evicted: Option<Cidr> },
}

/// The block trie's dynamic entries, kept beside the static ones within
/// `xdp.max_blocks`. Times are `bpf_ktime_get_ns` nanoseconds.
#[derive(Debug)]
pub struct Blocks {
    statics: HashSet<Cidr>,
    room: usize,
    dynamic: HashMap<Cidr, u64>,
}

impl Blocks {
    pub fn new(max_blocks: usize, statics: impl IntoIterator<Item = Cidr>) -> Self {
        let statics: HashSet<Cidr> = statics.into_iter().collect();
        Self {
            room: max_blocks.saturating_sub(statics.len()),
            statics,
            dynamic: HashMap::new(),
        }
    }

    /// Lists `net` until `now + ttl`; a full trie gives up the entry that
    /// expires first, never a static one.
    pub fn add(&mut self, net: Cidr, now: u64, ttl: u64) -> Add {
        if self.room == 0 || self.statics.contains(&net) {
            return Add::Skip;
        }
        let until = now + ttl;
        if let Some(t) = self.dynamic.get_mut(&net) {
            if *t > now + ttl / 2 {
                return Add::Skip;
            }
            *t = until;
            return Add::Write { evicted: None };
        }
        let mut evicted = None;
        if self.dynamic.len() >= self.room {
            // ponytail: O(n) scan, only when full and a new source comes in
            let (&oldest, _) = self.dynamic.iter().min_by_key(|(_, t)| **t).unwrap();
            self.dynamic.remove(&oldest);
            evicted = Some(oldest);
        }
        self.dynamic.insert(net, until);
        Add::Write { evicted }
    }

    /// Drops and returns the entries expired at `now`.
    pub fn expire(&mut self, now: u64) -> Vec<Cidr> {
        let gone: Vec<Cidr> = self
            .dynamic
            .iter()
            .filter(|(_, t)| **t <= now)
            .map(|(c, _)| *c)
            .collect();
        for c in &gone {
            self.dynamic.remove(c);
        }
        gone
    }

    /// Entries in the trie, static and dynamic.
    pub fn len(&self) -> usize {
        self.statics.len() + self.dynamic.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> Cidr {
        s.parse().unwrap()
    }

    // RFC 0011 case 9
    #[test]
    fn full_trie_replaces_the_oldest_dynamic_entry() {
        let mut b = Blocks::new(3, [net("192.0.2.0/24")]);
        let a = net("198.51.100.1");
        let c = net("198.51.100.2");
        assert_eq!(b.add(a, 0, 100), Add::Write { evicted: None });
        assert_eq!(b.add(c, 10, 100), Add::Write { evicted: None });
        assert_eq!(b.len(), 3);
        let d = net("198.51.100.3");
        assert_eq!(b.add(d, 20, 100), Add::Write { evicted: Some(a) });
        assert_eq!(b.len(), 3, "static entry kept");
        assert_eq!(b.add(net("192.0.2.0/24"), 30, 100), Add::Skip);
    }

    #[test]
    fn refresh_and_expiry() {
        let mut b = Blocks::new(10, []);
        let a = net("2001:db8::/64");
        assert_eq!(b.add(a, 0, 100), Add::Write { evicted: None });
        assert_eq!(b.add(a, 10, 100), Add::Skip, "fresh");
        assert_eq!(b.add(a, 60, 100), Add::Write { evicted: None });
        assert!(b.expire(159).is_empty());
        assert_eq!(b.expire(160), vec![a]);
        assert!(b.is_empty());
    }

    #[test]
    fn no_room_means_no_dynamic_blocks() {
        let mut b = Blocks::new(1, [net("192.0.2.0/24")]);
        assert_eq!(b.add(net("198.51.100.1"), 0, 100), Add::Skip);
    }

    #[test]
    fn keys_map_ipv4_into_ipv6() {
        let (len, k) = key(net("192.0.2.7/24"));
        assert_eq!(len, 120);
        assert_eq!(k[10..], [0xff, 0xff, 192, 0, 2, 0]);
        assert_eq!(key(net("2001:db8::/32")).0, 32);
    }
}
