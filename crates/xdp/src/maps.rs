#![allow(unused_variables, unused_imports, dead_code)]
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use dvarapala_engine::Cidr;

/// The LPM trie key of `net`: IPv4 mapped into IPv6, as the program
/// parses it.
pub fn key(net: Cidr) -> (u32, [u8; 16]) {
    todo!("rfc 0011")
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
        todo!("rfc 0011")
    }

    /// Lists `net` until `now + ttl`; a full trie gives up the entry that
    /// expires first, never a static one.
    pub fn add(&mut self, net: Cidr, now: u64, ttl: u64) -> Add {
        todo!("rfc 0011")
    }

    /// Drops and returns the entries expired at `now`.
    pub fn expire(&mut self, now: u64) -> Vec<Cidr> {
        todo!("rfc 0011")
    }

    /// Entries in the trie, static and dynamic.
    pub fn len(&self) -> usize {
        todo!("rfc 0011")
    }

    pub fn is_empty(&self) -> bool {
        todo!("rfc 0011")
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
    #[ignore = "rfc 0011"]
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
    #[ignore = "rfc 0011"]
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
    #[ignore = "rfc 0011"]
    fn no_room_means_no_dynamic_blocks() {
        let mut b = Blocks::new(1, [net("192.0.2.0/24")]);
        assert_eq!(b.add(net("198.51.100.1"), 0, 100), Add::Skip);
    }

    #[test]
    #[ignore = "rfc 0011"]
    fn keys_map_ipv4_into_ipv6() {
        let (len, k) = key(net("192.0.2.7/24"));
        assert_eq!(len, 120);
        assert_eq!(k[10..], [0xff, 0xff, 192, 0, 2, 0]);
        assert_eq!(key(net("2001:db8::/32")).0, 32);
    }
}
