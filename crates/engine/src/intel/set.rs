use std::net::IpAddr;

use crate::Cidr;

/// An immutable set of networks: merged ranges per family, found by
/// binary search. About 8 bytes per IPv4 range and 32 per IPv6 range.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrefixSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl PrefixSet {
    /// Overlapping and adjacent networks merge into one range.
    pub fn new(nets: impl IntoIterator<Item = Cidr>) -> Self {
        let (mut v4, mut v6) = (Vec::new(), Vec::new());
        for net in nets {
            match net.addr().to_canonical() {
                IpAddr::V4(a) => {
                    // a mapped IPv6 network counts in IPv4 bits
                    let prefix = if net.addr().is_ipv6() {
                        net.prefix().saturating_sub(96)
                    } else {
                        net.prefix()
                    };
                    let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
                    let start = u32::from(a) & mask;
                    v4.push((start, start | !mask));
                }
                IpAddr::V6(a) => {
                    let mask = u128::MAX
                        .checked_shl(128 - u32::from(net.prefix()))
                        .unwrap_or(0);
                    let start = u128::from(a) & mask;
                    v6.push((start, start | !mask));
                }
            }
        }
        Self {
            v4: merge(v4),
            v6: merge(v6),
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip.to_canonical() {
            IpAddr::V4(a) => find(&self.v4, u32::from(a)),
            IpAddr::V6(a) => find(&self.v6, u128::from(a)),
        }
    }

    /// Ranges after merging.
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Heap bytes held, for the footprint budget.
    pub fn bytes(&self) -> usize {
        self.v4.capacity() * size_of::<(u32, u32)>()
            + self.v6.capacity() * size_of::<(u128, u128)>()
    }
}

fn merge<T: Copy + Ord + One>(mut v: Vec<(T, T)>) -> Vec<(T, T)> {
    v.sort_unstable();
    let mut out: Vec<(T, T)> = Vec::with_capacity(v.len());
    for (s, e) in v {
        match out.last_mut() {
            // overlapping, or adjacent: the next start right after the end
            Some(last) if s <= last.1 || last.1.succ() == Some(s) => {
                last.1 = last.1.max(e);
            }
            _ => out.push((s, e)),
        }
    }
    out.shrink_to_fit();
    out
}

fn find<T: Copy + Ord>(v: &[(T, T)], x: T) -> bool {
    let i = v.partition_point(|&(s, _)| s <= x);
    i > 0 && v[i - 1].1 >= x
}

trait One: Sized {
    fn succ(self) -> Option<Self>;
}

impl One for u32 {
    fn succ(self) -> Option<Self> {
        self.checked_add(1)
    }
}

impl One for u128 {
    fn succ(self) -> Option<Self> {
        self.checked_add(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(nets: &[&str]) -> PrefixSet {
        PrefixSet::new(nets.iter().map(|n| n.parse().unwrap()))
    }

    fn has(s: &PrefixSet, ip: &str) -> bool {
        s.contains(ip.parse().unwrap())
    }

    #[test]
    fn members_and_non_members() {
        let s = set(&["192.0.2.0/24", "198.51.100.7", "2001:db8::/32"]);
        assert!(has(&s, "192.0.2.0"));
        assert!(has(&s, "192.0.2.255"));
        assert!(!has(&s, "192.0.3.0"));
        assert!(has(&s, "198.51.100.7"));
        assert!(!has(&s, "198.51.100.8"));
        assert!(has(&s, "2001:db8:1::1"));
        assert!(!has(&s, "2001:db9::1"));
        // a mapped client is looked up as IPv4
        assert!(has(&s, "::ffff:192.0.2.9"));
        assert!(!set(&[]).contains("192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn overlapping_and_adjacent_networks_merge() {
        let s = set(&[
            "192.0.2.0/25",
            "192.0.2.128/25",
            "192.0.2.7",
            "198.51.100.0/24",
            "198.51.100.0/25",
        ]);
        assert_eq!(s.len(), 2);
        assert!(has(&s, "192.0.2.200"));
        // host bits in the input are cleared
        let h = set(&["203.0.113.77/24"]);
        assert!(has(&h, "203.0.113.1"));
        assert_eq!(set(&["0.0.0.0/1", "128.0.0.0/1"]).len(), 1);
    }

    // RFC 0031 case 2 (the bench measures the time)
    #[test]
    fn a_hundred_thousand_prefixes() {
        // every other /24, so none merge
        let nets = (0..100_000u32).map(|i| {
            let a = std::net::Ipv4Addr::from(0x0a00_0000 + (i << 9));
            Cidr::of(a.into(), 24)
        });
        let v6 = (0..1_000u128).map(|i| {
            let a = std::net::Ipv6Addr::from((0x2001_0db8u128 << 96) | (i << 80));
            Cidr::of(a.into(), 48)
        });
        let s = PrefixSet::new(nets.chain(v6));
        // the /48s are adjacent: one range
        assert_eq!(s.len(), 100_001);
        assert!(has(&s, "10.0.0.1"));
        assert!(!has(&s, "10.0.1.1"));
        assert!(has(&s, "13.13.62.9"));
        assert!(!has(&s, "14.0.0.1"));
        assert!(has(&s, "2001:db8:3e7::1"));
        assert!(!has(&s, "2001:db8:3e8::1"));
        // RFC 0031 case 13: the memory a 100 000 prefix feed costs
        assert!(s.bytes() <= 100_000 * 40, "{}", s.bytes());
    }
}
