use crate::Cidr;

/// The `k` keys with the highest sketch estimates in the current window.
/// Fixed capacity; a key enters only by beating the current minimum.
pub(crate) struct TopK {
    k: usize,
    items: Vec<(Cidr, u32)>,
}

impl TopK {
    pub(crate) fn new(k: usize) -> Self {
        Self {
            k,
            items: Vec::with_capacity(k),
        }
    }

    /// Offers `key` with its current estimate.
    // ponytail: linear scan, fine for k in the tens; a min-heap plus index
    // if top_k grows into the thousands
    pub(crate) fn offer(&mut self, key: Cidr, estimate: u32) {
        if let Some(e) = self.items.iter_mut().find(|(k, _)| *k == key) {
            e.1 = estimate;
        } else if self.items.len() < self.k {
            self.items.push((key, estimate));
        } else if let Some(min) = self.items.iter_mut().min_by_key(|(_, c)| *c)
            && min.1 < estimate
        {
            *min = (key, estimate);
        }
    }

    /// Entries above `min`, highest first, written into `out` (cleared first).
    pub(crate) fn ranked_into(&self, min: u32, out: &mut Vec<(Cidr, u32)>) {
        out.clear();
        out.extend(self.items.iter().filter(|(_, c)| *c > min));
        out.sort_unstable_by_key(|e| std::cmp::Reverse(e.1));
    }

    pub(crate) fn clear(&mut self) {
        self.items.clear();
    }

    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize {
        self.items.capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::sketch::Sketch;
    use std::hash::{BuildHasher, RandomState};
    use std::net::{IpAddr, Ipv4Addr};

    fn key(i: u32) -> Cidr {
        Cidr::of(IpAddr::V4(Ipv4Addr::from(0x0a00_0000 | i)), 32)
    }

    fn feed(s: &mut Sketch, t: &mut TopK, hs: &RandomState, k: Cidr) {
        let e = s.add(hs.hash_one(k));
        t.offer(k, e);
    }

    #[test]
    fn dominant_key_ranks_first() {
        let hs = RandomState::new();
        let (mut s, mut t) = (Sketch::new(2048, 4), TopK::new(8));
        let hot = key(0);
        for i in 1..=10_000 {
            feed(&mut s, &mut t, &hs, key(i));
            feed(&mut s, &mut t, &hs, hot);
        }
        let mut out = Vec::new();
        t.ranked_into(0, &mut out);
        assert_eq!(out[0].0, hot);
        assert!(out.len() <= 8);
    }

    #[test]
    fn million_keys_keep_memory_fixed() {
        let hs = RandomState::new();
        let (mut s, mut t) = (Sketch::new(2048, 4), TopK::new(64));
        let (counters, cap) = (s.counters(), t.capacity());
        for i in 0..1_000_000 {
            feed(&mut s, &mut t, &hs, key(i));
        }
        assert_eq!(s.counters(), counters);
        assert_eq!(t.capacity(), cap);
    }

    #[test]
    fn ranked_skips_entries_at_or_below_min() {
        let mut t = TopK::new(4);
        t.offer(key(1), 5);
        t.offer(key(2), 50);
        let mut out = Vec::new();
        t.ranked_into(5, &mut out);
        assert_eq!(out, vec![(key(2), 50)]);
    }
}
