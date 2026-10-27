use std::collections::HashMap;
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::time::Instant;

use crate::{Bucket, Limit, Verdict};

/// Per-client buckets with a fixed capacity. When full, the least recently
/// seen client is evicted, so a flood of spoofed sources cannot grow memory.
///
/// Not thread-safe; callers wrap it in a lock.
pub struct Table<K> {
    capacity: usize,
    index: HashMap<K, usize>,
    slots: Vec<Slot<K>>,
    /// most recently seen slot
    head: Option<usize>,
    /// least recently seen slot, evicted first
    tail: Option<usize>,
    evictions: u64,
}

struct Slot<K> {
    key: K,
    bucket: Bucket,
    prev: Option<usize>,
    next: Option<usize>,
}

impl<K: Hash + Eq + Clone> Table<K> {
    pub fn new(_capacity: NonZeroUsize) -> Self {
        todo!("rfc 0001")
    }

    /// Takes one token from `key`'s bucket, creating a full one if unseen.
    pub fn take(&mut self, _key: K, _limit: &Limit, _now: Instant) -> Verdict {
        let _ = (
            &self.index,
            &self.slots,
            self.head,
            self.tail,
            self.capacity,
        );
        todo!("rfc 0001")
    }

    pub fn len(&self) -> usize {
        todo!("rfc 0001")
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn evictions(&self) -> u64 {
        self.evictions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(cap: usize) -> Table<u32> {
        Table::new(NonZeroUsize::new(cap).unwrap())
    }

    #[test]
    #[ignore = "rfc 0001 case 5"]
    fn evicts_least_recently_seen() {
        let l = Limit::new(1, 1).unwrap();
        let t = Instant::now();
        let mut tb = table(2);
        tb.take(1, &l, t);
        tb.take(2, &l, t);
        // 1 is now the most recent, so 2 goes when 3 arrives
        assert!(matches!(tb.take(1, &l, t), Verdict::Throttle { .. }));
        tb.take(3, &l, t);
        assert_eq!(tb.len(), 2);
        assert_eq!(tb.evictions(), 1);
        // 1 kept its empty bucket, 2 was evicted and starts full again
        assert!(matches!(tb.take(1, &l, t), Verdict::Throttle { .. }));
        assert_eq!(tb.take(2, &l, t), Verdict::Allow);
    }

    #[test]
    #[ignore = "rfc 0001 case 6"]
    fn million_keys_stay_bounded() {
        let l = Limit::new(1, 1).unwrap();
        let t = Instant::now();
        let mut tb = table(1000);
        for k in 0..1_000_000 {
            tb.take(k, &l, t);
        }
        assert_eq!(tb.len(), 1000);
        assert_eq!(tb.evictions(), 999_000);
        assert!(tb.slots.capacity() <= 2048);
        assert!(tb.index.capacity() <= 4096);
    }

    #[test]
    #[ignore = "rfc 0001"]
    fn capacity_one() {
        let l = Limit::new(1, 1).unwrap();
        let t = Instant::now();
        let mut tb = table(1);
        assert_eq!(tb.take(1, &l, t), Verdict::Allow);
        assert_eq!(tb.take(2, &l, t), Verdict::Allow);
        assert_eq!(tb.len(), 1);
        assert_eq!(tb.take(1, &l, t), Verdict::Allow);
    }
}
