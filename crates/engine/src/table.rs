use std::collections::HashMap;
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::time::Instant;

use crate::{Bucket, Limit, Verdict};

/// No slot. Links are `u32` to keep a slot small; capacity is capped below it.
const NIL: u32 = u32::MAX;

/// Per-client buckets with a fixed capacity. When full, the least recently
/// seen client is evicted, so a flood of spoofed sources cannot grow memory.
/// Slots are allocated as clients arrive, not up front.
///
/// Not thread-safe; callers wrap it in a lock.
pub struct Table<K> {
    capacity: usize,
    index: HashMap<K, u32>,
    slots: Vec<Slot<K>>,
    /// most recently seen slot
    head: u32,
    /// least recently seen slot, evicted first
    tail: u32,
    evictions: u64,
}

struct Slot<K> {
    key: K,
    bucket: Bucket,
    prev: u32,
    next: u32,
}

impl<K: Hash + Eq + Clone> Table<K> {
    /// `capacity` is capped at `u32::MAX - 1` clients.
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            capacity: capacity.get().min(NIL as usize),
            index: HashMap::new(),
            slots: Vec::new(),
            head: NIL,
            tail: NIL,
            evictions: 0,
        }
    }

    /// Takes one token from `key`'s bucket, creating a full one if unseen.
    pub fn take(&mut self, key: K, limit: &Limit, now: Instant) -> Verdict {
        if let Some(&i) = self.index.get(&key) {
            self.unlink(i);
            self.push_front(i);
            return self.slots[i as usize].bucket.take(limit, now);
        }
        let bucket = Bucket::full(limit, now);
        let i = if self.slots.len() < self.capacity {
            self.slots.push(Slot {
                key: key.clone(),
                bucket,
                prev: NIL,
                next: NIL,
            });
            (self.slots.len() - 1) as u32
        } else {
            let t = self.tail;
            self.unlink(t);
            let slot = &mut self.slots[t as usize];
            self.index.remove(&slot.key);
            slot.key = key.clone();
            slot.bucket = bucket;
            self.evictions += 1;
            t
        };
        self.index.insert(key, i);
        self.push_front(i);
        self.slots[i as usize].bucket.take(limit, now)
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn evictions(&self) -> u64 {
        self.evictions
    }

    fn unlink(&mut self, i: u32) {
        let Slot { prev, next, .. } = self.slots[i as usize];
        match prev {
            NIL => self.head = next,
            p => self.slots[p as usize].next = next,
        }
        match next {
            NIL => self.tail = prev,
            n => self.slots[n as usize].prev = prev,
        }
    }

    fn push_front(&mut self, i: u32) {
        let old = self.head;
        let s = &mut self.slots[i as usize];
        s.prev = NIL;
        s.next = old;
        match old {
            NIL => self.tail = i,
            h => self.slots[h as usize].prev = i,
        }
        self.head = i;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(cap: usize) -> Table<u32> {
        Table::new(NonZeroUsize::new(cap).unwrap())
    }

    #[test]
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
    fn capacity_one() {
        let l = Limit::new(1, 1).unwrap();
        let t = Instant::now();
        let mut tb = table(1);
        assert_eq!(tb.take(1, &l, t), Verdict::Allow);
        assert_eq!(tb.take(2, &l, t), Verdict::Allow);
        assert_eq!(tb.len(), 1);
        assert_eq!(tb.take(1, &l, t), Verdict::Allow);
    }

    #[test]
    fn matches_naive_lru_model() {
        // a Vec ordered most recent first is the model; xorshift picks keys
        let l = Limit::new(1, 1).unwrap();
        let t = Instant::now();
        let mut tb = table(8);
        let mut model: Vec<u32> = Vec::new();
        let mut x: u32 = 0x9e37_79b9;
        for _ in 0..10_000 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            let k = x % 20;
            tb.take(k, &l, t);
            model.retain(|&m| m != k);
            model.insert(0, k);
            model.truncate(8);
            let mut order = Vec::new();
            let mut i = tb.head;
            while i != NIL {
                order.push(tb.slots[i as usize].key);
                i = tb.slots[i as usize].next;
            }
            assert_eq!(order, model);
            assert_eq!(tb.len(), model.len());
        }
    }
}
