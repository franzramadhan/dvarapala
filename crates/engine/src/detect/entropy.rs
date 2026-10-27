/// Shannon entropy of sources over a fixed number of hashed buckets.
pub(crate) struct Entropy {
    buckets: Vec<u32>,
    total: u64,
}

impl Entropy {
    pub(crate) fn new(buckets: usize) -> Self {
        Self {
            buckets: vec![0; buckets],
            total: 0,
        }
    }

    pub(crate) fn add(&mut self, h: u64) {
        // high bits: the sketch uses the low ones for its columns
        let i = ((h >> 40) % self.buckets.len() as u64) as usize;
        self.buckets[i] = self.buckets[i].saturating_add(1);
        self.total += 1;
    }

    /// Shannon entropy in bits.
    fn bits(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        let t = self.total as f64;
        let sum: f64 = self
            .buckets
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| f64::from(c) * f64::from(c).log2())
            .sum();
        (t.log2() - sum / t).max(0.0)
    }

    /// Entropy over the maximum for the bucket count, in `[0, 1]`.
    pub(crate) fn normalized(&self) -> f64 {
        self.bits() / (self.buckets.len() as f64).log2()
    }

    /// `2^H`: the effective number of equally busy sources.
    pub(crate) fn perplexity(&self) -> f64 {
        self.bits().exp2()
    }

    pub(crate) fn total(&self) -> u64 {
        self.total
    }

    pub(crate) fn clear(&mut self) {
        self.buckets.fill(0);
        self.total = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::{BuildHasher, RandomState};

    #[test]
    fn uniform_sources_near_one() {
        let hs = RandomState::new();
        let mut e = Entropy::new(1024);
        for k in 0..200_000u32 {
            e.add(hs.hash_one(k));
        }
        assert!(e.normalized() > 0.99, "{}", e.normalized());
    }

    #[test]
    fn single_source_is_zero() {
        let mut e = Entropy::new(1024);
        for _ in 0..1000 {
            e.add(42);
        }
        assert_eq!(e.normalized(), 0.0);
        assert_eq!(e.perplexity(), 1.0);
    }

    #[test]
    fn empty_window_is_zero() {
        let e = Entropy::new(16);
        assert_eq!(e.normalized(), 0.0);
    }
}
