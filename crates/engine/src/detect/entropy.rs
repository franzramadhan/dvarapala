/// Shannon entropy of sources over a fixed number of hashed buckets.
pub(crate) struct Entropy {
    buckets: Vec<u32>,
    total: u64,
}

impl Entropy {
    pub(crate) fn new(_buckets: usize) -> Self {
        todo!("rfc 0002")
    }

    pub(crate) fn add(&mut self, _h: u64) {
        todo!("rfc 0002")
    }

    /// Entropy over the maximum for the bucket count, in `[0, 1]`.
    pub(crate) fn normalized(&self) -> f64 {
        todo!("rfc 0002")
    }

    /// `2^H`: the effective number of equally busy sources.
    pub(crate) fn perplexity(&self) -> f64 {
        todo!("rfc 0002")
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
    #[ignore = "rfc 0002 case 9"]
    fn uniform_sources_near_one() {
        let hs = RandomState::new();
        let mut e = Entropy::new(1024);
        for k in 0..200_000u32 {
            e.add(hs.hash_one(k));
        }
        assert!(e.normalized() > 0.99, "{}", e.normalized());
    }

    #[test]
    #[ignore = "rfc 0002 case 10"]
    fn single_source_is_zero() {
        let mut e = Entropy::new(1024);
        for _ in 0..1000 {
            e.add(42);
        }
        assert_eq!(e.normalized(), 0.0);
        assert_eq!(e.perplexity(), 1.0);
    }

    #[test]
    #[ignore = "rfc 0002"]
    fn empty_window_is_zero() {
        let e = Entropy::new(16);
        assert_eq!(e.normalized(), 0.0);
    }
}
