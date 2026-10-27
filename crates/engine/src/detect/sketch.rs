/// Count-min sketch with conservative update: `depth` rows of `width`
/// counters, fixed at creation. Estimates never undercount.
pub(crate) struct Sketch {
    width: usize,
    rows: Vec<u32>,
}

impl Sketch {
    pub(crate) fn new(_width: usize, _depth: usize) -> Self {
        todo!("rfc 0002")
    }

    /// Counts one occurrence of the key hashed to `h`; returns its estimate.
    pub(crate) fn add(&mut self, _h: u64) -> u32 {
        todo!("rfc 0002")
    }

    pub(crate) fn estimate(&self, _h: u64) -> u32 {
        todo!("rfc 0002")
    }

    /// Starts a new window: every counter back to zero, no reallocation.
    pub(crate) fn clear(&mut self) {
        todo!("rfc 0002")
    }

    pub(crate) fn counters(&self) -> usize {
        self.rows.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::{BuildHasher, RandomState};

    #[test]
    #[ignore = "rfc 0002 case 1"]
    fn never_undercounts_and_error_is_bounded() {
        let hs = RandomState::new();
        let mut s = Sketch::new(2048, 4);
        let counts: Vec<u32> = (0..10_000u32).map(|i| 1 + i % 50).collect();
        let total: u32 = counts.iter().sum();
        for (k, &c) in counts.iter().enumerate() {
            for _ in 0..c {
                s.add(hs.hash_one(k));
            }
        }
        let bound = std::f64::consts::E / 2048.0 * f64::from(total);
        let mut within = 0;
        for (k, &c) in counts.iter().enumerate() {
            let e = s.estimate(hs.hash_one(k));
            assert!(e >= c, "key {k}: estimate {e} < true {c}");
            if f64::from(e - c) <= bound {
                within += 1;
            }
        }
        assert!(within >= 9_900, "{within} of 10000 within e/w");
    }

    #[test]
    #[ignore = "rfc 0002 case 2"]
    fn clear_forgets_the_window() {
        let mut s = Sketch::new(64, 4);
        for _ in 0..10 {
            s.add(42);
        }
        assert_eq!(s.estimate(42), 10);
        s.clear();
        assert_eq!(s.estimate(42), 0);
        assert_eq!(s.counters(), 64 * 4);
    }
}
