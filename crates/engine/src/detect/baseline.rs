/// Exponentially weighted mean and variance of one signal, one sample per
/// window. Alarms only after `warmup` samples.
pub(crate) struct Baseline {
    alpha: f64,
    warmup: u32,
    n: u32,
    mean: f64,
    var: f64,
}

impl Baseline {
    pub(crate) fn new(_alpha: f64, _warmup: u32) -> Self {
        todo!("rfc 0002")
    }

    pub(crate) fn ready(&self) -> bool {
        todo!("rfc 0002")
    }

    pub(crate) fn mean(&self) -> f64 {
        self.mean
    }

    /// Standard deviations `x` lies above the mean; 0 before any sample.
    pub(crate) fn zscore(&self, _x: f64) -> f64 {
        todo!("rfc 0002")
    }

    pub(crate) fn learn(&mut self, _x: f64) {
        todo!("rfc 0002")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// xorshift64*, enough randomness for synthetic traffic.
    pub(crate) struct Rng(pub u64);

    impl Rng {
        pub(crate) fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        pub(crate) fn unit(&mut self) -> f64 {
            (self.next() >> 11) as f64 / (1u64 << 53) as f64
        }

        /// Normal approximation of a Poisson count with mean `l`.
        pub(crate) fn poisson(&mut self, l: f64) -> f64 {
            let (u, v) = (self.unit().max(f64::MIN_POSITIVE), self.unit());
            let z = (-2.0 * u.ln()).sqrt() * (std::f64::consts::TAU * v).cos();
            (l + l.sqrt() * z).round().max(0.0)
        }
    }

    fn warmed(rate: impl FnMut() -> f64) -> Baseline {
        let mut b = Baseline::new(0.05, 300);
        std::iter::repeat_with(rate)
            .take(300)
            .for_each(|x| b.learn(x));
        assert!(b.ready());
        b
    }

    #[test]
    #[ignore = "rfc 0002 case 5"]
    fn steady_rate_scores_zero() {
        let b = warmed(|| 100.0);
        assert!(b.zscore(100.0).abs() < 0.5, "{}", b.zscore(100.0));
    }

    #[test]
    #[ignore = "rfc 0002 case 6"]
    fn tenfold_window_scores_high() {
        let mut r = Rng(7);
        let b = warmed(|| r.poisson(100.0));
        assert!(b.zscore(1000.0) > 4.0, "{}", b.zscore(1000.0));
    }

    #[test]
    #[ignore = "rfc 0002 case 7"]
    fn no_alarm_during_warmup() {
        let mut b = Baseline::new(0.05, 300);
        for _ in 0..299 {
            b.learn(100.0);
        }
        assert!(!b.ready());
    }
}
