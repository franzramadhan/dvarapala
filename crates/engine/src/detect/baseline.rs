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
    pub(crate) fn new(alpha: f64, warmup: u32) -> Self {
        Self {
            alpha,
            warmup,
            n: 0,
            mean: 0.0,
            var: 0.0,
        }
    }

    pub(crate) fn ready(&self) -> bool {
        self.n > 0 && self.n >= self.warmup
    }

    pub(crate) fn mean(&self) -> f64 {
        self.mean
    }

    /// Standard deviations `x` lies above the mean; 0 before any sample.
    pub(crate) fn zscore(&self, x: f64) -> f64 {
        if self.n == 0 {
            return 0.0;
        }
        // floor at the Poisson spread: a perfectly steady signal has no
        // variance, and dividing by ~0 would alarm on any wobble
        let sd = self.var.sqrt().max(self.mean.sqrt()).max(1.0);
        (x - self.mean) / sd
    }

    pub(crate) fn learn(&mut self, x: f64) {
        if self.n == 0 {
            self.mean = x;
        } else {
            let d = x - self.mean;
            self.mean += self.alpha * d;
            self.var = (1.0 - self.alpha) * (self.var + self.alpha * d * d);
        }
        self.n = self.n.saturating_add(1);
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
    fn steady_rate_scores_zero() {
        let b = warmed(|| 100.0);
        assert!(b.zscore(100.0).abs() < 0.5, "{}", b.zscore(100.0));
    }

    #[test]
    fn tenfold_window_scores_high() {
        let mut r = Rng(7);
        let b = warmed(|| r.poisson(100.0));
        assert!(b.zscore(1000.0) > 4.0, "{}", b.zscore(1000.0));
    }

    #[test]
    fn no_alarm_during_warmup() {
        let mut b = Baseline::new(0.05, 300);
        for _ in 0..299 {
            b.learn(100.0);
        }
        assert!(!b.ready());
    }
}
