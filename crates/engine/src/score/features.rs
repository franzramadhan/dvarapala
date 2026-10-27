use std::time::{Duration, Instant};

pub const FEATURES: usize = 10;

/// One client's feature vector, in [`FEATURE_NAMES`] order.
pub type Features = [f64; FEATURES];

/// Feature names a model must use (RFC 0002, "Online features").
pub const FEATURE_NAMES: [&str; FEATURES] = [
    "window_requests",
    "rate_ewma",
    "iat_mean",
    "iat_var",
    "size_mean",
    "no_ua_share",
    "distinct_paths",
    "status_4xx_share",
    "global_rate_z",
    "source_entropy",
];

/// Distinct paths tracked per window; more count as this many.
pub const MAX_PATHS: usize = 8;

/// Smoothing for every per-client average.
// ponytail: one fixed factor; per-feature keys if a model needs them
const ALPHA: f32 = 0.1;

/// Per-client statistics, updated online in constant memory. Lives in the
/// limiter table entry, so it shares its capacity and eviction.
#[derive(Debug, Clone, Default)]
pub struct ClientStats {
    window_start: Option<Instant>,
    window_requests: u32,
    last: Option<Instant>,
    rate_ewma: f32,
    iat_mean: f32,
    iat_var: f32,
    size_mean: f32,
    no_ua: f32,
    paths: [u32; MAX_PATHS],
    status_4xx: f32,
    requests: u32,
    statuses: u32,
    /// closed windows so far
    windows: u32,
}

/// Moves `avg` toward `x`; the first sample sets it.
fn ewma(avg: &mut f32, x: f32, first: bool) {
    *avg = if first { x } else { *avg + ALPHA * (x - *avg) };
}

impl ClientStats {
    /// Records one request. `path_hash` is any hash of the request path.
    pub fn record(
        &mut self,
        now: Instant,
        window: Duration,
        size: u64,
        has_user_agent: bool,
        path_hash: u64,
    ) {
        match self.window_start {
            Some(start) if now.saturating_duration_since(start) < window => {}
            prev => {
                if prev.is_some() {
                    let n = self.window_requests as f32;
                    ewma(&mut self.rate_ewma, n, self.windows == 0);
                    self.windows = self.windows.saturating_add(1);
                }
                self.window_start = Some(now);
                self.window_requests = 0;
                self.paths = [0; MAX_PATHS];
            }
        }
        self.window_requests = self.window_requests.saturating_add(1);
        let first = self.requests == 0;
        ewma(&mut self.size_mean, size as f32, first);
        ewma(
            &mut self.no_ua,
            if has_user_agent { 0.0 } else { 1.0 },
            first,
        );
        if let Some(last) = self.last {
            let iat = now.saturating_duration_since(last).as_secs_f32();
            if self.requests == 1 {
                (self.iat_mean, self.iat_var) = (iat, 0.0);
            } else {
                let d = iat - self.iat_mean;
                self.iat_mean += ALPHA * d;
                self.iat_var = (1.0 - ALPHA) * (self.iat_var + ALPHA * d * d);
            }
        }
        self.last = Some(self.last.map_or(now, |l| l.max(now)));
        self.requests = self.requests.saturating_add(1);
        // 0 marks a free slot
        let p = (path_hash as u32).max(1);
        if !self.paths.contains(&p)
            && let Some(free) = self.paths.iter_mut().find(|x| **x == 0)
        {
            *free = p;
        }
    }

    /// Records the status of a response to this client.
    pub fn record_status(&mut self, status: u16) {
        let is_4xx = if (400..500).contains(&status) {
            1.0
        } else {
            0.0
        };
        ewma(&mut self.status_4xx, is_4xx, self.statuses == 0);
        self.statuses = self.statuses.saturating_add(1);
    }

    /// The feature vector, with the instance-wide signals filled in.
    pub fn features(&self, global_z: f64, entropy: f64) -> Features {
        [
            f64::from(self.window_requests),
            // before the first closed window, the open one is all there is
            f64::from(if self.windows == 0 {
                self.window_requests as f32
            } else {
                self.rate_ewma
            }),
            f64::from(self.iat_mean),
            f64::from(self.iat_var),
            f64::from(self.size_mean),
            f64::from(self.no_ua),
            self.paths.iter().filter(|&&p| p != 0).count() as f64,
            f64::from(self.status_4xx),
            global_z,
            entropy,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: Duration = Duration::from_secs(1);

    fn feature(f: &Features, name: &str) -> f64 {
        f[FEATURE_NAMES.iter().position(|n| *n == name).unwrap()]
    }

    #[test]
    fn counts_window_and_spacing() {
        let t0 = Instant::now();
        let mut s = ClientStats::default();
        for i in 0..10 {
            s.record(t0 + Duration::from_millis(100 * i), W, 200, true, i);
        }
        let f = s.features(1.5, 0.75);
        assert_eq!(feature(&f, "window_requests"), 10.0);
        assert!((feature(&f, "iat_mean") - 0.1).abs() < 0.01);
        assert!(feature(&f, "iat_var") < 1e-4);
        assert!((feature(&f, "size_mean") - 200.0).abs() < 1.0);
        assert_eq!(feature(&f, "distinct_paths"), 8.0);
        assert_eq!(feature(&f, "global_rate_z"), 1.5);
        assert_eq!(feature(&f, "source_entropy"), 0.75);
        // next window starts the count over
        s.record(t0 + Duration::from_secs(2), W, 200, true, 0);
        assert_eq!(feature(&s.features(0.0, 0.0), "window_requests"), 1.0);
    }

    #[test]
    fn shares_move_toward_observed_ratio() {
        let t0 = Instant::now();
        let mut s = ClientStats::default();
        for i in 0..200 {
            s.record(t0 + Duration::from_millis(i), W, 0, false, 1);
            s.record_status(404);
        }
        let f = s.features(0.0, 0.0);
        assert!(feature(&f, "no_ua_share") > 0.95);
        assert!(feature(&f, "status_4xx_share") > 0.95);
        assert_eq!(feature(&f, "distinct_paths"), 1.0);
    }
}
