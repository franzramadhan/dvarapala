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
}

impl ClientStats {
    /// Records one request. `path_hash` is any hash of the request path.
    pub fn record(
        &mut self,
        _now: Instant,
        _window: Duration,
        _size: u64,
        _has_user_agent: bool,
        _path_hash: u64,
    ) {
        todo!("rfc 0002")
    }

    /// Records the status of a response to this client.
    pub fn record_status(&mut self, _status: u16) {
        todo!("rfc 0002")
    }

    /// The feature vector, with the instance-wide signals filled in.
    pub fn features(&self, _global_z: f64, _entropy: f64) -> Features {
        todo!("rfc 0002")
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
    #[ignore = "rfc 0002"]
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
    #[ignore = "rfc 0002"]
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
