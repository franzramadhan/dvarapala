//! RFC 0022: the traffic history behind the console graph. A fixed ring of
//! samples (rates per verdict) and the roll-up into minute rows for a
//! store. The caller passes the counters and the clock in.
#![allow(unused_variables, unused_imports, dead_code)]

use std::collections::VecDeque;

use crate::State;

/// Verdicts per sample, in the order of `dvarapala_requests_total`:
/// allow, throttle, challenge, drop, error.
pub const VERDICTS: usize = 5;

/// Rates per second over one interval, ending at `t_ms` (Unix ms).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sample {
    pub t_ms: u64,
    pub rates: [f64; VERDICTS],
    /// `None` without detection.
    pub state: Option<State>,
}

/// Requests per verdict in the minute starting at `minute_ms`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Minute {
    pub minute_ms: u64,
    pub counts: [u64; VERDICTS],
}

/// The last `capacity` samples, allocated once.
#[derive(Debug)]
pub struct Ring {
    buf: VecDeque<Sample>,
    capacity: usize,
}

impl Ring {
    pub fn new(capacity: usize) -> Self {
        todo!("rfc 0022")
    }

    pub fn push(&mut self, s: Sample) {
        todo!("rfc 0022")
    }

    /// The samples at or after `since_ms`, oldest first.
    pub fn since(&self, since_ms: u64) -> Vec<Sample> {
        todo!("rfc 0022")
    }

    /// The oldest sample's time, `None` when empty.
    pub fn oldest(&self) -> Option<u64> {
        todo!("rfc 0022")
    }
}

/// Turns cumulative counters into samples and minute rows.
#[derive(Debug, Default)]
pub struct Sampler {
    prev: Option<(u64, [u64; VERDICTS])>,
    minute: Option<Minute>,
}

impl Sampler {
    /// The sample since the previous call, and the minute row completed by
    /// it, if any. The first call, a clock that did not move and counters
    /// that went down (they restarted) give no sample.
    pub fn sample(
        &mut self,
        t_ms: u64,
        totals: [u64; VERDICTS],
        state: Option<State>,
    ) -> (Option<Sample>, Option<Minute>) {
        todo!("rfc 0022")
    }

    /// Adds `delta` to the minute of `t_ms`; a new minute closes the last.
    fn roll(&mut self, t_ms: u64, delta: [u64; VERDICTS]) -> Option<Minute> {
        todo!("rfc 0022")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(t_ms: u64) -> Sample {
        Sample {
            t_ms,
            rates: [0.0; VERDICTS],
            state: None,
        }
    }

    // RFC 0022 case 1
    #[test]
    #[ignore = "rfc 0022"]
    fn the_ring_keeps_the_last_samples() {
        let mut r = Ring::new(3);
        for t in 1..=5 {
            r.push(s(t));
        }
        let t: Vec<_> = r.since(0).iter().map(|s| s.t_ms).collect();
        assert_eq!(t, [3, 4, 5]);
        assert_eq!(r.since(5).len(), 1);
        assert_eq!(r.oldest(), Some(3));
    }

    // RFC 0022 case 2
    #[test]
    #[ignore = "rfc 0022"]
    fn rates_per_second() {
        let mut p = Sampler::default();
        assert_eq!(p.sample(0, [100, 0, 0, 0, 0], None), (None, None));
        let (s, _) = p.sample(5_000, [150, 5, 0, 0, 0], Some(State::Attack));
        let s = s.unwrap();
        assert_eq!(s.rates, [10.0, 1.0, 0.0, 0.0, 0.0]);
        assert_eq!(s.state, Some(State::Attack));
    }

    // RFC 0022 case 3
    #[test]
    #[ignore = "rfc 0022"]
    fn counters_that_go_down_give_no_sample() {
        let mut p = Sampler::default();
        p.sample(0, [100, 0, 0, 0, 0], None);
        assert_eq!(p.sample(5_000, [10, 0, 0, 0, 0], None), (None, None));
        // and the next interval counts from the new values
        let (s, _) = p.sample(10_000, [20, 0, 0, 0, 0], None);
        assert_eq!(s.unwrap().rates[0], 2.0);
    }

    // RFC 0022 case 4
    #[test]
    #[ignore = "rfc 0022"]
    fn samples_roll_up_into_minutes() {
        let mut p = Sampler::default();
        let mut rows = Vec::new();
        // 60_000 is the first minute boundary; 13 samples of 5 s from there
        for i in 0..=13u64 {
            let (_, m) = p.sample(60_000 + i * 5_000, [i * 10, i, 0, 0, 0], None);
            rows.extend(m);
        }
        // the samples at 65 s .. 115 s are in the minute of 60 s; 120 s opens the next
        assert_eq!(
            rows,
            [Minute {
                minute_ms: 60_000,
                counts: [110, 11, 0, 0, 0]
            }]
        );
    }
}
