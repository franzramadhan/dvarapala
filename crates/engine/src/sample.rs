//! RFC 0023: which trigger hits become LLM samples. Each trigger has a
//! rate, and a client is sampled at most once per trigger per
//! `per_client`. Pure: the caller passes the time and the dice roll.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::ClientKey;

/// What happened to one candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    Sent,
    SkippedRate,
    Deduped,
}

impl Admit {
    /// The `result` label of `dvarapala_llm_samples_total`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Sent => "sent",
            Self::SkippedRate => "skipped_rate",
            Self::Deduped => "deduped",
        }
    }
}

/// The per-trigger rates and the dedupe table, bounded at `capacity`
/// entries; the oldest goes first when it is full.
#[derive(Debug)]
pub struct Gate {
    rates: Vec<f64>,
    per_client: Duration,
    capacity: usize,
    seen: HashMap<(usize, ClientKey), Instant>,
    // every entry lives `per_client`, so insertion order is expiry order
    order: VecDeque<((usize, ClientKey), Instant)>,
}

impl Gate {
    /// `rates[i]` is trigger `i`'s share of candidates, in (0, 1].
    pub fn new(rates: Vec<f64>, per_client: Duration, capacity: usize) -> Self {
        Self {
            rates,
            per_client,
            capacity: capacity.max(1),
            seen: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Decides for a candidate of trigger `trigger` from `client`. `roll`
    /// is uniform in [0, 1).
    pub fn admit(&mut self, trigger: usize, client: ClientKey, now: Instant, roll: f64) -> Admit {
        while let Some(&(_, at)) = self.order.front() {
            if now.saturating_duration_since(at) < self.per_client {
                break;
            }
            self.pop();
        }
        let key = (trigger, client);
        if self.seen.contains_key(&key) {
            return Admit::Deduped;
        }
        if roll >= self.rates.get(trigger).copied().unwrap_or(0.0) {
            return Admit::SkippedRate;
        }
        if self.seen.len() >= self.capacity {
            self.pop();
        }
        self.seen.insert(key, now);
        self.order.push_back((key, now));
        Admit::Sent
    }

    fn pop(&mut self) {
        if let Some((k, at)) = self.order.pop_front()
            && self.seen.get(&k) == Some(&at)
        {
            self.seen.remove(&k);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn client(n: u32) -> ClientKey {
        IpAddr::V4(Ipv4Addr::from(0xC000_0200 + n)).into()
    }

    /// A fixed LCG, so the test does not depend on luck.
    fn rolls() -> impl FnMut() -> f64 {
        let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
        move || {
            s = s
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (s >> 11) as f64 / (1u64 << 53) as f64
        }
    }

    // RFC 0023 case 3
    #[test]
    fn rate_samples_a_share() {
        let mut g = Gate::new(vec![0.25], Duration::from_secs(600), 10_000);
        let (now, mut roll) = (Instant::now(), rolls());
        let sent = (0..4000)
            .filter(|&n| g.admit(0, client(n), now, roll()) == Admit::Sent)
            .count();
        assert!((900..=1100).contains(&sent), "{sent}");
    }

    // RFC 0023 case 4
    #[test]
    fn one_sample_per_client_and_trigger() {
        let mut g = Gate::new(vec![1.0, 1.0], Duration::from_secs(600), 100);
        let t0 = Instant::now();
        let got: Vec<_> = (0..50)
            .map(|s| g.admit(0, client(1), t0 + Duration::from_secs(s), 0.0))
            .collect();
        assert_eq!(got[0], Admit::Sent);
        assert_eq!(got.iter().filter(|a| **a == Admit::Deduped).count(), 49);
        // another trigger counts apart, and the window ends
        assert_eq!(g.admit(1, client(1), t0, 0.0), Admit::Sent);
        let later = t0 + Duration::from_secs(600);
        assert_eq!(g.admit(0, client(1), later, 0.0), Admit::Sent);
    }

    #[test]
    fn bounded_oldest_first() {
        let mut g = Gate::new(vec![1.0], Duration::from_secs(600), 2);
        let t0 = Instant::now();
        for n in 0..3 {
            assert_eq!(g.admit(0, client(n), t0, 0.0), Admit::Sent);
        }
        assert_eq!(g.seen.len(), 2);
        assert_eq!(g.admit(0, client(0), t0, 0.0), Admit::Sent);
        assert_eq!(g.admit(0, client(2), t0, 0.0), Admit::Deduped);
        assert_eq!(g.admit(0, client(9), t0, 0.5), Admit::Sent);
    }
}
