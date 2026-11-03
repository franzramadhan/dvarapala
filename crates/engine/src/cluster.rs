use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::{Blocks, Cidr, ClientKey, Limit, ScheduleConfig, Verdict};

/// Shared state across replicas (RFC 0010).
#[derive(Debug, Clone)]
pub struct ClusterConfig {
    /// The per-client limit; `None` without a rate limiter (forward mode).
    pub limit: Option<Limit>,
    /// Length of a cluster counting window, aligned to unix time so every
    /// replica counts the same window.
    pub window: Duration,
    /// Clients sent per sync at most, busiest first.
    pub max_keys: usize,
    /// Clients counted between syncs at most (the rate limiter's table size).
    pub max_clients: usize,
}

/// What one replica sends in a sync round.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Batch {
    /// Start of the current window, unix milliseconds.
    pub window_start: u64,
    /// Requests allowed per client since the last round, busiest first.
    pub counts: Vec<(ClientKey, u32)>,
    /// Heavy hitters to publish, with how long they stay listed.
    pub heavy: Vec<(Cidr, Duration)>,
    /// Provider pauses to publish, per destination name.
    pub pauses: Vec<(String, Duration)>,
    /// Clients left out by `max_keys` or `max_clients` since the last round.
    pub dropped: u64,
}

/// What [`Cluster::take`] removed: not yet cut to `max_keys` or sorted.
#[derive(Debug)]
pub struct Pending {
    counts: HashMap<ClientKey, u32>,
    dropped: u64,
    heavy: Vec<(Cidr, Duration)>,
    pauses: Vec<(String, Duration)>,
    max_keys: usize,
    window_ms: u64,
}

impl Pending {
    /// Keeps the busiest `max_keys` clients, busiest first, and counts the
    /// rest as dropped. `unix_ms` is the wall clock.
    pub fn into_batch(self, unix_ms: u64) -> Batch {
        let mut counts: Vec<_> = self.counts.into_iter().collect();
        let mut dropped = self.dropped;
        if counts.len() > self.max_keys {
            counts.select_nth_unstable_by(self.max_keys, |a, b| b.1.cmp(&a.1));
            dropped += (counts.len() - self.max_keys) as u64;
            counts.truncate(self.max_keys);
        }
        counts.sort_unstable_by_key(|&(_, n)| std::cmp::Reverse(n));
        Batch {
            window_start: unix_ms - unix_ms % self.window_ms,
            counts,
            heavy: self.heavy,
            pauses: self.pauses,
            dropped,
        }
    }
}

/// What a sync round brings back.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Reply {
    /// Live replicas, this one included.
    pub replicas: u32,
    /// Cluster count of the window for each client in the batch.
    pub totals: Vec<(ClientKey, u64)>,
    /// Listed heavy hitters and how long they stay listed.
    pub heavy: Vec<(Cidr, Duration)>,
    /// Paused destinations and how long the pause lasts.
    pub pauses: Vec<(String, Duration)>,
}

/// One replica's view of the cluster: local counts waiting for the next
/// sync, and what the last sync decided. The request path reads it, the
/// sync task drains and feeds it. Time is an input.
///
/// Not thread-safe; callers wrap it in a lock.
#[derive(Debug)]
pub struct Cluster {
    cfg: ClusterConfig,
    deltas: HashMap<ClientKey, u32>,
    dropped: u64,
    throttled: HashMap<ClientKey, Instant>,
    blocked: Blocks,
    heavy_out: Vec<(Cidr, Duration)>,
    pauses_out: Vec<(String, Duration)>,
    pauses: HashMap<String, Instant>,
    replicas: u32,
}

impl Cluster {
    pub fn new(cfg: ClusterConfig) -> Self {
        Self {
            cfg,
            deltas: HashMap::new(),
            dropped: 0,
            throttled: HashMap::new(),
            blocked: Blocks::new(0),
            heavy_out: Vec::new(),
            pauses_out: Vec::new(),
            pauses: HashMap::new(),
            replicas: 1,
        }
    }

    /// The cluster's verdict for `key` at `now`, before the local bucket:
    /// `Drop` for a listed heavy hitter, `Throttle` for a client over the
    /// cluster count, `None` to go on.
    pub fn check(&self, key: ClientKey, now: Instant) -> Option<Verdict> {
        if self.blocked.contains(IpAddr::from(key), now) {
            return Some(Verdict::Drop);
        }
        let until = *self.throttled.get(&key)?;
        (until > now).then(|| Verdict::Throttle {
            retry_after: until - now,
        })
    }

    /// Counts one allowed request from `key` for the next sync.
    pub fn record(&mut self, key: ClientKey) {
        if let Some(n) = self.deltas.get_mut(&key) {
            *n = n.saturating_add(1);
        } else if self.deltas.len() < self.cfg.max_clients {
            self.deltas.insert(key, 1);
        } else {
            self.dropped += 1;
        }
    }

    /// Publishes the local detector's heavy hitters, listed for `ttl`.
    pub fn publish_heavy(&mut self, heavy: impl IntoIterator<Item = Cidr>, ttl: Duration) {
        self.heavy_out.extend(heavy.into_iter().map(|c| (c, ttl)));
    }

    /// Publishes a provider pause seen on this replica.
    pub fn publish_pause(&mut self, destination: &str, retry_after: Duration) {
        self.pauses_out.push((destination.to_owned(), retry_after));
    }

    /// How long `destination` stays paused by another replica, if at all.
    pub fn pause(&self, destination: &str, now: Instant) -> Option<Duration> {
        let until = *self.pauses.get(destination)?;
        (until > now).then(|| until - now)
    }

    /// Live replicas seen by the last good round, at least 1. Kept as is
    /// while the store is down, so the forward split stays safe.
    pub fn replicas(&self) -> u32 {
        self.replicas
    }

    pub fn window(&self) -> Duration {
        self.cfg.window
    }

    /// Takes everything waiting for the store, without sorting it. O(1):
    /// swaps the containers out, so the lock is held briefly. Build the
    /// batch with [`Pending::into_batch`] after releasing the lock.
    pub fn take(&mut self) -> Pending {
        Pending {
            // shortcut: the map regrows on the request path, keep a spare map if that shows up
            counts: std::mem::take(&mut self.deltas),
            dropped: std::mem::take(&mut self.dropped),
            heavy: std::mem::take(&mut self.heavy_out),
            pauses: std::mem::take(&mut self.pauses_out),
            max_keys: self.cfg.max_keys,
            window_ms: self.window_ms(),
        }
    }

    /// Takes everything waiting for the store; `unix_ms` is the wall clock.
    pub fn drain(&mut self, unix_ms: u64) -> Batch {
        self.take().into_batch(unix_ms)
    }

    /// Applies a good round: clients over the cluster allowance are
    /// throttled until their window ends, and the lists are replaced.
    pub fn apply(&mut self, reply: Reply, now: Instant, unix_ms: u64) {
        self.throttled.retain(|_, until| *until > now);
        if let Some(limit) = self.cfg.limit {
            let allowance = limit.allowance(self.cfg.window);
            let w = self.window_ms();
            let left = Duration::from_millis(w - unix_ms % w);
            for (key, total) in reply.totals {
                if total as f64 > allowance {
                    self.throttled.insert(key, now + left);
                }
            }
        }
        self.blocked =
            Blocks::from_entries(reply.heavy.into_iter().map(|(c, d)| (c, now + d)), now);
        self.pauses = reply
            .pauses
            .into_iter()
            .map(|(n, d)| (n, now + d))
            .collect();
        self.replicas = reply.replicas.max(1);
    }

    fn window_ms(&self) -> u64 {
        (self.cfg.window.as_millis() as u64).max(1)
    }
}

/// One replica's share of a destination budget (fail closed toward the
/// provider): rate divided by `replicas`, burst and `max_concurrent`
/// rounded down but at least 1. `max_concurrent` 0 (unlimited) stays 0.
pub fn split(
    cfg: &ScheduleConfig,
    max_concurrent: usize,
    replicas: u32,
) -> (ScheduleConfig, usize) {
    let n = replicas.max(1);
    let share = ScheduleConfig {
        rate: (cfg.rate / f64::from(n)).max(0.001),
        burst: (cfg.burst / n).max(1),
        ..*cfg
    };
    let places = if max_concurrent == 0 {
        0
    } else {
        (max_concurrent / n as usize).max(1)
    };
    (share, places)
}

/// Most requests a client can get through beyond the cluster allowance in
/// one window: every replica allows up to a sync interval of full rate
/// before the counts meet.
pub fn overshoot(rate: f64, replicas: u32, sync_interval: Duration) -> f64 {
    f64::from(replicas) * rate * sync_interval.as_secs_f64()
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn key(last: u8) -> ClientKey {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)).into()
    }

    fn cluster(max_keys: usize) -> Cluster {
        Cluster::new(ClusterConfig {
            limit: Some(Limit::new(10, 5).unwrap()),
            window: Duration::from_secs(10),
            max_keys,
            max_clients: 100,
        })
    }

    // RFC 0010 case 2
    #[test]
    fn over_the_cluster_count_throttles_until_the_window_ends() {
        let mut c = cluster(10);
        let t = Instant::now();
        // allowance 5 + 10 x 10 = 105; three replicas sent 40 each
        c.apply(
            Reply {
                replicas: 3,
                totals: vec![(key(1), 120), (key(2), 100)],
                ..Reply::default()
            },
            t,
            4_000,
        );
        let v = c.check(key(1), t);
        assert_eq!(
            v,
            Some(Verdict::Throttle {
                retry_after: Duration::from_secs(6)
            })
        );
        assert_eq!(c.check(key(2), t), None);
        assert_eq!(c.check(key(1), t + Duration::from_secs(6)), None);
        assert_eq!(c.replicas(), 3);
    }

    // RFC 0010 case 3
    #[test]
    fn overshoot_is_bounded_by_replicas_rate_and_interval() {
        assert_eq!(overshoot(20.0, 4, Duration::from_secs(1)), 80.0);
    }

    // RFC 0010 case 4
    #[test]
    fn destination_budget_is_split_by_live_replicas() {
        let cfg = ScheduleConfig {
            rate: 50.0,
            burst: 5,
            ..ScheduleConfig::default()
        };
        let (s, p) = split(&cfg, 4, 2);
        assert_eq!((s.rate, s.burst, p), (25.0, 2, 2));
        let (s, p) = split(&cfg, 4, 3);
        assert!((s.rate - 16.67).abs() < 0.01);
        assert_eq!((s.burst, p), (1, 1));
        assert_eq!(split(&cfg, 0, 3).1, 0);
        assert_eq!(split(&cfg, 4, 0).0.rate, 50.0);
    }

    #[test]
    fn drain_keeps_the_busiest_and_counts_the_rest() {
        let mut c = cluster(2);
        for (k, n) in [(1, 1), (2, 5), (3, 3)] {
            for _ in 0..n {
                c.record(key(k));
            }
        }
        let b = c.drain(12_345);
        assert_eq!(b.window_start, 10_000);
        assert_eq!(b.counts, vec![(key(2), 5), (key(3), 3)]);
        assert_eq!(b.dropped, 1);
        assert_eq!(c.drain(12_345).counts, vec![]);
    }

    #[test]
    fn take_then_build_matches_drain_and_leaves_the_cluster_empty() {
        let mut c = cluster(2);
        for (k, n) in [(1, 1), (2, 5), (3, 3)] {
            for _ in 0..n {
                c.record(key(k));
            }
        }
        c.publish_pause("api", Duration::from_secs(3));
        let pending = c.take();
        // the cluster is already empty before the batch is built
        let again = c.take().into_batch(0);
        assert_eq!(
            (again.counts, again.dropped, again.pauses),
            (vec![], 0, vec![])
        );
        let b = pending.into_batch(12_345);
        assert_eq!(b.window_start, 10_000);
        assert_eq!(b.counts, vec![(key(2), 5), (key(3), 3)]);
        assert_eq!(b.dropped, 1);
        assert_eq!(b.pauses, vec![("api".to_owned(), Duration::from_secs(3))]);
    }

    #[test]
    fn record_is_bounded_by_max_clients() {
        let mut c = Cluster::new(ClusterConfig {
            max_clients: 1,
            ..cluster(10).cfg
        });
        c.record(key(1));
        c.record(key(2));
        c.record(key(1));
        let b = c.drain(0);
        assert_eq!((b.counts, b.dropped), (vec![(key(1), 2)], 1));
    }

    #[test]
    fn heavy_hitters_and_pauses_round_trip() {
        let mut c = cluster(10);
        let t = Instant::now();
        let net: Cidr = "192.0.2.0/24".parse().unwrap();
        c.publish_heavy([net], Duration::from_secs(30));
        c.publish_pause("api", Duration::from_secs(2));
        let b = c.drain(0);
        assert_eq!(b.heavy, vec![(net, Duration::from_secs(30))]);
        assert_eq!(b.pauses, vec![("api".into(), Duration::from_secs(2))]);
        c.apply(
            Reply {
                replicas: 2,
                heavy: b.heavy,
                pauses: b.pauses,
                ..Reply::default()
            },
            t,
            0,
        );
        assert_eq!(c.check(key(9), t), Some(Verdict::Drop));
        assert_eq!(c.pause("api", t), Some(Duration::from_secs(2)));
        assert_eq!(c.pause("other", t), None);
        assert_eq!(c.check(key(9), t + Duration::from_secs(30)), None);
    }

    // issue 308: verdicts over a full list; the bench gates the speed
    #[test]
    fn check_over_a_full_heavy_hitter_list_keeps_verdicts() {
        let mut c = cluster(10);
        let t = Instant::now();
        let ttl = Duration::from_secs(30);
        let net = |i: u32| Cidr::of(IpAddr::V4(Ipv4Addr::from(0x0a00_0000 | i)), 32);
        let mut heavy: Vec<_> = (0..10_000).map(|i| (net(i), ttl)).collect();
        heavy.push((
            Cidr::of(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 32),
            ttl / 2,
        ));
        c.apply(
            Reply {
                heavy,
                ..Reply::default()
            },
            t,
            0,
        );
        let member = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 | 9_999)).into();
        assert_eq!(c.check(member, t), Some(Verdict::Drop));
        assert_eq!(c.check(member, t + ttl), None);
        let half = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)).into();
        assert_eq!(c.check(half, t), Some(Verdict::Drop));
        assert_eq!(c.check(half, t + ttl / 2), None);
        let other = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)).into();
        assert_eq!(c.check(other, t), None);
    }
}
