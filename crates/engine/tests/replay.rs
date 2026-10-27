//! RFC 0002 cases 16 to 18: synthetic traces replayed through `Detector`.
//! Sources are random addresses in 10.0.0.0/8; time is an input, nothing
//! sleeps.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use dvarapala_engine::{Cidr, DetectConfig, Detector, State};

/// xorshift64*
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Normal approximation of a Poisson count with mean `l`.
    fn poisson(&mut self, l: f64) -> u32 {
        let (u, v) = (self.unit().max(f64::MIN_POSITIVE), self.unit());
        let z = (-2.0 * u.ln()).sqrt() * (std::f64::consts::TAU * v).cos();
        (l + l.sqrt() * z).round().max(0.0) as u32
    }

    /// One of `n` fixed background sources.
    fn source(&mut self, n: u32) -> IpAddr {
        let i = (self.next() % u64::from(n)) as u32;
        // spread the index over 10/8 so /24 grouping still sees many prefixes
        IpAddr::V4(Ipv4Addr::from(
            0x0a00_0000 | (i.wrapping_mul(2_654_435_761) & 0xff_ffff),
        ))
    }
}

struct Replay {
    d: Detector,
    rng: Rng,
    t0: Instant,
    window: u64,
}

impl Replay {
    fn new(cfg: DetectConfig) -> Self {
        Self {
            d: Detector::new(cfg).unwrap(),
            rng: Rng(0x5eed),
            t0: Instant::now(),
            window: 0,
        }
    }

    /// One window: `background` Poisson requests from 5000 sources plus
    /// `extra` requests from `pick`. Returns the state after the window
    /// before it was closed.
    fn window(&mut self, background: f64, extra: u32, mut pick: impl FnMut(&mut Rng) -> IpAddr) {
        let now = self.t0 + Duration::from_secs(self.window);
        for _ in 0..self.rng.poisson(background) {
            let ip = self.rng.source(5000);
            self.d.observe(ip, now);
        }
        for _ in 0..extra {
            let ip = pick(&mut self.rng);
            self.d.observe(ip, now);
        }
        self.window += 1;
    }

    /// Closes the open window with one background request.
    fn close(&mut self) -> State {
        let now = self.t0 + Duration::from_secs(self.window);
        let ip = self.rng.source(5000);
        self.d.observe(ip, now);
        self.d.state()
    }
}

fn none(_: &mut Rng) -> IpAddr {
    unreachable!()
}

#[test]
fn distributed_flood_reaches_attack_fast() {
    let cfg = DetectConfig::default();
    let trigger = cfg.trigger_windows;
    let mut r = Replay::new(cfg);
    for _ in 0..600 {
        r.window(1000.0, 0, none);
    }
    assert_eq!(r.close(), State::Normal);
    // 200 prefixes, together 50x the baseline
    let attackers: Vec<IpAddr> = (0..200u32)
        .map(|i| IpAddr::V4(Ipv4Addr::from(0x0b00_0000 | (i << 8))))
        .collect();
    let mut reached = None;
    for w in 1..=trigger + 1 {
        r.window(1000.0, 50_000, |rng| attackers[(rng.next() % 200) as usize]);
        if r.close() == State::Attack {
            reached = Some(w);
            break;
        }
    }
    assert!(
        reached.is_some(),
        "no Attack within {} windows",
        trigger + 1
    );
    let set: HashSet<Cidr> = attackers.iter().map(|&a| Cidr::of(a, 32)).collect();
    let heavy = r.d.heavy();
    assert!(!heavy.is_empty());
    assert!(heavy.iter().all(|(c, _)| set.contains(c)), "{heavy:?}");
}

#[test]
fn slow_doubling_never_attacks() {
    let mut r = Replay::new(DetectConfig::default());
    for w in 0..3600 {
        r.window(200.0 * (1.0 + f64::from(w) / 3600.0), 0, none);
        assert_ne!(r.close(), State::Attack, "window {w}");
    }
}

#[test]
fn one_subnet_at_thirty_percent_drops_entropy() {
    // grouping by /24 is what makes one subnet one source
    let cfg = DetectConfig {
        prefix_v4: 24,
        ..DetectConfig::default()
    };
    let mut r = Replay::new(cfg);
    for _ in 0..600 {
        r.window(1000.0, 0, none);
    }
    assert_eq!(r.close(), State::Normal);
    let mut states = Vec::new();
    for _ in 0..5 {
        // same total rate: 700 background, 300 from 192.0.2.0/24
        r.window(700.0, 300, |rng| {
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, (rng.next() % 256) as u8))
        });
        states.push(r.close());
    }
    assert_eq!(states.last(), Some(&State::Attack), "{states:?}");
}
