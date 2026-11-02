use super::*;

const MS: Duration = Duration::from_millis(1);

fn gradient(limit: u32, min: u32, max: u32) -> ConcurrencyConfig {
    ConcurrencyConfig {
        mode: LimitMode::Gradient,
        limit,
        min,
        max,
        window: Duration::from_secs(1),
        reserve: 0.2,
    }
}

fn fixed(limit: u32, reserve: f64) -> ConcurrencyConfig {
    ConcurrencyConfig {
        mode: LimitMode::Fixed,
        limit,
        min: 1,
        max: 1,
        window: Duration::from_secs(1),
        reserve,
    }
}

fn p(class: Class) -> Priority {
    Priority { class, weight: 1 }
}

/// Runs one window: `n` trusted requests in flight at once, each answered
/// after `latency`, then the window closes. Returns the update.
fn window(c: &Concurrency, at: &mut Instant, n: u32, latency: Duration) -> Option<Update> {
    let taken: Vec<u32> = (0..n).filter_map(|_| c.admit(p(Class::Trusted))).collect();
    for w in &taken {
        c.release(*w, Outcome::Answered(latency), *at);
    }
    *at += Duration::from_secs(1);
    c.tick(*at)
}

// RFC 0032 case 1
#[test]
fn flat_latency_grows_the_limit_by_its_square_root() {
    let mut at = Instant::now();
    let c = Concurrency::new(gradient(20, 20, 100), at).unwrap();
    assert_eq!(c.tick(at), None, "the first tick opens the window");
    let mut last = c.limit();
    for _ in 0..15 {
        let u = window(&c, &mut at, last, 10 * MS).expect("a window closed");
        let grown = f64::from(last) + f64::from(last).sqrt();
        assert!(
            f64::from(u.limit) >= grown.min(100.0) - 1.0,
            "{last} to {}",
            u.limit
        );
        assert!(u.limit <= 100);
        last = u.limit;
    }
    assert_eq!(last, 100);
}

#[test]
fn an_idle_limit_does_not_grow() {
    let mut at = Instant::now();
    let c = Concurrency::new(gradient(40, 20, 100), at).unwrap();
    c.tick(at);
    // 5 in flight at most, under half the limit
    let u = window(&c, &mut at, 5, 10 * MS).unwrap();
    assert_eq!(u.limit, 40);
}

// RFC 0032 case 2
#[test]
fn rising_latency_halves_at_most_once_per_window() {
    let mut at = Instant::now();
    let c = Concurrency::new(gradient(400, 20, 1000), at).unwrap();
    c.tick(at);
    let u = window(&c, &mut at, 400, 10 * MS).unwrap();
    let before = u.limit;
    let mut last = before;
    for _ in 0..12 {
        let u = window(&c, &mut at, last, 20 * MS).unwrap();
        assert!(u.limit < last || u.limit == 20, "{last} to {}", u.limit);
        assert!(
            u.limit * 2 >= last,
            "more than halved: {last} to {}",
            u.limit
        );
        assert!(u.limit >= 20);
        last = u.limit;
    }
    assert!(last < before / 2);
}

#[test]
fn failures_count_as_slow() {
    let mut at = Instant::now();
    let c = Concurrency::new(gradient(100, 20, 1000), at).unwrap();
    c.tick(at);
    window(&c, &mut at, 100, 10 * MS).unwrap();
    // connection refused at once: still read as ten times the no-load latency
    for _ in 0..100 {
        let w = c.admit(p(Class::Normal)).unwrap();
        c.release(w, Outcome::Failed(Duration::from_micros(50)), at);
    }
    at += Duration::from_secs(1);
    let u = c.tick(at).unwrap();
    assert!(u.window >= 50 * MS, "{u:?}");
    assert!(u.limit < 100);
}

// RFC 0032 case 3
#[test]
fn fixed_is_a_hard_cap() {
    let c = Concurrency::new(fixed(10, 0.2), Instant::now()).unwrap();
    for _ in 0..8 {
        assert_eq!(c.admit(p(Class::Normal)), Some(1));
    }
    assert_eq!(c.admit(p(Class::Normal)), None);
    for _ in 0..2 {
        assert_eq!(c.admit(p(Class::Trusted)), Some(1));
    }
    for class in Class::ALL {
        assert_eq!(c.admit(p(class)), None, "{class:?}");
    }
    c.release(1, Outcome::Answered(MS), Instant::now());
    assert_eq!(c.admit(p(Class::Normal)), None);
    assert_eq!(c.admit(p(Class::Trusted)), Some(1));
    assert_eq!(c.in_flight(), 10);
    assert_eq!(c.tick(Instant::now() + Duration::from_secs(5)), None);
}

// RFC 0032 case 4
#[test]
fn the_reserve_is_for_trusted_requests() {
    let c = Concurrency::new(fixed(100, 0.2), Instant::now()).unwrap();
    for _ in 0..80 {
        c.admit(p(Class::Trusted)).unwrap();
    }
    assert_eq!(c.admit(p(Class::Normal)), None);
    assert_eq!(c.admit(p(Class::Trusted)), Some(1));
}

#[test]
fn suspects_go_first() {
    let c = Concurrency::new(fixed(100, 0.2), Instant::now()).unwrap();
    for _ in 0..60 {
        c.admit(p(Class::Trusted)).unwrap();
    }
    assert_eq!(c.admit(p(Class::Suspect)), None);
    assert_eq!(c.admit(p(Class::Normal)), Some(1));
}

#[test]
fn weights_take_slots_zero_bypasses() {
    let c = Concurrency::new(fixed(20, 0.0), Instant::now()).unwrap();
    let heavy = Priority {
        class: Class::Normal,
        weight: 10,
    };
    assert_eq!(c.admit(heavy), Some(10));
    assert_eq!(c.admit(heavy), Some(10));
    assert_eq!(c.admit(p(Class::Trusted)), None);
    let free = Priority {
        class: Class::Suspect,
        weight: 0,
    };
    assert_eq!(c.admit(free), Some(0));
    // a weight over the limit is cut to it, so the route still runs alone
    let c = Concurrency::new(fixed(5, 0.0), Instant::now()).unwrap();
    let huge = Priority {
        class: Class::Normal,
        weight: 100,
    };
    assert_eq!(c.admit(huge), Some(5));
}

#[test]
fn reconfigure_keeps_the_mode() {
    let at = Instant::now();
    let c = Concurrency::new(gradient(500, 20, 1000), at).unwrap();
    c.reconfigure(gradient(0, 20, 100)).unwrap();
    assert_eq!(c.limit(), 100);
    assert!(c.reconfigure(fixed(10, 0.2)).is_err());
    let f = Concurrency::new(fixed(10, 0.2), at).unwrap();
    f.reconfigure(fixed(30, 0.1)).unwrap();
    assert_eq!(f.limit(), 30);
}

#[test]
fn bad_configs_are_refused() {
    let at = Instant::now();
    assert!(Concurrency::new(fixed(0, 0.2), at).is_err());
    assert!(Concurrency::new(fixed(10, 0.6), at).is_err());
    assert!(Concurrency::new(gradient(0, 0, 10), at).is_err());
    assert!(Concurrency::new(gradient(0, 20, 10), at).is_err());
    let short = ConcurrencyConfig {
        window: 50 * MS,
        ..gradient(0, 20, 100)
    };
    assert!(Concurrency::new(short, at).is_err());
}

#[test]
fn concurrent_admit_and_release_balance() {
    let c = std::sync::Arc::new(Concurrency::new(fixed(64, 0.0), Instant::now()).unwrap());
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let c = c.clone();
            std::thread::spawn(move || {
                for _ in 0..10_000 {
                    if let Some(w) = c.admit(p(Class::Normal)) {
                        assert!(c.in_flight() <= 64);
                        c.release(w, Outcome::Dropped, Instant::now());
                    }
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(c.in_flight(), 0);
}
