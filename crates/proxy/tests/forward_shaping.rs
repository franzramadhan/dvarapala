//! RFC 0007: the rate, concurrency and `CONNECT` limits on the wire.

mod egress;

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use dvarapala_engine::ScheduleConfig;
use dvarapala_proxy::Destination;
use egress::{Behave, config, connect, dest, get, get_over, proxy, upstream};
use http::StatusCode;

/// RFC 0007 case 11
#[tokio::test(flavor = "multi_thread")]
async fn upstream_never_sees_more_than_the_rate() {
    let (up, seen) = upstream(Behave::default()).await;
    let (rate, burst) = (20.0, 5);
    let (p, _stop) = proxy(config(vec![dest(
        "c11",
        &format!("http://{up}"),
        rate,
        burst,
    )]))
    .await;
    let url = format!("http://{up}/");
    let tasks: Vec<_> = (0..100)
        .map(|_| {
            let url = url.clone();
            tokio::spawn(async move { get(p, &url).await })
        })
        .collect();
    let mut sent = 0;
    for t in tasks {
        let (status, headers, _) = t.await.unwrap();
        match status {
            StatusCode::OK => sent += 1,
            StatusCode::TOO_MANY_REQUESTS => {
                let secs: u64 = headers["retry-after"].to_str().unwrap().parse().unwrap();
                assert!(secs >= 1);
            }
            other => panic!("unexpected {other}"),
        }
    }
    let mut t = seen.times.lock().unwrap().clone();
    assert_eq!(t.len(), sent);
    // default max_wait 2 s: about burst + rate * 2 go, the rest are refused
    assert!(sent > 30 && sent < 100, "{sent} sent");
    t.sort();
    for (i, &a) in t.iter().enumerate() {
        for (j, &b) in t[i..].iter().enumerate() {
            // 2 sends of slack for scheduling jitter on the test host
            let allowed = f64::from(burst) + rate * (b - a).as_secs_f64() + 2.0;
            assert!((j + 1) as f64 <= allowed, "{} sends in {:?}", j + 1, b - a);
        }
    }
}

/// RFC 0007 case 12
#[tokio::test(flavor = "multi_thread")]
async fn max_concurrent_makes_the_third_wait() {
    let (up, seen) = upstream(Behave {
        delay: Duration::from_millis(300),
        ..Behave::default()
    })
    .await;
    let (p, _stop) = proxy(config(vec![Destination {
        max_concurrent: 2,
        ..dest("c12", &format!("http://{up}"), 1000.0, 10)
    }]))
    .await;
    let url = format!("http://{up}/");
    let start = Instant::now();
    let tasks: Vec<_> = (0..3)
        .map(|_| {
            let url = url.clone();
            tokio::spawn(async move { get(p, &url).await.0 })
        })
        .collect();
    for t in tasks {
        assert_eq!(t.await.unwrap(), StatusCode::OK);
    }
    assert!(
        start.elapsed() >= Duration::from_millis(600),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(seen.max_in_flight.load(Ordering::SeqCst), 2);
}

/// RFC 0007 case 14
#[tokio::test(flavor = "multi_thread")]
async fn connect_takes_a_slot_per_tunnel() {
    let (up, seen) = upstream(Behave::default()).await;
    let (p, _stop) = proxy(config(vec![Destination {
        schedule: ScheduleConfig {
            rate: 1.0,
            burst: 1,
            max_wait: Duration::from_millis(500),
            ..ScheduleConfig::default()
        },
        ..dest("c14", &format!("http://{up}"), 1.0, 1)
    }]))
    .await;
    let target = up.to_string();
    let (first, second) = tokio::join!(connect(p, &target), connect(p, &target));
    let (open, refused) = match (first, second) {
        (Ok(t), Err(s)) | (Err(s), Ok(t)) => (t, s),
        _ => panic!("want one tunnel and one refusal"),
    };
    assert_eq!(refused, StatusCode::TOO_MANY_REQUESTS);
    assert!(get_over(open).await.starts_with("GET /\n"));
    assert_eq!(seen.hits(), 1);
}
