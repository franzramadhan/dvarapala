//! RFC 0028 cases 7 to 14 and 21: blocks, egress and reload.

mod common;

use std::ptr;
use std::thread;
use std::time::Duration;

use common::{c, guard, req};
use dvarapala::*;

/// RFC 0028 case 7
#[test]
fn a_block_drops_requests_and_connections() {
    let g = guard(&[]).unwrap();
    assert_eq!(g.block("192.0.2.0/24", 60_000), DV_OK);
    assert_eq!(g.check("192.0.2.9").kind, DV_DROP);
    assert_eq!(g.request(req("192.0.2.9", "GET", "/")).unwrap().0, DV_DROP);
    let mut conn = ptr::null_mut();
    // SAFETY: a live guard, a NUL-terminated string, a valid out pointer
    let rc = unsafe { dv_conn_open(g.0, c("192.0.2.9").as_ptr(), &mut conn) };
    assert_eq!(rc, DV_E_LIMIT);
    assert_eq!(common::last_error(), "blocked");
    assert_eq!(g.check("198.51.100.1").kind, DV_ALLOW);
    let list = g.blocks();
    assert!(
        list.starts_with(r#"[{"cidr":"192.0.2.0/24","ttl_ms":"#),
        "{list}"
    );
}

/// RFC 0028 case 8
#[test]
fn a_block_expires() {
    let g = guard(&[]).unwrap();
    assert_eq!(g.block("192.0.2.9", 1), DV_OK);
    thread::sleep(Duration::from_millis(5));
    assert_eq!(g.check("192.0.2.9").kind, DV_ALLOW);
    assert_eq!(g.blocks(), "[]");
}

/// RFC 0028 case 9
#[test]
fn block_list_limits() {
    let g = guard(&[("admin.max_blocks", "2"), ("admin.max_block_ttl", "1m")]).unwrap();
    assert_eq!(g.block("192.0.2.1", 0), DV_OK);
    assert_eq!(g.block("192.0.2.2", 0), DV_OK);
    assert_eq!(g.block("192.0.2.3", 0), DV_E_LIMIT);
    assert_eq!(g.block("192.0.2.1", 120_000), DV_E_INVALID);
    assert_eq!(g.unblock("198.51.100.0/24"), DV_E_NOT_FOUND);
    assert_eq!(g.unblock("192.0.2.1"), DV_OK);
    assert_eq!(g.block("not an address", 0), DV_E_INVALID);
}

fn stripe(rate: &str, burst: u32, max_queue: u32) -> String {
    format!(
        r#"[{{"origin": "https://api.example.com", "name": "stripe", "rate": {rate}, "burst": {burst}, "max_queue": {max_queue}, "max_wait": "1s", "max_pause": "5s"}}]"#
    )
}

/// RFC 0028 case 10
#[test]
fn egress_now_wait_refuse() {
    let g = guard(&[("forward.destinations", &stripe("10", 1, 1))]).unwrap();
    let s: Vec<_> = (0..3).map(|_| g.egress("stripe")).collect();
    assert_eq!(
        s[0],
        DvSlot {
            kind: DV_SLOT_NOW,
            ms: 0
        }
    );
    assert_eq!(s[1].kind, DV_SLOT_WAIT);
    assert!((90..=100).contains(&s[1].ms), "{:?}", s[1]);
    assert_eq!(s[2].kind, DV_SLOT_REFUSE);
    let mut out = DvSlot::default();
    // SAFETY: a live guard, a NUL-terminated string, a valid out pointer
    let rc = unsafe { dv_egress(g.0, c("nope").as_ptr(), &mut out) };
    assert_eq!(rc, DV_E_NOT_FOUND);
}

/// RFC 0028 case 11
#[test]
fn egress_pause() {
    let g = guard(&[("forward.destinations", &stripe("10", 1, 1))]).unwrap();
    // SAFETY: a live guard and a NUL-terminated string
    assert_eq!(
        unsafe { dv_egress_pause(g.0, c("stripe").as_ptr(), 2000) },
        DV_OK
    );
    let s = g.egress("stripe");
    assert_eq!(s.kind, DV_SLOT_REFUSE);
    assert!((1900..=2000).contains(&s.ms), "{s:?}");
    // never above max_pause
    assert_eq!(
        unsafe { dv_egress_pause(g.0, c("stripe").as_ptr(), 60_000) },
        DV_OK
    );
    assert!(g.egress("stripe").ms <= 5000);
}

/// RFC 0028 case 12
#[test]
fn max_concurrent_is_refused() {
    let d = r#"[{"origin": "https://api.example.com", "rate": 1, "max_concurrent": 4}]"#;
    let e = guard(&[("forward.destinations", d)]).err().unwrap();
    assert!(
        e.contains("max_concurrent") && e.contains("semaphore"),
        "{e}"
    );
    let e = guard(&[("forward.clients", "127.0.0.0/8")]).err().unwrap();
    assert!(e.contains("does not apply in-process"), "{e}");
}

/// RFC 0028 case 13
#[test]
fn reload_keeps_counts_blocks_and_queues() {
    let dest = stripe("1", 1, 1);
    let start = [
        ("rate_limit.rate", "1"),
        ("rate_limit.burst", "1"),
        ("forward.destinations", &dest),
    ];
    let g = guard(&start).unwrap();
    assert_eq!(g.check("192.0.2.1").kind, DV_ALLOW);
    assert_eq!(g.check("192.0.2.1").kind, DV_THROTTLE);
    assert_eq!(g.block("198.51.100.0/24", 0), DV_OK);
    assert_eq!(g.egress("stripe").kind, DV_SLOT_NOW);
    assert_eq!(g.egress("stripe").kind, DV_SLOT_WAIT);
    let fast = [
        ("rate_limit.rate", "100"),
        ("rate_limit.burst", "1"),
        ("forward.destinations", &dest),
    ];
    g.reload(&fast).unwrap();
    // still out of tokens right after, then refilled at 100/s
    assert_eq!(g.check("192.0.2.1").kind, DV_THROTTLE);
    thread::sleep(Duration::from_millis(20));
    assert_eq!(g.check("192.0.2.1").kind, DV_ALLOW);
    assert_eq!(g.check("198.51.100.1").kind, DV_DROP);
    // the waiting slot still holds the one queue place
    assert_eq!(g.egress("stripe").kind, DV_SLOT_REFUSE);
}

/// RFC 0028 case 14
#[test]
fn reload_refuses_start_only_keys() {
    let g = guard(&[("rate_limit.rate", "1"), ("rate_limit.burst", "1")]).unwrap();
    assert_eq!(g.check("192.0.2.1").kind, DV_ALLOW);
    for (k, v) in [
        ("rate_limit.max_clients", "10"),
        ("l4.max_clients", "10"),
        ("l4.max_connections", "10"),
    ] {
        let e = g.reload(&[("rate_limit.rate", "100"), (k, v)]).unwrap_err();
        assert!(e.contains(k), "{k}: {e}");
    }
    // the guard kept rate 1: no token yet
    assert_eq!(g.check("192.0.2.1").kind, DV_THROTTLE);
    let e = g.reload(&[("rate_limit.rate", "fast")]).unwrap_err();
    assert!(e.contains("rate_limit.rate"), "{e}");
}

/// RFC 0028 case 21
#[test]
fn an_abandoned_wait_holds_its_place() {
    let g = guard(&[("forward.destinations", &stripe("1", 1, 1))]).unwrap();
    assert_eq!(g.egress("stripe").kind, DV_SLOT_NOW);
    let wait = g.egress("stripe");
    assert_eq!(wait.kind, DV_SLOT_WAIT);
    // the caller gives up; its slot still holds the queue
    assert_eq!(g.egress("stripe").kind, DV_SLOT_REFUSE);
    thread::sleep(Duration::from_millis(wait.ms + 10));
    // the place is free again: the next slot is the rate's, not a refusal
    assert_eq!(g.egress("stripe").kind, DV_SLOT_WAIT);
}
