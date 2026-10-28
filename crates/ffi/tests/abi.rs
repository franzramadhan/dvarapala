//! RFC 0008 cases 2 to 7, 15 and 16, through the exported functions as a
//! C caller sees them.

use std::ffi::{CStr, CString, c_char};
use std::ptr;
use std::thread;
use std::time::{Duration, Instant};

use dvarapala::*;

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn last_error() -> String {
    let p = dv_last_error();
    assert!(!p.is_null(), "no error message");
    // SAFETY: a NUL-terminated message owned by this thread
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

/// A guard from `pairs`, or the error message.
fn guard(pairs: &[(&str, &str)]) -> Result<Guard, String> {
    let cfg = dv_config_new();
    for (k, v) in pairs {
        // SAFETY: a live config and NUL-terminated strings
        assert_eq!(
            unsafe { dv_config_set(cfg, c(k).as_ptr(), c(v).as_ptr()) },
            DV_OK
        );
    }
    // SAFETY: a live config, freed once below
    let g = unsafe { dv_guard_new(cfg) };
    unsafe { dv_config_free(cfg) };
    if g.is_null() {
        Err(last_error())
    } else {
        Ok(Guard(g))
    }
}

struct Guard(*mut DvGuard);

// SAFETY: DvGuard is thread-safe by contract (case 6)
unsafe impl Send for Guard {}
unsafe impl Sync for Guard {}

impl Drop for Guard {
    fn drop(&mut self) {
        // SAFETY: from dv_guard_new, freed once
        unsafe { dv_guard_free(self.0) }
    }
}

impl Guard {
    fn check(&self, ip: &str, xff: Option<&str>) -> DvVerdict {
        let xff = xff.map(c);
        let mut v = DvVerdict::default();
        let x = xff.as_ref().map_or(ptr::null(), |x| x.as_ptr());
        // SAFETY: a live guard, NUL-terminated strings, a valid out pointer
        assert_eq!(
            unsafe { dv_check(self.0, c(ip).as_ptr(), x, &mut v) },
            DV_OK
        );
        v
    }

    fn open(&self, ip: &str) -> Result<*mut DvConn, String> {
        let mut h = ptr::null_mut();
        // SAFETY: a live guard, a NUL-terminated string, a valid out pointer
        match unsafe { dv_conn_open(self.0, c(ip).as_ptr(), &mut h) } {
            DV_OK => Ok(h),
            DV_E_LIMIT => Err(last_error()),
            code => panic!("dv_conn_open: {code}"),
        }
    }
}

fn close(h: *mut DvConn) {
    // SAFETY: from dv_conn_open, closed once
    unsafe { dv_conn_close(h) }
}

/// RFC 0008 case 2
#[test]
fn throttles_over_the_burst() {
    let g = guard(&[("rate_limit.rate", "1"), ("rate_limit.burst", "2")]).unwrap();
    let v: Vec<_> = (0..3).map(|_| g.check("192.0.2.10", None)).collect();
    assert_eq!(v[0].kind, DV_ALLOW);
    assert_eq!(v[1].kind, DV_ALLOW);
    assert_eq!(v[2].kind, DV_THROTTLE);
    assert!((1..=1000).contains(&v[2].retry_after_ms), "{:?}", v[2]);
}

/// RFC 0008 case 3
#[test]
fn bad_config_names_the_key() {
    for (k, v) in [
        ("rate_limit.nope", "1"),
        ("rate_limit.rate", "fast"),
        ("listen", "127.0.0.1:8080"),
        ("tls.cert", "c.pem"),
        ("l4.idle_timeout", "60s"),
        ("detection.mode", "loud"),
        ("trusted_proxies", "192.0.2.0/33"),
    ] {
        let e = guard(&[(k, v)])
            .err()
            .unwrap_or_else(|| panic!("{k} accepted"));
        assert!(e.contains(k), "{k}: {e}");
    }
}

/// RFC 0008 case 4
#[test]
fn trusted_proxies_pick_the_client() {
    let g = guard(&[
        ("rate_limit.rate", "1"),
        ("rate_limit.burst", "1"),
        ("trusted_proxies", "192.0.2.0/24"),
    ])
    .unwrap();
    let xff = Some("198.51.100.7");
    // through a trusted proxy: keyed by 198.51.100.7
    assert_eq!(g.check("192.0.2.1", xff).kind, DV_ALLOW);
    assert_eq!(g.check("192.0.2.2", xff).kind, DV_THROTTLE);
    // an untrusted peer is keyed by itself, the header ignored
    assert_eq!(g.check("203.0.113.1", xff).kind, DV_ALLOW);
    assert_eq!(g.check("203.0.113.1", xff).kind, DV_THROTTLE);
}

/// RFC 0008 case 5
#[test]
fn bad_input_is_an_error_not_a_crash() {
    let g = guard(&[]).unwrap();
    let mut v = DvVerdict::default();
    let ip = c("192.0.2.1");
    let bad_utf8: &[u8] = b"\xff\xfe\0";
    // SAFETY: each pointer is null or valid for what it claims
    unsafe {
        assert_eq!(
            dv_check(ptr::null(), ip.as_ptr(), ptr::null(), &mut v),
            DV_E_NULL
        );
        assert_eq!(dv_check(g.0, ptr::null(), ptr::null(), &mut v), DV_E_NULL);
        assert_eq!(
            dv_check(g.0, ip.as_ptr(), ptr::null(), ptr::null_mut()),
            DV_E_NULL
        );
        let p = bad_utf8.as_ptr().cast::<c_char>();
        assert_eq!(dv_check(g.0, p, ptr::null(), &mut v), DV_E_UTF8);
        assert_eq!(
            dv_check(g.0, c("not an ip").as_ptr(), ptr::null(), &mut v),
            DV_E_INVALID
        );
        assert_eq!(
            dv_config_set(ptr::null_mut(), ip.as_ptr(), ip.as_ptr()),
            DV_E_NULL
        );
        assert!(dv_guard_new(ptr::null()).is_null());
        // null frees are no-ops
        dv_guard_free(ptr::null_mut());
        dv_config_free(ptr::null_mut());
        dv_conn_close(ptr::null_mut());
    }
}

/// RFC 0008 case 6
#[test]
fn bound_holds_across_threads() {
    let (rate, burst) = (50u64, 10u64);
    let g = guard(&[
        ("rate_limit.rate", &rate.to_string()),
        ("rate_limit.burst", &burst.to_string()),
    ])
    .unwrap();
    let start = Instant::now();
    let allowed: u64 = thread::scope(|s| {
        let hs: Vec<_> = (0..8)
            .map(|_| {
                s.spawn(|| {
                    let mut n = 0;
                    for _ in 0..1250 {
                        if g.check("192.0.2.10", None).kind == DV_ALLOW {
                            n += 1;
                        }
                        thread::sleep(Duration::from_micros(1500));
                    }
                    n
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).sum()
    });
    let secs = start.elapsed().as_secs_f64();
    let bound = burst as f64 + rate as f64 * secs;
    assert!(
        (allowed as f64) <= bound + 1.0,
        "{allowed} allowed in {secs:.2}s, bound {bound:.0}"
    );
    let mut st = DvStats::default();
    // SAFETY: a live guard and a valid out pointer
    assert_eq!(unsafe { dv_stats(g.0, &mut st) }, DV_OK);
    assert_eq!((st.allowed, st.allowed + st.throttled), (allowed, 10_000));
    assert_eq!(st.clients, 1);
}

/// RFC 0008 case 7: one normal window, a flood from one address, then
/// the next request closes the window in `Attack`
#[test]
fn heavy_hitter_is_dropped_in_enforce() {
    let g = guard(&[
        ("rate_limit.rate", "4"),
        ("rate_limit.burst", "1"),
        ("detection.mode", "enforce"),
        ("detection.window", "200ms"),
        ("detection.warmup_windows", "1"),
        ("detection.trigger_windows", "1"),
    ])
    .unwrap();
    for i in 0..10 {
        g.check(&format!("198.51.100.{i}"), None);
    }
    thread::sleep(Duration::from_millis(220));
    for _ in 0..1000 {
        g.check("192.0.2.10", None);
    }
    thread::sleep(Duration::from_millis(220));
    assert_eq!(g.check("192.0.2.10", None).kind, DV_DROP);
    let mut st = DvStats::default();
    // SAFETY: a live guard and a valid out pointer
    assert_eq!(unsafe { dv_stats(g.0, &mut st) }, DV_OK);
    assert_eq!(st.detection_state, 2);
    assert!(st.dropped >= 1);
}

/// RFC 0008 case 15
#[test]
fn per_client_connection_cap() {
    let g = guard(&[("l4.max_per_client", "2")]).unwrap();
    let a = g.open("192.0.2.1").unwrap();
    let b = g.open("192.0.2.1").unwrap();
    assert_eq!(g.open("192.0.2.1").unwrap_err(), "per_client");
    close(a);
    let d = g.open("192.0.2.1").unwrap();
    close(b);
    close(d);
}

/// RFC 0008 case 16
#[test]
fn connection_rate() {
    let g = guard(&[("l4.accept_rate", "10"), ("l4.accept_burst", "2")]).unwrap();
    let (a, b) = (g.open("192.0.2.1").unwrap(), g.open("192.0.2.1").unwrap());
    assert_eq!(g.open("192.0.2.1").unwrap_err(), "rate");
    close(a);
    close(b);
}

#[test]
fn total_cap_and_l4_off() {
    let g = guard(&[("l4.max_connections", "1"), ("l4.max_per_client", "0")]).unwrap();
    let a = g.open("192.0.2.1").unwrap();
    assert_eq!(g.open("192.0.2.2").unwrap_err(), "total");
    // the guard can go first: the connection keeps its state alive
    drop(g);
    close(a);
    let off = guard(&[("l4.enabled", "false"), ("l4.max_per_client", "1")]).unwrap();
    let hs: Vec<_> = (0..5).map(|_| off.open("192.0.2.1").unwrap()).collect();
    hs.into_iter().for_each(close);
}
