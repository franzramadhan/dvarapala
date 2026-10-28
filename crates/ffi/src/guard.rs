use std::ffi::c_char;
use std::net::IpAddr;
use std::ptr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use dvarapala_engine::{Conns, Guard, TrustedProxies, Verdict, client_key};

use crate::config::Settings;
use crate::error::{DV_E_INVALID, Error, catch, code, null, text};

pub const DV_ALLOW: i32 = 0;
pub const DV_THROTTLE: i32 = 1;
pub const DV_DROP: i32 = 2;

/// Key/value settings for [`dv_guard_new`].
pub struct DvConfig(pub(crate) Settings);

/// A thread-safe guard: the client table, the detector, the trusted
/// proxies and the connection counts.
pub struct DvGuard(pub(crate) Arc<Shared>);

pub(crate) struct Shared {
    pub(crate) guard: Mutex<Guard>,
    pub(crate) trusted: TrustedProxies,
    pub(crate) conns: Option<Mutex<Conns>>,
    pub(crate) max_connections: usize,
    pub(crate) open: AtomicUsize,
    pub(crate) counts: [AtomicU64; 3],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DvVerdict {
    /// `DV_ALLOW`, `DV_THROTTLE` or `DV_DROP`.
    pub kind: i32,
    /// With `DV_THROTTLE`: when to retry, in milliseconds.
    pub retry_after_ms: u64,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct DvStats {
    pub allowed: u64,
    pub throttled: u64,
    pub dropped: u64,
    pub clients: u64,
    pub evictions: u64,
    /// 0 `Normal`, 1 `Suspect`, 2 `Attack`, 3 `Cooldown`; 0 without detection.
    pub detection_state: u8,
    pub rate_zscore: f64,
    pub source_entropy: f64,
}

/// An empty config; free it with [`dv_config_free`].
#[unsafe(no_mangle)]
pub extern "C" fn dv_config_new() -> *mut DvConfig {
    Box::into_raw(Box::new(DvConfig(Settings::default())))
}

/// Sets `key` (a `CONFIG.md` name such as `rate_limit.rate`) to `value`.
/// Keys and values are checked by [`dv_guard_new`].
///
/// # Safety
///
/// `cfg` comes from [`dv_config_new`]; `key` and `value` are null or
/// NUL-terminated strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dv_config_set(
    cfg: *mut DvConfig,
    key: *const c_char,
    value: *const c_char,
) -> i32 {
    code(|| {
        // SAFETY: null or from dv_config_new, by contract
        let cfg = unsafe { cfg.as_mut() }.ok_or_else(|| null("config"))?;
        // SAFETY: null or NUL-terminated, by contract
        let (k, v) = unsafe { (text(key, "key")?, text(value, "value")?) };
        cfg.0.0.push((k.to_owned(), v.to_owned()));
        Ok(())
    })
}

/// # Safety
///
/// `cfg` is null or comes from [`dv_config_new`], freed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dv_config_free(cfg: *mut DvConfig) {
    if !cfg.is_null() {
        // SAFETY: from dv_config_new and freed once, by contract
        drop(unsafe { Box::from_raw(cfg) });
    }
}

/// A guard from `cfg`, or null with `dv_last_error` naming the bad key.
///
/// # Safety
///
/// `cfg` is null or comes from [`dv_config_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dv_guard_new(cfg: *const DvConfig) -> *mut DvGuard {
    let built = catch(|| {
        // SAFETY: null or from dv_config_new, by contract
        let cfg = unsafe { cfg.as_ref() }.ok_or_else(|| null("config"))?;
        let invalid = |e: String| (DV_E_INVALID, e);
        let b = cfg.0.build().map_err(invalid)?;
        let guard = Guard::new(b.guard).map_err(|e| invalid(format!("detection: {}", e.0)))?;
        let conns = b
            .conns
            .map(|c| Conns::new(c).map_err(|e| invalid(format!("l4: {}", e.0))))
            .transpose()?;
        Ok(Shared {
            guard: Mutex::new(guard),
            trusted: b.trusted,
            conns: conns.map(Mutex::new),
            max_connections: b.max_connections,
            open: AtomicUsize::new(0),
            counts: Default::default(),
        })
    });
    match built {
        Ok(s) => Box::into_raw(Box::new(DvGuard(Arc::new(s)))),
        Err(_) => ptr::null_mut(),
    }
}

/// The verdict for one request from `ip`, with the raw `X-Forwarded-For`
/// value or null.
///
/// # Safety
///
/// `g` comes from [`dv_guard_new`]; `ip` and `xff` are null or
/// NUL-terminated; `out` is null or points to a `DvVerdict`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dv_check(
    g: *const DvGuard,
    ip: *const c_char,
    xff: *const c_char,
    out: *mut DvVerdict,
) -> i32 {
    code(|| {
        // SAFETY: null or from dv_guard_new, by contract
        let g = unsafe { g.as_ref() }.ok_or_else(|| null("guard"))?;
        // SAFETY: null or NUL-terminated, by contract
        let ip = unsafe { text(ip, "ip")? };
        let xff = match xff.is_null() {
            true => None,
            // SAFETY: NUL-terminated, by contract
            false => Some(unsafe { text(xff, "xff")? }),
        };
        // SAFETY: null or a valid DvVerdict, by contract
        let out = unsafe { out.as_mut() }.ok_or_else(|| null("out"))?;
        let key = client_key(peer(ip)?, xff, &g.0.trusted);
        let d = lock(&g.0.guard).check(key, Instant::now());
        *out = match d.verdict {
            Verdict::Allow => DvVerdict {
                kind: DV_ALLOW,
                retry_after_ms: 0,
            },
            Verdict::Throttle { retry_after } => DvVerdict {
                kind: DV_THROTTLE,
                retry_after_ms: millis(retry_after),
            },
            // not produced without the scorer; the closest answer is a retry
            Verdict::Challenge => DvVerdict {
                kind: DV_THROTTLE,
                retry_after_ms: 1000,
            },
            Verdict::Drop => DvVerdict {
                kind: DV_DROP,
                retry_after_ms: 0,
            },
        };
        g.0.counts[out.kind as usize].fetch_add(1, Ordering::Relaxed);
        Ok(())
    })
}

/// # Safety
///
/// `g` comes from [`dv_guard_new`]; `out` is null or points to a `DvStats`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dv_stats(g: *const DvGuard, out: *mut DvStats) -> i32 {
    code(|| {
        // SAFETY: null or from dv_guard_new, by contract
        let g = unsafe { g.as_ref() }.ok_or_else(|| null("guard"))?;
        // SAFETY: null or a valid DvStats, by contract
        let out = unsafe { out.as_mut() }.ok_or_else(|| null("out"))?;
        let count = |i: usize| g.0.counts[i].load(Ordering::Relaxed);
        let guard = lock(&g.0.guard);
        let det = guard.detector();
        *out = DvStats {
            allowed: count(0),
            throttled: count(1),
            dropped: count(2),
            clients: guard.clients() as u64,
            evictions: guard.evictions(),
            detection_state: det.map_or(0, |d| d.state().code()),
            rate_zscore: det.map_or(0.0, |d| d.zscore()),
            source_entropy: det.map_or(0.0, |d| d.entropy()),
        };
        Ok(())
    })
}

/// Open connections keep the guard's state alive until they close.
///
/// # Safety
///
/// `g` is null or comes from [`dv_guard_new`], freed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dv_guard_free(g: *mut DvGuard) {
    if !g.is_null() {
        // SAFETY: from dv_guard_new and freed once, by contract
        drop(unsafe { Box::from_raw(g) });
    }
}

pub(crate) fn peer(ip: &str) -> Result<IpAddr, Error> {
    ip.parse()
        .map_err(|_| (DV_E_INVALID, format!("ip: {ip:?} is not an IP address")))
}

/// Whole milliseconds, rounded up, at least 1.
fn millis(d: Duration) -> u64 {
    (d.as_nanos().div_ceil(1_000_000) as u64).max(1)
}

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // every update is a few field writes: a panic leaves usable state
    m.lock().unwrap_or_else(|e| e.into_inner())
}
