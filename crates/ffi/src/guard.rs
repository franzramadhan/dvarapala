use std::ffi::c_char;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use dvarapala_engine::{Conns, Guard, TrustedProxies};

use crate::config::Settings;

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
    pub(crate) open: std::sync::atomic::AtomicUsize,
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
    todo!("rfc 0008")
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
    let _ = (cfg, key, value);
    todo!("rfc 0008")
}

/// # Safety
///
/// `cfg` is null or comes from [`dv_config_new`], freed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dv_config_free(cfg: *mut DvConfig) {
    let _ = cfg;
    todo!("rfc 0008")
}

/// A guard from `cfg`, or null with `dv_last_error` naming the bad key.
///
/// # Safety
///
/// `cfg` is null or comes from [`dv_config_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dv_guard_new(cfg: *const DvConfig) -> *mut DvGuard {
    let _ = cfg;
    todo!("rfc 0008")
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
    let _ = (g, ip, xff, out);
    todo!("rfc 0008")
}

/// # Safety
///
/// `g` comes from [`dv_guard_new`]; `out` is null or points to a `DvStats`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dv_stats(g: *const DvGuard, out: *mut DvStats) -> i32 {
    let _ = (g, out);
    todo!("rfc 0008")
}

/// Open connections keep the guard's state alive until they close.
///
/// # Safety
///
/// `g` is null or comes from [`dv_guard_new`], freed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dv_guard_free(g: *mut DvGuard) {
    let _ = g;
    todo!("rfc 0008")
}
