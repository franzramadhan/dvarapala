use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::ptr;

use dvarapala::{
    DV_OK, DvConn, DvGuard, DvStats, DvVerdict, dv_check, dv_config_free, dv_config_new,
    dv_config_set, dv_conn_close, dv_conn_open, dv_guard_free, dv_guard_new, dv_last_error,
    dv_stats,
};
use napi::{Error, Result};
use napi_derive::napi;

#[napi(object)]
pub struct Verdict {
    /// 0 allow, 1 throttle, 2 drop
    pub kind: i32,
    pub retry_after_ms: f64,
}

#[napi(object)]
pub struct Stats {
    pub allowed: f64,
    pub throttled: f64,
    pub dropped: f64,
    pub clients: f64,
    pub evictions: f64,
    pub detection_state: u32,
    pub rate_zscore: f64,
    pub source_entropy: f64,
}

#[napi]
pub struct Guard(*mut DvGuard);

// SAFETY: the guard is thread-safe behind the C ABI
unsafe impl Send for Guard {}

#[napi]
impl Guard {
    /// Settings by their CONFIG.md names; throws naming a bad key.
    #[napi(constructor)]
    pub fn new(config: Option<HashMap<String, String>>) -> Result<Self> {
        let cfg = dv_config_new();
        let set = || -> Result<*mut DvGuard> {
            for (k, v) in config.unwrap_or_default() {
                let (k, v) = (cstr(k)?, cstr(v)?);
                // SAFETY: a live config and NUL-terminated strings
                if unsafe { dv_config_set(cfg, k.as_ptr(), v.as_ptr()) } != DV_OK {
                    return Err(last());
                }
            }
            // SAFETY: a live config
            let g = unsafe { dv_guard_new(cfg) };
            if g.is_null() { Err(last()) } else { Ok(g) }
        };
        let g = set();
        // SAFETY: from dv_config_new, freed once
        unsafe { dv_config_free(cfg) };
        g.map(Self)
    }

    #[napi]
    pub fn check(&self, ip: String, xff: Option<String>) -> Result<Verdict> {
        let ip = cstr(ip)?;
        let xff = xff.map(cstr).transpose()?;
        let mut v = DvVerdict {
            kind: 0,
            retry_after_ms: 0,
        };
        let x = xff.as_ref().map_or(ptr::null(), |x| x.as_ptr());
        // SAFETY: a live guard, NUL-terminated strings, a valid out pointer
        if unsafe { dv_check(self.0, ip.as_ptr(), x, &mut v) } != DV_OK {
            return Err(last());
        }
        Ok(Verdict {
            kind: v.kind,
            retry_after_ms: v.retry_after_ms as f64,
        })
    }

    #[napi]
    pub fn stats(&self) -> Stats {
        let mut s = DvStats {
            allowed: 0,
            throttled: 0,
            dropped: 0,
            clients: 0,
            evictions: 0,
            detection_state: 0,
            rate_zscore: 0.0,
            source_entropy: 0.0,
        };
        // SAFETY: a live guard and a valid out pointer
        unsafe { dv_stats(self.0, &mut s) };
        Stats {
            allowed: s.allowed as f64,
            throttled: s.throttled as f64,
            dropped: s.dropped as f64,
            clients: s.clients as f64,
            evictions: s.evictions as f64,
            detection_state: s.detection_state.into(),
            rate_zscore: s.rate_zscore,
            source_entropy: s.source_entropy,
        }
    }

    /// Counts a connection from `ip`; throws with the reason (`total`,
    /// `per_client`, `rate`) over a limit.
    #[napi]
    pub fn conn_open(&self, ip: String) -> Result<Conn> {
        let ip = cstr(ip)?;
        let mut c = ptr::null_mut();
        // SAFETY: a live guard, a NUL-terminated string, a valid out pointer
        if unsafe { dv_conn_open(self.0, ip.as_ptr(), &mut c) } != DV_OK {
            return Err(last());
        }
        Ok(Conn(c))
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        // SAFETY: from dv_guard_new, freed once; open conns keep the state
        unsafe { dv_guard_free(self.0) };
    }
}

/// One open connection's place.
#[napi]
pub struct Conn(*mut DvConn);

// SAFETY: a place is freed from any thread
unsafe impl Send for Conn {}

#[napi]
impl Conn {
    /// Frees the place; later calls are no-ops.
    #[napi]
    pub fn close(&mut self) {
        // SAFETY: from dv_conn_open; nulled so it is closed once
        unsafe { dv_conn_close(std::mem::replace(&mut self.0, ptr::null_mut())) };
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        self.close();
    }
}

fn cstr(s: String) -> Result<CString> {
    CString::new(s).map_err(|_| Error::from_reason("a NUL byte in a string"))
}

fn last() -> Error {
    let m = dv_last_error();
    if m.is_null() {
        return Error::from_reason("unknown error");
    }
    // SAFETY: NUL-terminated, valid until the next call on this thread
    Error::from_reason(unsafe { CStr::from_ptr(m) }.to_string_lossy())
}
