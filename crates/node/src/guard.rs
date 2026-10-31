use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::ptr;

use dvarapala::{
    DV_OK, DvConfig, DvConn, DvGuard, DvRequest, DvRequestVerdict, DvSlot, DvStats, DvVerdict,
    dv_block, dv_blocks, dv_check, dv_check_request, dv_config_free, dv_config_new, dv_config_set,
    dv_conn_close, dv_conn_open, dv_egress, dv_egress_pause, dv_guard_free, dv_guard_new,
    dv_guard_reload, dv_last_error, dv_route_headers, dv_stats, dv_string_free, dv_unblock,
};
use napi::{Error, Result};
use napi_derive::napi;

#[napi(object)]
pub struct Verdict {
    /// 0 allow, 1 throttle, 2 drop
    pub kind: i32,
    pub retry_after_ms: f64,
}

/// RFC 0028: a request's verdict with the routes applied.
#[napi(object)]
pub struct RequestVerdict {
    pub kind: i32,
    pub retry_after_ms: f64,
    /// The matched route's name.
    pub route: Option<String>,
}

/// RFC 0028: 0 now, 1 wait `ms`, 2 refused, retry after `ms`.
#[napi(object)]
pub struct Slot {
    pub kind: i32,
    pub ms: f64,
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
        with_config(config, |cfg| {
            // SAFETY: a live config
            let g = unsafe { dv_guard_new(cfg) };
            if g.is_null() {
                Err(last())
            } else {
                Ok(Self(g))
            }
        })
    }

    /// RFC 0028: applies `config` in place; throws naming a key that only
    /// applies at creation, and the guard stays as it was.
    #[napi]
    pub fn reload(&self, config: Option<HashMap<String, String>>) -> Result<()> {
        // SAFETY: a live guard and config
        with_config(config, |cfg| ok(unsafe { dv_guard_reload(self.0, cfg) }))
    }

    /// RFC 0028: `headers` holds `name: value` lines for `routeHeaders()`.
    /// Throws on bad input (a field over 8 KiB, a bad header line, no
    /// method or path).
    #[napi]
    pub fn check_request(
        &self,
        ip: String,
        xff: Option<String>,
        method: String,
        host: Option<String>,
        path: String,
        headers: Option<String>,
    ) -> Result<RequestVerdict> {
        let (ip, method, path) = (cstr(ip)?, cstr(method)?, cstr(path)?);
        let (xff, host, headers) = (opt(xff)?, opt(host)?, opt(headers)?);
        let p = |v: &Option<CString>| v.as_ref().map_or(ptr::null(), |v| v.as_ptr());
        let r = DvRequest {
            ip: ip.as_ptr(),
            xff: p(&xff),
            method: method.as_ptr(),
            host: p(&host),
            path: path.as_ptr(),
            headers: p(&headers),
        };
        let mut v = DvRequestVerdict {
            kind: 0,
            retry_after_ms: 0,
            route: ptr::null(),
        };
        // SAFETY: a live guard, a request of NUL-terminated strings, a valid out
        ok(unsafe { dv_check_request(self.0, &r, &mut v) })?;
        Ok(RequestVerdict {
            kind: v.kind,
            retry_after_ms: v.retry_after_ms as f64,
            route: (!v.route.is_null())
                // SAFETY: a name the guard keeps while it lives
                .then(|| {
                    unsafe { CStr::from_ptr(v.route) }
                        .to_string_lossy()
                        .into_owned()
                }),
        })
    }

    /// The header names route keys read, lower case and comma separated.
    #[napi]
    pub fn route_headers(&self) -> String {
        // SAFETY: a live guard; the string lives as long as it
        unsafe { CStr::from_ptr(dv_route_headers(self.0)) }
            .to_string_lossy()
            .into_owned()
    }

    /// Blocks `cidr` for `ttl_ms`, 0 for `admin.max_block_ttl`.
    #[napi]
    pub fn block(&self, cidr: String, ttl_ms: Option<f64>) -> Result<()> {
        let cidr = cstr(cidr)?;
        let ttl = ttl_ms.unwrap_or(0.0).max(0.0) as u64;
        // SAFETY: a live guard and a NUL-terminated string
        ok(unsafe { dv_block(self.0, cidr.as_ptr(), ttl) })
    }

    /// Throws when `cidr` is not blocked.
    #[napi]
    pub fn unblock(&self, cidr: String) -> Result<()> {
        let cidr = cstr(cidr)?;
        // SAFETY: a live guard and a NUL-terminated string
        ok(unsafe { dv_unblock(self.0, cidr.as_ptr()) })
    }

    /// The blocks in force, as JSON.
    #[napi]
    pub fn blocks(&self) -> Result<String> {
        // SAFETY: a live guard; the string is freed once below
        unsafe {
            let p = dv_blocks(self.0);
            if p.is_null() {
                return Err(last());
            }
            let s = CStr::from_ptr(p).to_string_lossy().into_owned();
            dv_string_free(p);
            Ok(s)
        }
    }

    #[napi]
    pub fn egress(&self, dest: String) -> Result<Slot> {
        let dest = cstr(dest)?;
        let mut s = DvSlot { kind: 0, ms: 0 };
        // SAFETY: a live guard, a NUL-terminated string, a valid out pointer
        ok(unsafe { dv_egress(self.0, dest.as_ptr(), &mut s) })?;
        Ok(Slot {
            kind: s.kind,
            ms: s.ms as f64,
        })
    }

    #[napi]
    pub fn egress_pause(&self, dest: String, retry_after_ms: f64) -> Result<()> {
        let dest = cstr(dest)?;
        let ms = retry_after_ms.max(0.0) as u64;
        // SAFETY: a live guard and a NUL-terminated string
        ok(unsafe { dv_egress_pause(self.0, dest.as_ptr(), ms) })
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

/// Runs `f` with a config holding `config`, freed after.
fn with_config<T>(
    config: Option<HashMap<String, String>>,
    f: impl FnOnce(*mut DvConfig) -> Result<T>,
) -> Result<T> {
    let cfg = dv_config_new();
    let set = || -> Result<T> {
        for (k, v) in config.unwrap_or_default() {
            let (k, v) = (cstr(k)?, cstr(v)?);
            // SAFETY: a live config and NUL-terminated strings
            ok(unsafe { dv_config_set(cfg, k.as_ptr(), v.as_ptr()) })?;
        }
        f(cfg)
    };
    let r = set();
    // SAFETY: from dv_config_new, freed once
    unsafe { dv_config_free(cfg) };
    r
}

fn ok(code: i32) -> Result<()> {
    if code == DV_OK { Ok(()) } else { Err(last()) }
}

fn opt(s: Option<String>) -> Result<Option<CString>> {
    s.map(cstr).transpose()
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
