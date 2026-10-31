//! RFC 0028 test helpers: a guard and its calls as a C caller makes them.
#![allow(dead_code)]

use std::ffi::{CStr, CString};
use std::ptr;

use dvarapala::*;

pub fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

pub fn last_error() -> String {
    let p = dv_last_error();
    assert!(!p.is_null(), "no error message");
    // SAFETY: a NUL-terminated message owned by this thread
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

pub fn config(pairs: &[(&str, &str)]) -> *mut DvConfig {
    let cfg = dv_config_new();
    for (k, v) in pairs {
        // SAFETY: a live config and NUL-terminated strings
        assert_eq!(
            unsafe { dv_config_set(cfg, c(k).as_ptr(), c(v).as_ptr()) },
            DV_OK
        );
    }
    cfg
}

/// A guard from `pairs`, or the error message.
pub fn guard(pairs: &[(&str, &str)]) -> Result<Guard, String> {
    let cfg = config(pairs);
    // SAFETY: a live config, freed once below
    let g = unsafe { dv_guard_new(cfg) };
    unsafe { dv_config_free(cfg) };
    if g.is_null() {
        Err(last_error())
    } else {
        Ok(Guard(g))
    }
}

pub struct Guard(pub *mut DvGuard);

// SAFETY: DvGuard is thread-safe by contract
unsafe impl Send for Guard {}
unsafe impl Sync for Guard {}

impl Drop for Guard {
    fn drop(&mut self) {
        // SAFETY: from dv_guard_new, freed once
        unsafe { dv_guard_free(self.0) }
    }
}

/// A request's fields; `None` passes null.
#[derive(Clone, Copy)]
pub struct Req<'a> {
    pub ip: &'a str,
    pub method: Option<&'a str>,
    pub host: Option<&'a str>,
    pub path: Option<&'a str>,
    pub headers: Option<&'a str>,
}

pub fn req<'a>(ip: &'a str, method: &'a str, path: &'a str) -> Req<'a> {
    Req {
        ip,
        method: Some(method),
        host: None,
        path: Some(path),
        headers: None,
    }
}

impl Guard {
    pub fn check(&self, ip: &str) -> DvVerdict {
        let mut v = DvVerdict::default();
        // SAFETY: a live guard, NUL-terminated strings, a valid out pointer
        assert_eq!(
            unsafe { dv_check(self.0, c(ip).as_ptr(), ptr::null(), &mut v) },
            DV_OK
        );
        v
    }

    /// The verdict and the route name, or the error code.
    pub fn request(&self, r: Req) -> Result<(i32, u64, Option<String>), i32> {
        let s = |v: Option<&str>| v.map(c);
        let (ip, m, h, p, hs) = (c(r.ip), s(r.method), s(r.host), s(r.path), s(r.headers));
        let ptr = |v: &Option<CString>| v.as_ref().map_or(ptr::null(), |v| v.as_ptr());
        let req = DvRequest {
            ip: ip.as_ptr(),
            xff: ptr::null(),
            method: ptr(&m),
            host: ptr(&h),
            path: ptr(&p),
            headers: ptr(&hs),
        };
        let mut v = DvRequestVerdict::default();
        // SAFETY: a live guard, a request of NUL-terminated strings, a valid out
        match unsafe { dv_check_request(self.0, &req, &mut v) } {
            DV_OK => {
                let route = (!v.route.is_null())
                    // SAFETY: a name the guard keeps while it lives
                    .then(|| {
                        unsafe { CStr::from_ptr(v.route) }
                            .to_str()
                            .unwrap()
                            .to_owned()
                    });
                Ok((v.kind, v.retry_after_ms, route))
            }
            code => Err(code),
        }
    }

    pub fn route_headers(&self) -> String {
        // SAFETY: a live guard; the string lives as long as it
        let p = unsafe { dv_route_headers(self.0) };
        unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_owned()
    }

    pub fn block(&self, cidr: &str, ttl_ms: u64) -> i32 {
        // SAFETY: a live guard and a NUL-terminated string
        unsafe { dv_block(self.0, c(cidr).as_ptr(), ttl_ms) }
    }

    pub fn unblock(&self, cidr: &str) -> i32 {
        // SAFETY: a live guard and a NUL-terminated string
        unsafe { dv_unblock(self.0, c(cidr).as_ptr()) }
    }

    pub fn blocks(&self) -> String {
        // SAFETY: a live guard; the string is freed once below
        unsafe {
            let p = dv_blocks(self.0);
            let s = CStr::from_ptr(p).to_str().unwrap().to_owned();
            dv_string_free(p);
            s
        }
    }

    pub fn egress(&self, dest: &str) -> DvSlot {
        let mut s = DvSlot::default();
        // SAFETY: a live guard, a NUL-terminated string, a valid out pointer
        assert_eq!(
            unsafe { dv_egress(self.0, c(dest).as_ptr(), &mut s) },
            DV_OK
        );
        s
    }

    pub fn reload(&self, pairs: &[(&str, &str)]) -> Result<(), String> {
        let cfg = config(pairs);
        // SAFETY: a live guard and config, freed once below
        let rc = unsafe { dv_guard_reload(self.0, cfg) };
        unsafe { dv_config_free(cfg) };
        match rc {
            DV_OK => Ok(()),
            _ => Err(last_error()),
        }
    }
}
