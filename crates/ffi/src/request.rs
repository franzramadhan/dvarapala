//! RFC 0028: a request's verdict with the routes applied.

use std::ffi::{CStr, c_char};
use std::ptr;
use std::time::Instant;

use dvarapala_engine::{Verdict, client_key, strip_port};

use crate::error::{DV_E_INVALID, DV_E_UTF8, Error, code, null};
use crate::guard::{DvGuard, lock, peer};

/// Longest field `dv_check_request` reads.
const MAX_FIELD: usize = 8 * 1024;

/// A request as the HTTP server parsed it. Every field is NUL-terminated
/// UTF-8 of at most 8 KiB.
#[repr(C)]
pub struct DvRequest {
    /// The peer address.
    pub ip: *const c_char,
    /// `X-Forwarded-For`, or null.
    pub xff: *const c_char,
    pub method: *const c_char,
    /// The authority or `Host`, or null when the request has none.
    pub host: *const c_char,
    /// The raw path, without the query.
    pub path: *const c_char,
    /// `name: value` lines, one per `\n`, for the names
    /// [`dv_route_headers`] lists; or null.
    pub headers: *const c_char,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DvRequestVerdict {
    /// `DV_ALLOW`, `DV_THROTTLE` or `DV_DROP`.
    pub kind: i32,
    /// With `DV_THROTTLE`: when to retry, in milliseconds.
    pub retry_after_ms: u64,
    /// The matched route's name, or null; valid while the guard lives.
    pub route: *const c_char,
}

impl Default for DvRequestVerdict {
    fn default() -> Self {
        Self {
            kind: 0,
            retry_after_ms: 0,
            route: ptr::null(),
        }
    }
}

/// The verdict for `r` with `routes` applied as the gateway applies them:
/// a block, then a denied route, then the global bucket, then the route's.
/// A field over 8 KiB, a bad header line or a missing method or path is
/// `DV_E_INVALID`, a field that is not UTF-8 `DV_E_UTF8`.
///
/// # Safety
///
/// `g` comes from [`crate::dv_guard_new`]; `r` is null or points to a
/// `DvRequest` whose fields are null or NUL-terminated; `out` is null or
/// points to a `DvRequestVerdict`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dv_check_request(
    g: *const DvGuard,
    r: *const DvRequest,
    out: *mut DvRequestVerdict,
) -> i32 {
    code(|| {
        // SAFETY: null or from dv_guard_new, by contract
        let g = unsafe { g.as_ref() }.ok_or_else(|| null("guard"))?;
        // SAFETY: null or a valid DvRequest, by contract
        let r = unsafe { r.as_ref() }.ok_or_else(|| null("request"))?;
        // SAFETY: null or a valid DvRequestVerdict, by contract
        let out = unsafe { out.as_mut() }.ok_or_else(|| null("out"))?;
        // SAFETY: each field null or NUL-terminated, by contract
        let (ip, xff, method, host, path, headers) = unsafe {
            (
                field(r.ip, "ip")?.ok_or_else(|| null("ip"))?,
                field(r.xff, "xff")?,
                field(r.method, "method")?.filter(|m| !m.is_empty()),
                field(r.host, "host")?,
                field(r.path, "path")?.filter(|p| !p.is_empty()),
                field(r.headers, "headers")?.unwrap_or_default(),
            )
        };
        let missing = |n: &str| (DV_E_INVALID, format!("{n} is missing"));
        let method = method.ok_or_else(|| missing("method"))?;
        let path = path.ok_or_else(|| missing("path"))?;
        let headers = lines(headers)?;
        let host = host.map(|h| strip_port(h.as_bytes()));
        let peer = peer(ip)?;
        let now = Instant::now();

        let mut state = lock(&g.0.state);
        let s = &mut *state;
        let key = client_key(peer, xff, &s.trusted);
        let mut route = None;
        let v = if s.blocks.contains(key.into(), now) {
            Verdict::Drop
        } else {
            let ip = key.into();
            route = s
                .routes
                .iter()
                .find(|r| r.matcher.matches(method, host, path, ip));
            match route {
                Some(r) if r.deny => Verdict::Drop,
                _ => match (s.guard.check(key, now).verdict, route) {
                    (Verdict::Allow, Some(r)) => r.limits.as_ref().map_or(Verdict::Allow, |l| {
                        let value = r.header.as_deref().and_then(|h| header(&headers, h));
                        l.take(value.map(str::as_bytes), key, now).0
                    }),
                    (v, _) => v,
                },
            }
        };
        let d = g.0.verdict(v);
        *out = DvRequestVerdict {
            kind: d.kind,
            retry_after_ms: d.retry_after_ms,
            route: route.map_or(ptr::null(), |r| r.name.as_ptr()),
        };
        Ok(())
    })
}

/// The header names route keys read, lower case and comma separated; `""`
/// when none does. Valid while the guard lives; null for a null guard.
///
/// # Safety
///
/// `g` is null or comes from [`crate::dv_guard_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dv_route_headers(g: *const DvGuard) -> *const c_char {
    // SAFETY: null or from dv_guard_new, by contract
    match unsafe { g.as_ref() } {
        Some(g) => lock(&g.0.state).headers.as_ptr(),
        None => ptr::null(),
    }
}

/// `p` as UTF-8 of at most [`MAX_FIELD`] bytes, `None` when null.
///
/// # Safety
///
/// `p` is null or NUL-terminated.
unsafe fn field<'a>(p: *const c_char, name: &str) -> Result<Option<&'a str>, Error> {
    if p.is_null() {
        return Ok(None);
    }
    // SAFETY: non-null and NUL-terminated by the caller's contract
    let b = unsafe { CStr::from_ptr(p) }.to_bytes();
    if b.len() > MAX_FIELD {
        return Err((DV_E_INVALID, format!("{name} is over 8 KiB")));
    }
    let s = std::str::from_utf8(b).map_err(|_| (DV_E_UTF8, format!("{name} is not UTF-8")))?;
    Ok(Some(s))
}

/// `name: value` lines; a line without a token name and a colon (a value
/// that held a newline) or with a carriage return fails.
fn lines(h: &str) -> Result<Vec<(&str, &str)>, Error> {
    let bad = || {
        (
            DV_E_INVALID,
            "headers: one \"name: value\" per line".to_owned(),
        )
    };
    h.split('\n')
        .filter(|l| !l.is_empty())
        .map(|l| {
            let (n, v) = l.split_once(':').ok_or_else(bad)?;
            let token = |b: u8| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b);
            if n.is_empty() || !n.bytes().all(token) || v.contains('\r') {
                return Err(bad());
            }
            Ok((n, v.trim_matches([' ', '\t'])))
        })
        .collect()
}

/// The first value of `name` (lower case).
fn header<'a>(lines: &[(&str, &'a str)], name: &str) -> Option<&'a str> {
    lines
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| *v)
}
