//! RFC 0028: a request's verdict with the routes applied.

use std::ffi::c_char;
use std::ptr;

use crate::guard::DvGuard;

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
    let _ = (g, r, out);
    todo!("rfc 0028")
}

/// The header names route keys read, lower case and comma separated; `""`
/// when none does. Valid while the guard lives; null for a null guard.
///
/// # Safety
///
/// `g` is null or comes from [`crate::dv_guard_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dv_route_headers(g: *const DvGuard) -> *const c_char {
    let _ = g;
    todo!("rfc 0028")
}
