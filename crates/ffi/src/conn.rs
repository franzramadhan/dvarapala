use std::ffi::c_char;
use std::sync::Arc;

use dvarapala_engine::ConnKey;

use crate::guard::{DvGuard, Shared};

/// One open connection's place; [`dv_conn_close`] frees it.
pub struct DvConn {
    pub(crate) shared: Arc<Shared>,
    pub(crate) key: Option<ConnKey>,
}

/// Counts a new connection from `ip`: `DV_OK` with `*out` set, or
/// `DV_E_LIMIT` with the reason (`total`, `per_client`, `rate`) in
/// `dv_last_error`. With `l4.enabled = false` every connection is `DV_OK`.
///
/// # Safety
///
/// `g` comes from [`crate::dv_guard_new`]; `ip` is null or NUL-terminated;
/// `out` is null or points to a `*mut DvConn`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dv_conn_open(
    g: *const DvGuard,
    ip: *const c_char,
    out: *mut *mut DvConn,
) -> i32 {
    let _ = (g, ip, out);
    todo!("rfc 0008")
}

/// Frees the place; null is a no-op.
///
/// # Safety
///
/// `c` is null or comes from [`dv_conn_open`], closed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dv_conn_close(c: *mut DvConn) {
    let _ = c;
    todo!("rfc 0008")
}
