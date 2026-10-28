use std::ffi::c_char;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use dvarapala_engine::ConnKey;

use crate::error::{DV_E_LIMIT, code, null, text};
use crate::guard::{DvGuard, Shared, lock, peer};

/// One open connection's place; [`dv_conn_close`] frees it.
pub struct DvConn {
    pub(crate) shared: Arc<Shared>,
    /// set once the per-client table counted it
    pub(crate) key: Option<ConnKey>,
}

impl Drop for DvConn {
    fn drop(&mut self) {
        if let (Some(key), Some(conns)) = (self.key.take(), &self.shared.conns) {
            lock(conns).close(key);
        }
        self.shared.open.fetch_sub(1, Ordering::AcqRel);
    }
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
    code(|| {
        // SAFETY: null or from dv_guard_new, by contract
        let g = unsafe { g.as_ref() }.ok_or_else(|| null("guard"))?;
        // SAFETY: null or NUL-terminated, by contract
        let ip = peer(unsafe { text(ip, "ip")? })?;
        // SAFETY: null or a valid pointer slot, by contract
        let out = unsafe { out.as_mut() }.ok_or_else(|| null("out"))?;
        let shared = &g.0;
        let open = shared.open.fetch_add(1, Ordering::AcqRel);
        // from here a refusal gives the place back when `conn` drops
        let mut conn = Box::new(DvConn {
            shared: shared.clone(),
            key: None,
        });
        let limit = |reason: &str| (DV_E_LIMIT, reason.to_owned());
        if shared.max_connections > 0 && open >= shared.max_connections {
            return Err(limit("total"));
        }
        if let Some(conns) = &shared.conns {
            let key = lock(conns)
                .open(ip, Instant::now())
                .map_err(|r| limit(r.as_str()))?;
            conn.key = Some(key);
        }
        *out = Box::into_raw(conn);
        Ok(())
    })
}

/// Frees the place; null is a no-op.
///
/// # Safety
///
/// `c` is null or comes from [`dv_conn_open`], closed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dv_conn_close(c: *mut DvConn) {
    if !c.is_null() {
        // SAFETY: from dv_conn_open and closed once, by contract
        drop(unsafe { Box::from_raw(c) });
    }
}
