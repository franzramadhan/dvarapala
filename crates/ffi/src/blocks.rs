//! RFC 0028: manual blocks, as the gateway's `POST /blocks` (RFC 0014).

use std::ffi::{CString, c_char};
use std::fmt::Write;
use std::ptr;
use std::time::{Duration, Instant};

use dvarapala_engine::Cidr;

use crate::error::{DV_E_INVALID, DV_E_LIMIT, DV_E_NOT_FOUND, Error, catch, code, null, text};
use crate::guard::{DvGuard, lock};

/// Blocks `cidr` (an address or `addr/prefix`) for `ttl_ms`, 0 for
/// `admin.max_block_ttl`; blocking a listed network again moves its
/// expiry. A full list is `DV_E_LIMIT`, a TTL over the maximum
/// `DV_E_INVALID`.
///
/// # Safety
///
/// `g` comes from [`crate::dv_guard_new`]; `cidr` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dv_block(g: *const DvGuard, cidr: *const c_char, ttl_ms: u64) -> i32 {
    code(|| {
        // SAFETY: null or from dv_guard_new, by contract
        let g = unsafe { g.as_ref() }.ok_or_else(|| null("guard"))?;
        // SAFETY: null or NUL-terminated, by contract
        let net = network(unsafe { text(cidr, "cidr")? })?;
        let now = Instant::now();
        let mut s = lock(&g.0.state);
        let ttl = match ttl_ms {
            0 => s.max_block_ttl,
            ms => Duration::from_millis(ms),
        };
        if ttl > s.max_block_ttl {
            let max = s.max_block_ttl.as_millis();
            return Err((
                DV_E_INVALID,
                format!("ttl_ms: over admin.max_block_ttl ({max} ms)"),
            ));
        }
        s.blocks
            .add(net, now + ttl, now)
            .map_err(|e| (DV_E_LIMIT, e.to_string()))
    })
}

/// Lifts the block on `cidr`; `DV_E_NOT_FOUND` when it is not listed.
///
/// # Safety
///
/// `g` comes from [`crate::dv_guard_new`]; `cidr` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dv_unblock(g: *const DvGuard, cidr: *const c_char) -> i32 {
    code(|| {
        // SAFETY: null or from dv_guard_new, by contract
        let g = unsafe { g.as_ref() }.ok_or_else(|| null("guard"))?;
        // SAFETY: null or NUL-terminated, by contract
        let net = network(unsafe { text(cidr, "cidr")? })?;
        match lock(&g.0.state).blocks.remove(net) {
            true => Ok(()),
            false => Err((DV_E_NOT_FOUND, format!("{net} is not blocked"))),
        }
    })
}

/// The blocks in force as JSON, `[{"cidr": "192.0.2.0/24", "ttl_ms": 59000}]`;
/// free it with [`dv_string_free`]. Null with `dv_last_error` on error.
///
/// # Safety
///
/// `g` comes from [`crate::dv_guard_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dv_blocks(g: *const DvGuard) -> *mut c_char {
    let json = catch(|| {
        // SAFETY: null or from dv_guard_new, by contract
        let g = unsafe { g.as_ref() }.ok_or_else(|| null("guard"))?;
        let now = Instant::now();
        let mut list = lock(&g.0.state).blocks.list(now);
        list.sort_by_key(|(n, _)| (n.addr(), n.prefix()));
        let mut out = String::from("[");
        for (i, (net, until)) in list.iter().enumerate() {
            let sep = if i == 0 { "" } else { "," };
            let ms = (*until - now).as_millis();
            // a CIDR's text is digits, dots, colons and a slash: no escaping
            let _ = write!(out, r#"{sep}{{"cidr":"{net}","ttl_ms":{ms}}}"#);
        }
        out.push(']');
        Ok(CString::new(out).unwrap_or_default())
    });
    json.map_or(ptr::null_mut(), CString::into_raw)
}

/// Frees a string from [`dv_blocks`]; null is a no-op.
///
/// # Safety
///
/// `s` is null or comes from [`dv_blocks`], freed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dv_string_free(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: from CString::into_raw in dv_blocks, freed once
        drop(unsafe { CString::from_raw(s) });
    }
}

fn network(s: &str) -> Result<Cidr, Error> {
    s.trim()
        .parse()
        .map_err(|e: dvarapala_engine::CidrError| (DV_E_INVALID, format!("cidr: {e}")))
}
