//! RFC 0028: manual blocks, as the gateway's `POST /blocks` (RFC 0014).

use std::ffi::c_char;

use crate::guard::DvGuard;

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
    let _ = (g, cidr, ttl_ms);
    todo!("rfc 0028")
}

/// Lifts the block on `cidr`; `DV_E_NOT_FOUND` when it is not listed.
///
/// # Safety
///
/// `g` comes from [`crate::dv_guard_new`]; `cidr` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dv_unblock(g: *const DvGuard, cidr: *const c_char) -> i32 {
    let _ = (g, cidr);
    todo!("rfc 0028")
}

/// The blocks in force as JSON, `[{"cidr": "192.0.2.0/24", "ttl_ms": 59000}]`;
/// free it with [`dv_string_free`]. Null with `dv_last_error` on error.
///
/// # Safety
///
/// `g` comes from [`crate::dv_guard_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dv_blocks(g: *const DvGuard) -> *mut c_char {
    let _ = g;
    todo!("rfc 0028")
}

/// Frees a string from [`dv_blocks`]; null is a no-op.
///
/// # Safety
///
/// `s` is null or comes from [`dv_blocks`], freed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dv_string_free(s: *mut c_char) {
    let _ = s;
    todo!("rfc 0028")
}
