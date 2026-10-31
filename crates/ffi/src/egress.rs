//! RFC 0028: egress shaping in process, the forward proxy's schedule
//! (RFC 0007) without the hop. The library never waits: it says when.

use std::ffi::c_char;

use crate::guard::DvGuard;

pub const DV_SLOT_NOW: i32 = 0;
pub const DV_SLOT_WAIT: i32 = 1;
pub const DV_SLOT_REFUSE: i32 = 2;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DvSlot {
    /// `DV_SLOT_NOW`, `DV_SLOT_WAIT` or `DV_SLOT_REFUSE`.
    pub kind: i32,
    /// How long to wait with `DV_SLOT_WAIT`, when to retry with
    /// `DV_SLOT_REFUSE`, in milliseconds.
    pub ms: u64,
}

/// A slot for one call to `dest` (a destination's `name`): send now, wait
/// `ms` then send, or give up and retry after `ms`. A `WAIT` slot is spent
/// once given out, sent or not, and holds a queue place until its time.
/// `DV_E_NOT_FOUND` for an unknown destination.
///
/// # Safety
///
/// `g` comes from [`crate::dv_guard_new`]; `dest` is null or
/// NUL-terminated; `out` is null or points to a `DvSlot`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dv_egress(
    g: *const DvGuard,
    dest: *const c_char,
    out: *mut DvSlot,
) -> i32 {
    let _ = (g, dest, out);
    todo!("rfc 0028")
}

/// Holds every call to `dest` for `retry_after_ms` (a provider's
/// `Retry-After`), at most the destination's `max_pause`.
///
/// # Safety
///
/// `g` comes from [`crate::dv_guard_new`]; `dest` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dv_egress_pause(
    g: *const DvGuard,
    dest: *const c_char,
    retry_after_ms: u64,
) -> i32 {
    let _ = (g, dest, retry_after_ms);
    todo!("rfc 0028")
}
