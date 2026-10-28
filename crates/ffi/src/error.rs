use std::ffi::{CStr, c_char};

pub const DV_OK: i32 = 0;
/// A required pointer was null.
pub const DV_E_NULL: i32 = 1;
/// A string was not UTF-8.
pub const DV_E_UTF8: i32 = 2;
/// A bad address, key or value; `dv_last_error` says which.
pub const DV_E_INVALID: i32 = 3;
/// A connection over an `l4.*` limit; `dv_last_error` names the reason.
pub const DV_E_LIMIT: i32 = 4;
/// A bug in the library, caught before it crossed the ABI.
pub const DV_E_PANIC: i32 = 5;

/// The message of the last error on this thread, or null. Valid until the
/// next call on this thread.
#[unsafe(no_mangle)]
pub extern "C" fn dv_last_error() -> *const c_char {
    todo!("rfc 0008")
}

/// Runs `f`, turning a panic into `DV_E_PANIC` and an error into its code
/// with the message kept for `dv_last_error`.
pub(crate) fn guarded(f: impl FnOnce() -> Result<(), (i32, String)>) -> i32 {
    let _ = f;
    todo!("rfc 0008")
}

/// `s` as UTF-8; `name` labels the error.
///
/// # Safety
///
/// `s` is null or a NUL-terminated string.
pub(crate) unsafe fn text<'a>(s: *const c_char, name: &str) -> Result<&'a str, (i32, String)> {
    let _ = (s, name, CStr::is_empty);
    todo!("rfc 0008")
}
