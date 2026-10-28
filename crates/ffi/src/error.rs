use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;

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

/// An error code and its message.
pub(crate) type Error = (i32, String);

thread_local! {
    static LAST: RefCell<Option<CString>> = const { RefCell::new(None) };
}

/// The message of the last error on this thread, or null. Valid until the
/// next call on this thread.
#[unsafe(no_mangle)]
pub extern "C" fn dv_last_error() -> *const c_char {
    LAST.with_borrow(|l| l.as_ref().map_or(ptr::null(), |s| s.as_ptr()))
}

fn keep(msg: String) {
    // a NUL inside would cut the message; the bytes came from the caller
    let msg = CString::new(msg.replace('\0', " ")).unwrap_or_default();
    LAST.set(Some(msg));
}

/// Runs `f`; a panic becomes `DV_E_PANIC`, an error its code with the
/// message kept for `dv_last_error`.
pub(crate) fn catch<T>(f: impl FnOnce() -> Result<T, Error>) -> Result<T, i32> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(v)) => Ok(v),
        Ok(Err((code, msg))) => {
            keep(msg);
            Err(code)
        }
        Err(_) => {
            keep("panic inside dvarapala, please report it".into());
            Err(DV_E_PANIC)
        }
    }
}

/// [`catch`] as a return code.
pub(crate) fn code(f: impl FnOnce() -> Result<(), Error>) -> i32 {
    catch(f).err().unwrap_or(DV_OK)
}

pub(crate) fn null(name: &str) -> Error {
    (DV_E_NULL, format!("{name} is null"))
}

/// `s` as UTF-8; `name` labels the error.
///
/// # Safety
///
/// `s` is null or a NUL-terminated string.
pub(crate) unsafe fn text<'a>(s: *const c_char, name: &str) -> Result<&'a str, Error> {
    if s.is_null() {
        return Err(null(name));
    }
    // SAFETY: non-null and NUL-terminated by the caller's contract
    unsafe { CStr::from_ptr(s) }
        .to_str()
        .map_err(|_| (DV_E_UTF8, format!("{name} is not UTF-8")))
}
