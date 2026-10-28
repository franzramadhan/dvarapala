//! RFC 0008 case 13: client bytes through `dv_check` (address and
//! `X-Forwarded-For`, invalid UTF-8 included) never panic or crash, and
//! every call returns a known code.
#![no_main]

use std::ffi::CString;
use std::ptr;
use std::sync::LazyLock;

use dvarapala::{
    DV_E_INVALID, DV_E_UTF8, DV_OK, DvGuard, DvVerdict, dv_check, dv_config_new, dv_config_set,
    dv_guard_new,
};
use libfuzzer_sys::fuzz_target;

/// One guard for the run, as a host would hold it.
static GUARD: LazyLock<usize> = LazyLock::new(|| unsafe {
    let cfg = dv_config_new();
    dv_config_set(cfg, c"trusted_proxies".as_ptr(), c"192.0.2.0/24".as_ptr());
    dv_config_set(cfg, c"detection.mode".as_ptr(), c"enforce".as_ptr());
    let g = dv_guard_new(cfg);
    assert!(!g.is_null());
    g as usize
});

fn c(bytes: &[u8]) -> CString {
    CString::new(
        bytes
            .iter()
            .copied()
            .filter(|&b| b != 0)
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

fuzz_target!(|data: (&[u8], &[u8], bool)| {
    let (ip, xff, with_xff) = data;
    let (ip, xff) = (c(ip), c(xff));
    let xff = if with_xff { xff.as_ptr() } else { ptr::null() };
    let mut out = DvVerdict {
        kind: -1,
        retry_after_ms: 0,
    };
    // SAFETY: a live guard, NUL-terminated strings, a valid out pointer
    let rc = unsafe { dv_check(*GUARD as *const DvGuard, ip.as_ptr(), xff, &mut out) };
    assert!([DV_OK, DV_E_UTF8, DV_E_INVALID].contains(&rc), "{rc}");
    if rc == DV_OK {
        assert!((0..=2).contains(&out.kind));
    }
});
