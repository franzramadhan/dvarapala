//! RFC 0028 case 17: client bytes through `dv_check_request` (method, host,
//! path and header lines, invalid UTF-8 included) never panic or crash,
//! and every call returns a known code.
#![no_main]

use std::ffi::CString;
use std::ptr;
use std::sync::LazyLock;

use dvarapala::{
    DV_E_INVALID, DV_E_UTF8, DV_OK, DvGuard, DvRequest, DvRequestVerdict, dv_check_request,
    dv_config_free, dv_config_new, dv_config_set, dv_guard_new,
};
use libfuzzer_sys::fuzz_target;

const ROUTES: &str = r#"[
  {"name": "probes", "path": "/wp-admin", "deny": true},
  {"name": "login", "host": "*.example.com", "path": "=/login", "methods": ["POST"], "rate": 1},
  {"name": "api", "path": "/", "key": "header:x-api-key", "rate": 5, "max_keys": 100}
]"#;

/// One guard for the run, as a host would hold it.
static GUARD: LazyLock<usize> = LazyLock::new(|| unsafe {
    let cfg = dv_config_new();
    let routes = CString::new(ROUTES).unwrap();
    dv_config_set(cfg, c"routes".as_ptr(), routes.as_ptr());
    let g = dv_guard_new(cfg);
    dv_config_free(cfg);
    assert!(!g.is_null());
    g as usize
});

fn c(bytes: &[u8]) -> CString {
    CString::new(bytes.iter().copied().filter(|&b| b != 0).collect::<Vec<_>>()).unwrap()
}

fuzz_target!(|data: (&[u8], &[u8], &[u8], &[u8], bool)| {
    let (method, host, path, headers, with_host) = data;
    let (method, host, path, headers) = (c(method), c(host), c(path), c(headers));
    let r = DvRequest {
        ip: c"192.0.2.1".as_ptr(),
        xff: ptr::null(),
        method: method.as_ptr(),
        host: if with_host { host.as_ptr() } else { ptr::null() },
        path: path.as_ptr(),
        headers: headers.as_ptr(),
    };
    let mut out = DvRequestVerdict::default();
    // SAFETY: a live guard, NUL-terminated fields, a valid out pointer
    let rc = unsafe { dv_check_request(*GUARD as *const DvGuard, &r, &mut out) };
    assert!([DV_OK, DV_E_UTF8, DV_E_INVALID].contains(&rc), "{rc}");
    if rc == DV_OK {
        assert!((0..=2).contains(&out.kind));
    }
});
