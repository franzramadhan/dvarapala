//! C ABI over the engine (RFC 0008): a guard per process or service that
//! the Go, Python and JavaScript packages call. `dvarapala.h` is the
//! contract.

mod config;
mod conn;
mod error;
mod guard;

pub use conn::{DvConn, dv_conn_close, dv_conn_open};
pub use error::{DV_E_INVALID, DV_E_LIMIT, DV_E_NULL, DV_E_PANIC, DV_E_UTF8, DV_OK, dv_last_error};
pub use guard::{
    DV_ALLOW, DV_DROP, DV_THROTTLE, DvConfig, DvGuard, DvStats, DvVerdict, dv_check,
    dv_config_free, dv_config_new, dv_config_set, dv_guard_free, dv_guard_new, dv_stats,
};
