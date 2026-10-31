//! C ABI over the engine (RFC 0008): a guard per process or service that
//! the Go, Python and JavaScript packages call. `dvarapala.h` is the
//! contract.

mod blocks;
mod config;
mod conn;
mod egress;
mod error;
mod guard;
mod lists;
mod request;
mod state;

pub use blocks::{dv_block, dv_blocks, dv_string_free, dv_unblock};
pub use conn::{DvConn, dv_conn_close, dv_conn_open};
pub use egress::{DV_SLOT_NOW, DV_SLOT_REFUSE, DV_SLOT_WAIT, DvSlot, dv_egress, dv_egress_pause};
pub use error::{
    DV_E_INVALID, DV_E_LIMIT, DV_E_NOT_FOUND, DV_E_NULL, DV_E_PANIC, DV_E_UTF8, DV_OK,
    dv_last_error,
};
pub use guard::{
    DV_ALLOW, DV_DROP, DV_THROTTLE, DvConfig, DvGuard, DvStats, DvVerdict, dv_check,
    dv_config_free, dv_config_new, dv_config_set, dv_guard_free, dv_guard_new, dv_guard_reload,
    dv_stats,
};
pub use request::{DvRequest, DvRequestVerdict, dv_check_request, dv_route_headers};
