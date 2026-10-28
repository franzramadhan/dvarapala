//! N-API addon for `sdk/js` (RFC 0008): the `dv_*` C ABI as JavaScript
//! classes, so the config rules and errors stay those of `crates/ffi`.

mod guard;

pub use guard::{Conn, Guard};
