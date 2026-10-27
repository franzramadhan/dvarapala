//! Verdict engine. No I/O and no async runtime: callers pass the current
//! time in, so every decision is deterministic and testable.

// rfc 0001 stubs: removed once the engine layer fills the bodies in
#![allow(dead_code, unused_variables)]

mod bucket;
mod cidr;
mod key;
mod table;
mod verdict;

pub use bucket::{Bucket, Limit, LimitError};
pub use cidr::{Cidr, CidrError, TrustedProxies};
pub use key::{ClientKey, client_key};
pub use table::Table;
pub use verdict::Verdict;
