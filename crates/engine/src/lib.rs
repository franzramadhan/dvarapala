//! Verdict engine. No I/O and no async runtime: callers pass the current
//! time in, so every decision is deterministic and testable.

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
