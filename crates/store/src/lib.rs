//! Shared state for dvarapala clusters (RFC 0010). A background task syncs
//! each replica's [`dvarapala_engine::Cluster`] with a store; nothing on the
//! request path waits for it.

#[cfg(feature = "postgres")]
mod history;
mod memory;
mod migrate;
#[cfg(feature = "postgres")]
mod postgres;
#[cfg(feature = "redis")]
mod redis;
mod round;
mod sync;

pub use memory::Memory;
pub use migrate::{LATEST, MIGRATIONS, Migration, render};
#[cfg(feature = "postgres")]
pub use migrate::{apply, version};
#[cfg(feature = "postgres")]
pub use postgres::Postgres;
#[cfg(feature = "redis")]
pub use redis::{Redis, decode};
pub use round::{Error, Round, Store};
pub use sync::{Status, SyncConfig, spawn};
