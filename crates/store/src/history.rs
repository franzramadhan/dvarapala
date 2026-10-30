//! RFC 0022: the console's traffic history in PostgreSQL, one row per
//! replica and minute in `dvarapala.traffic_history`.
#![allow(unused_variables, unused_imports, dead_code)]

use dvarapala_engine::{Minute, VERDICTS};

use crate::Error;
use crate::postgres::{Postgres, pg};

/// Rows deleted per sweep at most.
const SWEEP_ROWS: i64 = 10_000;

impl Postgres {
    /// Adds this replica's minute row; a second write of the same minute adds up.
    pub async fn history_write(
        &mut self,
        cluster: &str,
        replica: &str,
        m: &Minute,
    ) -> Result<(), Error> {
        todo!("rfc 0022")
    }

    /// The minutes at or after `since_ms`, summed over the replicas of
    /// `cluster`, oldest first.
    pub async fn history_read(
        &mut self,
        cluster: &str,
        since_ms: u64,
    ) -> Result<Vec<Minute>, Error> {
        todo!("rfc 0022")
    }

    /// Deletes rows of `cluster` before `before_ms` when no other replica
    /// is doing it; the number deleted.
    pub async fn history_expire(&mut self, cluster: &str, before_ms: u64) -> Result<u64, Error> {
        todo!("rfc 0022")
    }

    /// A failed call drops the connection; the next one reconnects.
    fn drop_on_error<T>(&mut self, r: Result<T, Error>) -> Result<T, Error> {
        todo!("rfc 0022")
    }
}
