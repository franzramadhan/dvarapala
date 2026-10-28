use std::fmt;
use std::future::Future;
use std::time::Duration;

use dvarapala_engine::{Batch, Reply};

/// One sync round as the backend sees it.
#[derive(Debug, Clone, Copy)]
pub struct Round<'a> {
    /// `store.cluster`: replicas with the same name share state.
    pub cluster: &'a str,
    /// This replica, unique while it runs.
    pub replica: &'a str,
    /// How long this replica's heartbeat counts as alive.
    pub heartbeat: Duration,
    /// The counting window; counters live for two.
    pub window: Duration,
    /// Listed heavy hitters and pauses read back at most.
    pub max_list: usize,
    pub batch: &'a Batch,
}

/// A failed round. The text never holds the store URL or its password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// A shared backend. One call is one round trip (a Redis pipeline, a
/// PostgreSQL transaction): heartbeat, add the batch, read the cluster
/// view back. The caller bounds the call with `store.timeout`.
pub trait Store: Send + 'static {
    fn round(&mut self, round: &Round<'_>) -> impl Future<Output = Result<Reply, Error>> + Send;

    /// Connects when there is no connection, before each round. Bounded by
    /// ten round timeouts, not one: a first PostgreSQL connection migrates,
    /// and replicas starting together wait for each other's migrations.
    fn connect(&mut self) -> impl Future<Output = Result<(), Error>> + Send {
        async { Ok(()) }
    }
}
