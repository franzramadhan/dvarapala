#![allow(unused_variables, unused_imports, unused_mut, dead_code)]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dvarapala_engine::{Batch, Reply};
use redis::aio::MultiplexedConnection;
use redis::{Client, TlsCertificates, Value};

use crate::{Error, Round, Store};

/// Redis backend (RFC 0010): one pipeline per round, one multiplexed
/// connection, dropped and made again after an error. Keys: the hash
/// `<cluster>:count:<window>` (one field per client, a TTL of two
/// windows), and the
/// sorted sets `<cluster>:replicas`, `<cluster>:heavy`, `<cluster>:pauses`
/// scored by expiry in unix milliseconds of the writing replica's clock.
pub struct Redis {
    client: Client,
    conn: Option<MultiplexedConnection>,
}

fn rd(e: redis::RedisError) -> Error {
    todo!("rfc 0010")
}

impl Redis {
    /// `url` is `redis://` or `rediss://`; TLS is verified against `ca`
    /// (PEM) or the system roots.
    pub fn new(url: &str, ca: Option<&[u8]>) -> Result<Self, Error> {
        todo!("rfc 0010")
    }
}

impl Store for Redis {
    async fn round(&mut self, r: &Round<'_>) -> Result<Reply, Error> {
        todo!("rfc 0010")
    }
}

fn pipeline(r: &Round<'_>, now: u64) -> redis::Pipeline {
    todo!("rfc 0010")
}

/// Reads the pipeline's replies for `batch`: the replica count, one total
/// per client, then the heavy and pause lists. Anything else is an error,
/// never a panic: the replies come from the network (fuzz target
/// `store_reply`).
pub fn decode(values: Vec<Value>, batch: &Batch) -> Result<Reply, Error> {
    todo!("rfc 0010")
}

fn ms(d: Duration) -> u64 {
    todo!("rfc 0010")
}

fn unix_ms() -> u64 {
    todo!("rfc 0010")
}

impl std::fmt::Debug for Redis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!("rfc 0010")
    }
}
