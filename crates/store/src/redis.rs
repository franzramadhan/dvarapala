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
    // the driver's errors carry no URL or password
    Error(format!("redis: {e}"))
}

impl Redis {
    /// `url` is `redis://` or `rediss://`; TLS is verified against `ca`
    /// (PEM) or the system roots.
    pub fn new(url: &str, ca: Option<&[u8]>) -> Result<Self, Error> {
        let client = match ca {
            Some(pem) => Client::build_with_tls(
                url,
                TlsCertificates {
                    client_tls: None,
                    root_cert: Some(pem.to_vec()),
                },
            ),
            None => Client::open(url),
        }
        .map_err(|e| Error(format!("store.url is not a Redis URL: {:?}", e.kind())))?;
        Ok(Self { client, conn: None })
    }
}

impl Store for Redis {
    async fn round(&mut self, r: &Round<'_>) -> Result<Reply, Error> {
        let mut conn = match &self.conn {
            Some(c) => c.clone(),
            None => {
                let c = self
                    .client
                    .get_multiplexed_async_connection()
                    .await
                    .map_err(rd)?;
                self.conn = Some(c.clone());
                c
            }
        };
        let now = unix_ms();
        let values: Vec<Value> = match pipeline(r, now).query_async(&mut conn).await {
            Ok(v) => v,
            Err(e) => {
                self.conn = None;
                return Err(rd(e));
            }
        };
        decode(values, r.batch)
    }
}

fn pipeline(r: &Round<'_>, now: u64) -> redis::Pipeline {
    let c = r.cluster;
    let (replicas, heavy, pauses) = (
        format!("{c}:replicas"),
        format!("{c}:heavy"),
        format!("{c}:pauses"),
    );
    let mut p = redis::pipe();
    p.zadd(&replicas, r.replica, now + ms(r.heartbeat)).ignore();
    p.zrembyscore(&replicas, "-inf", now).ignore();
    p.zcard(&replicas);
    let counts = format!("{c}:count:{}", r.batch.window_start);
    for (key, n) in &r.batch.counts {
        p.hincr(&counts, key.to_string(), *n);
    }
    p.pexpire(&counts, ms(r.window * 2) as i64).ignore();
    // GT keeps the later expiry when two replicas list the same entry
    for (net, d) in &r.batch.heavy {
        p.cmd("ZADD")
            .arg(&heavy)
            .arg("GT")
            .arg(now + ms(*d))
            .arg(net.to_string())
            .ignore();
    }
    for (name, d) in &r.batch.pauses {
        p.cmd("ZADD")
            .arg(&pauses)
            .arg("GT")
            .arg(now + ms(*d))
            .arg(name)
            .ignore();
    }
    for set in [&heavy, &pauses] {
        p.zrembyscore(set, "-inf", now).ignore();
        p.cmd("ZRANGEBYSCORE")
            .arg(set)
            .arg(now)
            .arg("+inf")
            .arg("WITHSCORES")
            .arg("LIMIT")
            .arg(0)
            .arg(r.max_list);
    }
    p
}

/// Reads the pipeline's replies for `batch`: the replica count, one total
/// per client, then the heavy and pause lists. Anything else is an error,
/// never a panic: the replies come from the network (fuzz target
/// `store_reply`).
pub fn decode(values: Vec<Value>, batch: &Batch) -> Result<Reply, Error> {
    let bad = |what: &str| Error(format!("redis: unexpected reply for {what}"));
    if values.len() != 3 + batch.counts.len() {
        return Err(bad("the pipeline"));
    }
    let mut it = values.into_iter();
    let replicas: i64 = redis::from_redis_value(it.next().unwrap_or(Value::Nil))
        .map_err(|_| bad("the replica count"))?;
    let mut reply = Reply {
        replicas: replicas.clamp(1, i64::from(u32::MAX)) as u32,
        ..Reply::default()
    };
    for &(key, _) in &batch.counts {
        let total: i64 =
            redis::from_redis_value(it.next().unwrap_or(Value::Nil)).map_err(|_| bad("a count"))?;
        reply.totals.push((key, total.max(0) as u64));
    }
    let now = unix_ms() as f64;
    let mut list = |what| -> Result<Vec<(String, Duration)>, Error> {
        let pairs: Vec<(String, f64)> =
            redis::from_redis_value(it.next().unwrap_or(Value::Nil)).map_err(|_| bad(what))?;
        Ok(pairs
            .into_iter()
            .filter(|(_, at)| at.is_finite())
            .map(|(k, at)| (k, Duration::from_millis((at - now).max(0.0) as u64)))
            .collect())
    };
    // an entry that does not parse is skipped, never a reason to drop
    reply.heavy = list("the heavy hitters")?
        .into_iter()
        .filter_map(|(k, d)| Some((k.parse().ok()?, d)))
        .collect();
    reply.pauses = list("the pauses")?;
    Ok(reply)
}

fn ms(d: Duration) -> u64 {
    d.as_millis().min(u128::from(u64::MAX)) as u64
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

impl std::fmt::Debug for Redis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // the client holds the password
        f.write_str("Redis { .. }")
    }
}
