//! RFC 0022: the console's traffic history in PostgreSQL, one row per
//! replica and minute in `dvarapala.traffic_history`.

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
        let counts: Vec<i64> = m
            .counts
            .iter()
            .map(|&n| n.min(i64::MAX as u64) as i64)
            .collect();
        let result = async {
            let client = self.client().await?;
            client
                .execute(
                    "INSERT INTO dvarapala.traffic_history AS t (cluster, minute, replica, counts) \
                     VALUES ($1, $2, $3, $4) \
                     ON CONFLICT (cluster, minute, replica) DO UPDATE SET counts = ARRAY( \
                     SELECT a + b FROM unnest(t.counts, EXCLUDED.counts) AS u(a, b))",
                    &[&cluster, &(m.minute_ms as i64), &replica, &counts],
                )
                .await
                .map_err(pg)
        }
        .await;
        self.drop_on_error(result).map(drop)
    }

    /// The minutes at or after `since_ms`, summed over the replicas of
    /// `cluster`, oldest first.
    pub async fn history_read(
        &mut self,
        cluster: &str,
        since_ms: u64,
    ) -> Result<Vec<Minute>, Error> {
        let result = async {
            let client = self.client().await?;
            client
                .query(
                    "SELECT minute, sum(counts[1])::bigint, sum(counts[2])::bigint, \
                     sum(counts[3])::bigint, sum(counts[4])::bigint, sum(counts[5])::bigint \
                     FROM dvarapala.traffic_history WHERE cluster = $1 AND minute >= $2 \
                     GROUP BY minute ORDER BY minute",
                    &[&cluster, &(since_ms.min(i64::MAX as u64) as i64)],
                )
                .await
                .map_err(pg)
        }
        .await;
        let rows = self.drop_on_error(result)?;
        Ok(rows
            .iter()
            .map(|r| Minute {
                minute_ms: r.get::<_, i64>(0).max(0) as u64,
                counts: std::array::from_fn::<_, VERDICTS, _>(|i| {
                    r.get::<_, Option<i64>>(i + 1).unwrap_or(0).max(0) as u64
                }),
            })
            .collect())
    }

    /// Deletes rows of `cluster` before `before_ms` when no other replica
    /// is doing it; the number deleted.
    pub async fn history_expire(&mut self, cluster: &str, before_ms: u64) -> Result<u64, Error> {
        let result = async {
            let client = self.client().await?;
            let tx = client.transaction().await.map_err(pg)?;
            let locked: bool = tx
                .query_one(
                    "SELECT pg_try_advisory_xact_lock(hashtext('dvarapala.history'))",
                    &[],
                )
                .await
                .map_err(pg)?
                .get(0);
            let n = if locked {
                tx.execute(
                    "DELETE FROM dvarapala.traffic_history WHERE ctid = ANY(ARRAY( \
                     SELECT ctid FROM dvarapala.traffic_history \
                     WHERE cluster = $1 AND minute < $2 LIMIT $3))",
                    &[
                        &cluster,
                        &(before_ms.min(i64::MAX as u64) as i64),
                        &SWEEP_ROWS,
                    ],
                )
                .await
                .map_err(pg)?
            } else {
                0
            };
            tx.commit().await.map_err(pg)?;
            Ok(n)
        }
        .await;
        self.drop_on_error(result)
    }

    /// A failed call drops the connection; the next one reconnects.
    pub(crate) fn drop_on_error<T>(&mut self, r: Result<T, Error>) -> Result<T, Error> {
        if r.is_err() {
            self.client = None;
        }
        r
    }
}
