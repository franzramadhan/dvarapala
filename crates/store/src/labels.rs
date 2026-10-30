//! RFC 0024: LLM labels (RFC 0023) in PostgreSQL, one row per model answer
//! in `dvarapala.llm_labels`.

use tokio_postgres::Row;

use crate::Error;
use crate::postgres::{Postgres, pg};

/// Rows deleted per sweep at most.
const SWEEP_ROWS: i64 = 10_000;

/// One label as the table holds it.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct LabelRow {
    /// Set by the database; ignored on write.
    pub id: i64,
    pub at_ms: u64,
    pub trigger: String,
    /// `""` without a route.
    pub route: String,
    pub method: String,
    pub path: String,
    pub label: String,
    pub confidence: f64,
    pub pattern: String,
    /// The `[ml]` features as a JSON object, when a model scored.
    pub features: Option<String>,
}

/// An export range: `since` and `until` inclusive, empty lists match all.
#[derive(Debug, Clone, Copy)]
pub struct LabelQuery<'a> {
    pub since_ms: u64,
    pub until_ms: u64,
    pub labels: &'a [String],
    pub triggers: &'a [String],
}

const COLUMNS: &str =
    "id, at, trigger, route, method, path, label, confidence, pattern, features::text";

fn ms(v: u64) -> i64 {
    v.min(i64::MAX as u64) as i64
}

fn row(r: &Row) -> LabelRow {
    LabelRow {
        id: r.get(0),
        at_ms: r.get::<_, i64>(1).max(0) as u64,
        trigger: r.get(2),
        route: r.get(3),
        method: r.get(4),
        path: r.get(5),
        label: r.get(6),
        confidence: r.get(7),
        pattern: r.get(8),
        features: r.get(9),
    }
}

impl Postgres {
    /// Inserts `rows` of this replica in one statement.
    pub async fn labels_write(
        &mut self,
        cluster: &str,
        replica: &str,
        rows: &[LabelRow],
    ) -> Result<(), Error> {
        let text = |f: fn(&LabelRow) -> &str| rows.iter().map(f).collect::<Vec<_>>();
        let at: Vec<i64> = rows.iter().map(|r| ms(r.at_ms)).collect();
        let confidence: Vec<f64> = rows.iter().map(|r| r.confidence).collect();
        let features: Vec<Option<&str>> = rows.iter().map(|r| r.features.as_deref()).collect();
        let (trigger, route, method) = (
            text(|r| &r.trigger),
            text(|r| &r.route),
            text(|r| &r.method),
        );
        let (path, label, pattern) = (text(|r| &r.path), text(|r| &r.label), text(|r| &r.pattern));
        let result = async {
            let client = self.client().await?;
            client
                .execute(
                    "INSERT INTO dvarapala.llm_labels (cluster, replica, at, trigger, route, \
                     method, path, label, confidence, pattern, features) \
                     SELECT $1, $2, u.at, u.trigger, u.route, u.method, u.path, u.label, \
                     u.confidence, u.pattern, u.features::jsonb \
                     FROM unnest($3::bigint[], $4::text[], $5::text[], $6::text[], $7::text[], \
                     $8::text[], $9::float8[], $10::text[], $11::text[]) \
                     AS u(at, trigger, route, method, path, label, confidence, pattern, features)",
                    &[
                        &cluster,
                        &replica,
                        &at,
                        &trigger,
                        &route,
                        &method,
                        &path,
                        &label,
                        &confidence,
                        &pattern,
                        &features,
                    ],
                )
                .await
                .map_err(pg)
        }
        .await;
        self.drop_on_error(result).map(drop)
    }

    /// The counts per label and trigger at or after `since_ms`, and the
    /// last `recent` rows, newest first, over the replicas of `cluster`.
    pub async fn labels_read(
        &mut self,
        cluster: &str,
        since_ms: u64,
        recent: i64,
    ) -> Result<(Vec<(String, String, u64)>, Vec<LabelRow>), Error> {
        let result = async {
            let client = self.client().await?;
            let counts = client
                .query(
                    "SELECT label, trigger, count(*) FROM dvarapala.llm_labels \
                     WHERE cluster = $1 AND at >= $2 GROUP BY 1, 2 ORDER BY 1, 2",
                    &[&cluster, &ms(since_ms)],
                )
                .await
                .map_err(pg)?;
            let rows = client
                .query(
                    &format!(
                        "SELECT {COLUMNS} FROM dvarapala.llm_labels WHERE cluster = $1 \
                         ORDER BY at DESC, id DESC LIMIT $2"
                    ),
                    &[&cluster, &recent],
                )
                .await
                .map_err(pg)?;
            Ok((counts, rows))
        }
        .await;
        let (counts, rows) = self.drop_on_error(result)?;
        Ok((
            counts
                .iter()
                .map(|r| (r.get(0), r.get(1), r.get::<_, i64>(2).max(0) as u64))
                .collect(),
            rows.iter().map(row).collect(),
        ))
    }

    /// Up to `limit` rows of `q` after `after` (the last row's `(at_ms,
    /// id)`, `None` for the first page), oldest first.
    pub async fn labels_page(
        &mut self,
        cluster: &str,
        q: &LabelQuery<'_>,
        after: Option<(u64, i64)>,
        limit: i64,
    ) -> Result<Vec<LabelRow>, Error> {
        // ids start at 1: (since, 0) takes the rows at `since` too
        let (at, id) = after.unwrap_or((q.since_ms, 0));
        let result = async {
            let client = self.client().await?;
            client
                .query(
                    &format!(
                        "SELECT {COLUMNS} FROM dvarapala.llm_labels \
                         WHERE cluster = $1 AND (at, id) > ($2, $3) AND at <= $4 \
                         AND (cardinality($5::text[]) = 0 OR label = ANY($5)) \
                         AND (cardinality($6::text[]) = 0 OR trigger = ANY($6)) \
                         ORDER BY at, id LIMIT $7"
                    ),
                    &[
                        &cluster,
                        &ms(at),
                        &id,
                        &ms(q.until_ms),
                        &q.labels,
                        &q.triggers,
                        &limit,
                    ],
                )
                .await
                .map_err(pg)
        }
        .await;
        Ok(self.drop_on_error(result)?.iter().map(row).collect())
    }

    /// Deletes rows of `cluster` before `before_ms` when no other replica
    /// is doing it; the number deleted.
    pub async fn labels_expire(&mut self, cluster: &str, before_ms: u64) -> Result<u64, Error> {
        let result = async {
            let client = self.client().await?;
            let tx = client.transaction().await.map_err(pg)?;
            let locked: bool = tx
                .query_one(
                    "SELECT pg_try_advisory_xact_lock(hashtext('dvarapala.llm_labels'))",
                    &[],
                )
                .await
                .map_err(pg)?
                .get(0);
            let n = if locked {
                tx.execute(
                    "DELETE FROM dvarapala.llm_labels WHERE ctid = ANY(ARRAY( \
                     SELECT ctid FROM dvarapala.llm_labels \
                     WHERE cluster = $1 AND at < $2 LIMIT $3))",
                    &[&cluster, &ms(before_ms), &SWEEP_ROWS],
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
}
