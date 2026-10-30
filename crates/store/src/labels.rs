//! RFC 0024: LLM labels (RFC 0023) in PostgreSQL, one row per model answer
//! in `dvarapala.llm_labels`.
#![allow(unused_variables, unused_imports, dead_code)]

use crate::Error;
use crate::postgres::{Postgres, pg};

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

impl Postgres {
    /// Inserts `rows` of this replica in one statement.
    pub async fn labels_write(
        &mut self,
        cluster: &str,
        replica: &str,
        rows: &[LabelRow],
    ) -> Result<(), Error> {
        todo!("rfc 0024")
    }

    /// The counts per label and trigger at or after `since_ms`, and the
    /// last `recent` rows, newest first, over the replicas of `cluster`.
    pub async fn labels_read(
        &mut self,
        cluster: &str,
        since_ms: u64,
        recent: i64,
    ) -> Result<(Vec<(String, String, u64)>, Vec<LabelRow>), Error> {
        todo!("rfc 0024")
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
        todo!("rfc 0024")
    }

    /// Deletes rows of `cluster` before `before_ms` when no other replica
    /// is doing it; the number deleted.
    pub async fn labels_expire(&mut self, cluster: &str, before_ms: u64) -> Result<u64, Error> {
        todo!("rfc 0024")
    }
}
