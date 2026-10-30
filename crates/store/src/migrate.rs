//! PostgreSQL schema versions (RFC 0010). A released file is never edited:
//! a change is a new file.

/// One schema version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Migration {
    pub version: u32,
    pub sql: &'static str,
}

pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        sql: include_str!("../migrations/0001.sql"),
    },
    Migration {
        version: 2,
        sql: include_str!("../migrations/0002.sql"),
    },
    Migration {
        version: 3,
        sql: include_str!("../migrations/0003.sql"),
    },
];

/// The schema version this binary needs.
pub const LATEST: u32 = MIGRATIONS[MIGRATIONS.len() - 1].version;

/// The SQL that takes a database from version `from` to [`LATEST`], one
/// transaction per migration with its `schema_version` row, for
/// `dvarapala store schema` and hand-run migrations.
pub fn render(from: u32) -> String {
    MIGRATIONS
        .iter()
        .filter(|m| m.version > from)
        .map(|m| {
            format!(
                "-- dvarapala schema version {v}\nBEGIN;\n{sql}\nINSERT INTO dvarapala.schema_version (version) VALUES ({v});\nCOMMIT;\n",
                v = m.version,
                sql = m.sql.trim_end()
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(feature = "postgres")]
mod apply {
    use tokio_postgres::GenericClient;

    use super::Migration;
    use crate::Error;

    fn pg(e: tokio_postgres::Error) -> Error {
        match e.as_db_error() {
            // the message only, never the detail: it can hold row values
            Some(d) => Error(format!("postgres: {} ({})", d.message(), d.code().code())),
            None => Error(format!("postgres: {e}")),
        }
    }

    /// The schema version of the database, 0 when there is none.
    pub async fn version(client: &impl GenericClient) -> Result<u32, Error> {
        // two queries: a missing table fails at parse time, even in a CASE
        let exists: bool = client
            .query_one(
                "SELECT to_regclass('dvarapala.schema_version') IS NOT NULL",
                &[],
            )
            .await
            .map_err(pg)?
            .get(0);
        if !exists {
            return Ok(0);
        }
        let row = client
            .query_one(
                "SELECT coalesce(max(version), 0) FROM dvarapala.schema_version",
                &[],
            )
            .await
            .map_err(pg)?;
        Ok(row.get::<_, i32>(0) as u32)
    }

    /// Applies the missing migrations of `list` in order, each in its own
    /// transaction under an advisory lock, so replicas starting together
    /// migrate once. Transaction-scoped locks work through PgBouncer in
    /// transaction mode. Returns the final version; a database newer than
    /// `list` is an error and nothing runs.
    pub async fn apply(
        client: &mut tokio_postgres::Client,
        list: &[Migration],
    ) -> Result<u32, Error> {
        let latest = list.last().map_or(0, |m| m.version);
        loop {
            let tx = client.transaction().await.map_err(pg)?;
            tx.execute(
                "SELECT pg_advisory_xact_lock(hashtext('dvarapala.migrate'))",
                &[],
            )
            .await
            .map_err(pg)?;
            let v = version(&tx).await?;
            if v > latest {
                return Err(Error(format!(
                    "schema version {v} is newer than this binary's {latest}"
                )));
            }
            let Some(m) = list.iter().find(|m| m.version > v) else {
                return Ok(v);
            };
            tx.batch_execute(m.sql).await.map_err(pg)?;
            tx.execute(
                "INSERT INTO dvarapala.schema_version (version) VALUES ($1)",
                &[&(m.version as i32)],
            )
            .await
            .map_err(pg)?;
            tx.commit().await.map_err(pg)?;
            tracing::info!(msg = "store schema migrated", version = m.version);
        }
    }
}

#[cfg(feature = "postgres")]
pub use apply::{apply, version};

#[cfg(test)]
mod tests {
    use super::*;

    /// FNV-1a: stable across Rust versions, unlike `DefaultHasher`.
    fn fnv(s: &str) -> u64 {
        s.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| {
            (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
        })
    }

    // RFC 0010 case 21: append a line here with each new migration, never
    // change one
    const RELEASED: &[(u32, u64)] = &[(1, 0xb50c0e7f96ea4f9e), (2, 0xccbac390fad33a75)];

    #[test]
    fn released_migrations_never_change() {
        for &(v, sum) in RELEASED {
            let m = MIGRATIONS.iter().find(|m| m.version == v).unwrap();
            assert_eq!(fnv(m.sql), sum, "migration {v} changed after release");
        }
    }

    #[test]
    fn versions_count_up_from_one() {
        for (i, m) in MIGRATIONS.iter().enumerate() {
            assert_eq!(m.version as usize, i + 1);
        }
    }

    #[test]
    fn render_starts_after_from() {
        assert!(render(0).contains("VALUES (1);"));
        assert_eq!(render(LATEST), "");
    }
}
