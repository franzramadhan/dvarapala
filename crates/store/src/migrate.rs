//! PostgreSQL schema versions (RFC 0010). A released file is never edited:
//! a change is a new file.
#![allow(unused_variables, unused_imports, unused_mut, dead_code)]

/// One schema version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Migration {
    pub version: u32,
    pub sql: &'static str,
}

pub const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    sql: include_str!("../migrations/0001.sql"),
}];

/// The schema version this binary needs.
pub const LATEST: u32 = MIGRATIONS[MIGRATIONS.len() - 1].version;

/// The SQL that takes a database from version `from` to [`LATEST`], one
/// transaction per migration with its `schema_version` row, for
/// `dvarapala store schema` and hand-run migrations.
pub fn render(from: u32) -> String {
    todo!("rfc 0010")
}

#[cfg(feature = "postgres")]
mod apply {
    use tokio_postgres::GenericClient;

    use super::Migration;
    use crate::Error;

    fn pg(e: tokio_postgres::Error) -> Error {
        todo!("rfc 0010")
    }

    /// The schema version of the database, 0 when there is none.
    pub async fn version(client: &impl GenericClient) -> Result<u32, Error> {
        todo!("rfc 0010")
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
        todo!("rfc 0010")
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
    const RELEASED: &[(u32, u64)] = &[(1, 0xb50c0e7f96ea4f9e)];

    #[test]
    #[ignore = "rfc 0010"]
    fn released_migrations_never_change() {
        for &(v, sum) in RELEASED {
            let m = MIGRATIONS.iter().find(|m| m.version == v).unwrap();
            assert_eq!(fnv(m.sql), sum, "migration {v} changed after release");
        }
    }

    #[test]
    #[ignore = "rfc 0010"]
    fn versions_count_up_from_one() {
        for (i, m) in MIGRATIONS.iter().enumerate() {
            assert_eq!(m.version as usize, i + 1);
        }
    }

    #[test]
    #[ignore = "rfc 0010"]
    fn render_starts_after_from() {
        assert!(render(0).contains("VALUES (1);"));
        assert_eq!(render(LATEST), "");
    }
}
