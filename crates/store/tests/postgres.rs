//! RFC 0010 PostgreSQL cases: migrations, the hand-run schema and the
//! expiry sweep. Each test gets a database of its own.
#![cfg(feature = "postgres")]

mod common;

use std::time::Duration;

use dvarapala_engine::Batch;
use dvarapala_store::{LATEST, MIGRATIONS, Migration, Postgres, Round, Store, apply, render};
use tokio_postgres::{Client, NoTls};

async fn client(url: &str) -> Client {
    let (c, conn) = tokio_postgres::connect(url, NoTls).await.unwrap();
    tokio::spawn(conn);
    c
}

/// A new empty database next to the one in `DVARAPALA_TEST_POSTGRES`.
async fn fresh() -> Option<String> {
    let url = common::url("DVARAPALA_TEST_POSTGRES")?;
    let name = common::unique("t");
    client(&url)
        .await
        .batch_execute(&format!("CREATE DATABASE {name}"))
        .await
        .unwrap();
    let rest = url.split("://").nth(1).unwrap();
    let path = rest.find('/').unwrap();
    let query = rest.find('?').map_or("", |q| &rest[q..]);
    Some(format!("postgres://{}/{name}{query}", &rest[..path]))
}

fn store(url: &str, migrate: bool) -> Postgres {
    Postgres::new(url, None, migrate, Duration::from_secs(2)).unwrap()
}

async fn round(s: &mut Postgres) -> Result<(), dvarapala_store::Error> {
    let batch = Batch::default();
    s.round(&Round {
        cluster: "c",
        replica: "r",
        heartbeat: Duration::from_secs(1),
        window: Duration::from_secs(1),
        max_list: 10,
        batch: &batch,
    })
    .await
    .map(drop)
}

async fn versions(c: &Client) -> Vec<i32> {
    c.query(
        "SELECT version FROM dvarapala.schema_version ORDER BY 1",
        &[],
    )
    .await
    .unwrap()
    .iter()
    .map(|r| r.get(0))
    .collect()
}

/// Every column of the `dvarapala` schema, to compare two databases.
async fn columns(c: &Client) -> Vec<String> {
    c.query(
        "SELECT table_name || '.' || column_name || ' ' || data_type \
         FROM information_schema.columns WHERE table_schema = 'dvarapala' ORDER BY 1",
        &[],
    )
    .await
    .unwrap()
    .iter()
    .map(|r| r.get(0))
    .collect()
}

// case 16
#[tokio::test(flavor = "multi_thread")]
async fn replicas_starting_together_migrate_once() {
    let Some(url) = fresh().await else { return };
    let (mut a, mut b) = (store(&url, true), store(&url, true));
    let (ra, rb) = tokio::join!(round(&mut a), round(&mut b));
    ra.unwrap();
    rb.unwrap();
    let want: Vec<i32> = (1..=LATEST as i32).collect();
    assert_eq!(versions(&client(&url).await).await, want);
}

// case 17
#[tokio::test(flavor = "multi_thread")]
async fn without_migrate_a_missing_schema_fails_open() {
    let Some(url) = fresh().await else { return };
    let e = round(&mut store(&url, false)).await.unwrap_err();
    assert!(
        e.0.contains(&format!("schema version 0, this binary needs {LATEST}")),
        "{e}"
    );
    // and once migrated, the same replica works
    round(&mut store(&url, true)).await.unwrap();
    round(&mut store(&url, false)).await.unwrap();
}

// case 18
#[tokio::test(flavor = "multi_thread")]
async fn only_the_missing_migration_runs() {
    let Some(url) = fresh().await else { return };
    let mut c = client(&url).await;
    assert_eq!(apply(&mut c, &MIGRATIONS[..1]).await.unwrap(), 1);
    let next = Migration {
        version: 2,
        sql: "CREATE TABLE dvarapala.second (x int)",
    };
    let list = [MIGRATIONS[0], next];
    assert_eq!(apply(&mut c, &list).await.unwrap(), 2);
    assert_eq!(versions(&c).await, vec![1, 2]);
    assert_eq!(
        apply(&mut c, &list).await.unwrap(),
        2,
        "a no-op the second time"
    );
}

// case 19
#[tokio::test(flavor = "multi_thread")]
async fn a_newer_database_is_refused() {
    let Some(url) = fresh().await else { return };
    let mut c = client(&url).await;
    apply(&mut c, MIGRATIONS).await.unwrap();
    c.execute(
        "INSERT INTO dvarapala.schema_version (version) VALUES (99)",
        &[],
    )
    .await
    .unwrap();
    let e = round(&mut store(&url, true)).await.unwrap_err();
    assert!(
        e.0.contains(&format!(
            "schema version 99 is newer than this binary's {LATEST}"
        )),
        "{e}"
    );
    let e = round(&mut store(&url, false)).await.unwrap_err();
    assert!(e.0.contains("schema version 99"), "{e}");
}

// case 20
#[tokio::test(flavor = "multi_thread")]
async fn rendered_schema_matches_migrate() {
    let (Some(by_hand), Some(by_migrate)) = (fresh().await, fresh().await) else {
        return;
    };
    let hand = client(&by_hand).await;
    hand.batch_execute(&render(0)).await.unwrap();
    round(&mut store(&by_migrate, true)).await.unwrap();
    let migrated = client(&by_migrate).await;
    assert_eq!(columns(&hand).await, columns(&migrated).await);
    assert_eq!(versions(&hand).await, versions(&migrated).await);
    // a replica without DDL rights runs on the hand-made schema
    round(&mut store(&by_hand, false)).await.unwrap();
}

// case 22
#[tokio::test(flavor = "multi_thread")]
async fn sweep_deletes_expired_rows_on_one_replica() {
    let Some(url) = fresh().await else { return };
    let mut s = store(&url, true);
    round(&mut s).await.unwrap();
    let c = client(&url).await;
    c.batch_execute(
        "INSERT INTO dvarapala.counters VALUES \
           ('c', 'old', 0, 1, now() - interval '1 second'), \
           ('c', 'new', 0, 1, now() + interval '1 hour')",
    )
    .await
    .unwrap();
    let count = async || -> i64 {
        c.query_one("SELECT count(*) FROM dvarapala.counters", &[])
            .await
            .unwrap()
            .get(0)
    };
    // another replica holds the sweep lock: nothing is deleted
    let mut other = client(&url).await;
    let tx = other.transaction().await.unwrap();
    tx.execute(
        "SELECT pg_advisory_xact_lock(hashtext('dvarapala.sweep'))",
        &[],
    )
    .await
    .unwrap();
    s.sweep_now().await.unwrap();
    assert_eq!(count().await, 2);
    tx.rollback().await.unwrap();
    s.sweep_now().await.unwrap();
    assert_eq!(count().await, 1);
}

// the first round after a start does not sweep: a new replica waits on it,
// and the rows other clusters left can take longer than the timeout
#[tokio::test(flavor = "multi_thread")]
async fn first_round_does_not_sweep() {
    let Some(url) = fresh().await else { return };
    let mut s = store(&url, true);
    s.connect().await.unwrap();
    let c = client(&url).await;
    c.batch_execute(
        "INSERT INTO dvarapala.counters VALUES ('c', 'old', 0, 1, now() - interval '1 second')",
    )
    .await
    .unwrap();
    let count = async || -> i64 {
        c.query_one("SELECT count(*) FROM dvarapala.counters", &[])
            .await
            .unwrap()
            .get(0)
    };
    round(&mut s).await.unwrap();
    assert_eq!(count().await, 1);
    // a sweep every 10 rounds
    for _ in 1..10 {
        round(&mut s).await.unwrap();
    }
    assert_eq!(count().await, 0);
}

// a broken hand-made schema fails the round with the server's message and
// SQLSTATE, and the next round tries again
#[tokio::test(flavor = "multi_thread")]
async fn a_broken_schema_reports_the_sqlstate() {
    let Some(url) = fresh().await else { return };
    let c = client(&url).await;
    c.batch_execute(&render(0)).await.unwrap();
    c.batch_execute("DROP TABLE dvarapala.marks").await.unwrap();
    let mut s = store(&url, false);
    for _ in 0..2 {
        let e = round(&mut s).await.unwrap_err();
        assert!(e.0.starts_with("postgres: "), "{e}");
        assert!(e.0.ends_with("(42P01)"), "{e}");
    }
}

// rows another writer left that this binary does not know are skipped
#[tokio::test(flavor = "multi_thread")]
async fn unknown_marks_are_skipped() {
    let Some(url) = fresh().await else { return };
    let mut s = store(&url, true);
    round(&mut s).await.unwrap();
    client(&url)
        .await
        .batch_execute(
            "INSERT INTO dvarapala.marks (cluster, kind, key, expires_at) VALUES \
               ('c', 'heavy', '192.0.2.0/24', now() + interval '1 hour'), \
               ('c', 'heavy', 'not a network', now() + interval '1 hour'), \
               ('c', 'other', 'x', now() + interval '1 hour'), \
               ('c', 'pause', 'p', now() + interval '1 hour')",
        )
        .await
        .unwrap();
    let batch = Batch::default();
    let reply = s
        .round(&Round {
            cluster: "c",
            replica: "r",
            heartbeat: Duration::from_secs(1),
            window: Duration::from_secs(1),
            max_list: 10,
            batch: &batch,
        })
        .await
        .unwrap();
    let heavy: Vec<String> = reply.heavy.iter().map(|(n, _)| n.to_string()).collect();
    assert_eq!(heavy, ["192.0.2.0/24"]);
    let pauses: Vec<&str> = reply.pauses.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(pauses, ["p"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_migration_reports_the_error() {
    let Some(url) = fresh().await else { return };
    let mut c = client(&url).await;
    let bad = Migration {
        version: 1,
        sql: "CREATE TABL dvarapala.x (x int)",
    };
    let e = apply(&mut c, &[bad]).await.unwrap_err();
    assert!(e.0.ends_with("(42601)"), "{e}");
    assert_eq!(versions_or_none(&c).await, None, "rolled back");
    // a lost connection is an error too, without a SQLSTATE
    let (mut gone, conn) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    drop(conn);
    let e = apply(&mut gone, MIGRATIONS).await.unwrap_err();
    assert!(e.0.starts_with("postgres: "), "{e}");
    assert!(!e.0.ends_with(')'), "{e}");
}

async fn versions_or_none(c: &Client) -> Option<Vec<i32>> {
    let exists: bool = c
        .query_one(
            "SELECT to_regclass('dvarapala.schema_version') IS NOT NULL",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    if exists {
        Some(versions(c).await)
    } else {
        None
    }
}

fn minute(minute_ms: u64, allow: u64) -> dvarapala_engine::Minute {
    dvarapala_engine::Minute {
        minute_ms,
        counts: [allow, 1, 0, 0, 0],
    }
}

// RFC 0022 case 10
#[tokio::test(flavor = "multi_thread")]
async fn history_sums_the_replicas_per_minute() {
    let Some(url) = fresh().await else { return };
    let (mut a, mut b) = (store(&url, true), store(&url, true));
    a.history_write("c", "a", &minute(60_000, 10))
        .await
        .unwrap();
    b.history_write("c", "b", &minute(60_000, 5)).await.unwrap();
    a.history_write("c", "a", &minute(120_000, 7))
        .await
        .unwrap();
    // a second write of a minute adds up, another cluster stays apart
    a.history_write("c", "a", &minute(120_000, 1))
        .await
        .unwrap();
    a.history_write("other", "a", &minute(60_000, 99))
        .await
        .unwrap();
    let rows = a.history_read("c", 0).await.unwrap();
    assert_eq!(
        rows,
        [
            dvarapala_engine::Minute {
                minute_ms: 60_000,
                counts: [15, 2, 0, 0, 0]
            },
            dvarapala_engine::Minute {
                minute_ms: 120_000,
                counts: [8, 2, 0, 0, 0]
            },
        ]
    );
    assert_eq!(a.history_read("c", 120_000).await.unwrap().len(), 1);
}

// RFC 0022 case 12
#[tokio::test(flavor = "multi_thread")]
async fn history_retention_deletes_old_rows() {
    let Some(url) = fresh().await else { return };
    let mut s = store(&url, true);
    for m in [60_000, 120_000, 180_000] {
        s.history_write("c", "a", &minute(m, 1)).await.unwrap();
    }
    s.history_write("other", "a", &minute(60_000, 1))
        .await
        .unwrap();
    assert_eq!(s.history_expire("c", 180_000).await.unwrap(), 2);
    let left: Vec<u64> = s
        .history_read("c", 0)
        .await
        .unwrap()
        .iter()
        .map(|m| m.minute_ms)
        .collect();
    assert_eq!(left, [180_000]);
    assert_eq!(s.history_read("other", 0).await.unwrap().len(), 1);
}

// RFC 0022 case 13
#[tokio::test(flavor = "multi_thread")]
async fn version_1_migrates_to_the_history_table() {
    let Some(url) = fresh().await else { return };
    let mut c = client(&url).await;
    assert_eq!(apply(&mut c, &MIGRATIONS[..1]).await.unwrap(), 1);
    round(&mut store(&url, true)).await.unwrap();
    assert_eq!(versions(&c).await, vec![1, 2]);
    assert!(render(1).starts_with("-- dvarapala schema version 2\n"));
    assert!(render(1).contains("dvarapala.traffic_history"));
}
