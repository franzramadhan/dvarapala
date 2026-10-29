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
