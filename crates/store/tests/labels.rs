//! RFC 0024 PostgreSQL cases: label rows, reads over replicas, the export
//! pages, retention and migration 3. Each test gets a database of its own.
#![cfg(feature = "postgres")]

mod common;

use std::time::Duration;

use common::{client, fresh};
use dvarapala_store::{LabelQuery, LabelRow, MIGRATIONS, Postgres, apply, render};

fn store(url: &str) -> Postgres {
    Postgres::new(url, None, true, Duration::from_secs(5)).unwrap()
}

fn label(at_ms: u64, label: &str, trigger: &str) -> LabelRow {
    LabelRow {
        at_ms,
        trigger: trigger.into(),
        route: "login".into(),
        method: "POST".into(),
        path: "/login?user=<redacted>".into(),
        label: label.into(),
        confidence: 0.8413,
        pattern: "many users from one client".into(),
        features: Some(r#"{"error_ratio":0.1,"rate":12.5}"#.into()),
        ..LabelRow::default()
    }
}

const ALL: LabelQuery<'static> = LabelQuery {
    since_ms: 0,
    until_ms: u64::MAX,
    labels: &[],
    triggers: &[],
};

// RFC 0024 case 7: what is written reads back unchanged, features included
#[tokio::test(flavor = "multi_thread")]
async fn a_row_reads_back_unchanged() {
    let Some(url) = fresh().await else { return };
    let mut s = store(&url);
    let mut want = label(1_000, "scanner", "waf");
    let mut bare = label(2_000, "benign", "attack");
    bare.features = None;
    bare.route = String::new();
    s.labels_write("c", "a", &[want.clone(), bare.clone()])
        .await
        .unwrap();
    let got = s.labels_page("c", &ALL, None, 10).await.unwrap();
    assert_eq!(got.len(), 2);
    (want.id, bare.id) = (got[0].id, got[1].id);
    // jsonb normalizes the text, not the values
    let features = got[0].features.clone().unwrap();
    assert!(features.contains("\"rate\": 12.5"), "{features}");
    let (mut a, mut b) = (got[0].clone(), want.clone());
    a.features = None;
    b.features = None;
    assert_eq!(a, b);
    assert_eq!(got[1], bare);
}

// RFC 0024 cases 8 and 9
#[tokio::test(flavor = "multi_thread")]
async fn reads_merge_the_replicas_of_one_cluster() {
    let Some(url) = fresh().await else { return };
    let (mut a, mut b) = (store(&url), store(&url));
    a.labels_write(
        "c",
        "a",
        &[
            label(1_000, "scanner", "waf"),
            label(3_000, "flood", "attack"),
        ],
    )
    .await
    .unwrap();
    b.labels_write("c", "b", &[label(2_000, "scanner", "waf")])
        .await
        .unwrap();
    a.labels_write("other", "a", &[label(4_000, "spam", "waf")])
        .await
        .unwrap();
    let (ca, ra) = a.labels_read("c", 0, 200).await.unwrap();
    let (cb, rb) = b.labels_read("c", 0, 200).await.unwrap();
    assert_eq!((&ca, &ra), (&cb, &rb));
    assert_eq!(
        ca,
        [
            ("flood".into(), "attack".into(), 1),
            ("scanner".into(), "waf".into(), 2)
        ]
    );
    let at: Vec<u64> = ra.iter().map(|r| r.at_ms).collect();
    assert_eq!(at, [3_000, 2_000, 1_000]);
    // counts start at `since`, recent is bounded
    let (c, r) = a.labels_read("c", 2_000, 1).await.unwrap();
    assert_eq!(c.iter().map(|x| x.2).sum::<u64>(), 2);
    assert_eq!(r.len(), 1);
}

// RFC 0024 case 11
#[tokio::test(flavor = "multi_thread")]
async fn retention_deletes_old_rows() {
    let Some(url) = fresh().await else { return };
    let mut s = store(&url);
    let rows: Vec<_> = [1_000, 2_000, 3_000]
        .map(|at| label(at, "scanner", "waf"))
        .to_vec();
    s.labels_write("c", "a", &rows).await.unwrap();
    s.labels_write("other", "a", &rows[..1]).await.unwrap();
    assert_eq!(s.labels_expire("c", 3_000).await.unwrap(), 2);
    let left = s.labels_page("c", &ALL, None, 10).await.unwrap();
    assert_eq!(left.iter().map(|r| r.at_ms).collect::<Vec<_>>(), [3_000]);
    assert_eq!(
        s.labels_page("other", &ALL, None, 10).await.unwrap().len(),
        1
    );
}

// RFC 0024 cases 5 and 12: filters, and 10 000 rows in pages that end
#[tokio::test(flavor = "multi_thread")]
async fn pages_cover_the_range_once() {
    let Some(url) = fresh().await else { return };
    let mut s = store(&url);
    for chunk in 0..100u64 {
        // equal timestamps across a page edge: the id breaks the tie
        let rows: Vec<_> = (0..100)
            .map(|i| label(chunk * 10 + i % 10, "scanner", "waf"))
            .collect();
        s.labels_write("c", "a", &rows).await.unwrap();
    }
    let (mut after, mut n) = (None, 0);
    loop {
        let page = s.labels_page("c", &ALL, after, 1_000).await.unwrap();
        let Some(last) = page.last() else { break };
        after = Some((last.at_ms, last.id));
        n += page.len();
    }
    assert_eq!(n, 10_000);
    s.labels_write(
        "c",
        "a",
        &[label(5, "flood", "attack"), label(6, "spam", "route")],
    )
    .await
    .unwrap();
    let (labels, triggers) = (["flood".into(), "spam".into()], ["attack".into()]);
    let q = LabelQuery {
        since_ms: 5,
        until_ms: 5,
        labels: &labels,
        triggers: &triggers,
    };
    let page = s.labels_page("c", &q, None, 10).await.unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].label, "flood");
}

// RFC 0024 case 15
#[tokio::test(flavor = "multi_thread")]
async fn version_2_migrates_to_the_label_table() {
    let Some(url) = fresh().await else { return };
    let mut c = client(&url).await;
    assert_eq!(apply(&mut c, &MIGRATIONS[..2]).await.unwrap(), 2);
    store(&url).labels_read("c", 0, 1).await.unwrap();
    let v: i32 = c
        .query_one("SELECT max(version) FROM dvarapala.schema_version", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(v, 3);
    assert!(render(2).starts_with("-- dvarapala schema version 3\n"));
    assert!(render(2).contains("dvarapala.llm_labels"));
}
