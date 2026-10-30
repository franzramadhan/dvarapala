//! RFC 0024: labels as rows in the PostgreSQL store. A bounded queue feeds
//! one writer, one batch in flight; `GET /llm`, the export and the hourly
//! retention sweep share its connection. Failures fail open: logged once,
//! counted, and labeling goes on in memory.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dvarapala_l7::ExportQuery;
use dvarapala_store::{Error, LabelQuery, LabelRow};
use tokio::sync::mpsc;

use super::labels::export_line;
use crate::admin::history::{Db, connect};
use crate::config::Config;

/// Rows per insert at most.
const BATCH: usize = 100;
/// A batch waits at most this long after its first row.
const FLUSH: Duration = Duration::from_secs(5);
const SWEEP: Duration = Duration::from_secs(3600);
/// `GET /llm`: the counts over this, and the recent rows.
const COUNTS: Duration = Duration::from_secs(24 * 3600);
const RECENT: i64 = 200;
/// Rows per export page, read under the lock, then sent.
const PAGE: i64 = 1000;

pub struct Persist {
    tx: mpsc::Sender<LabelRow>,
    db: Db,
    cluster: String,
    timeout: Duration,
    retention_secs: AtomicU64,
    down: AtomicBool,
}

/// What `GET /llm` reads: counts per label and trigger, recent rows.
pub type Read = (Vec<(String, String, u64)>, Vec<LabelRow>);

impl Persist {
    /// Connects lazily and starts the writer and the sweep.
    pub fn start(cfg: &Config) -> Result<Arc<Self>, String> {
        let (db, cluster, timeout) = connect(cfg, "ml.llm.persist")?;
        let (tx, mut rx) = mpsc::channel(cfg.ml.llm.persist_queue);
        let me = Arc::new(Self {
            tx,
            db,
            cluster,
            timeout,
            retention_secs: AtomicU64::new(cfg.ml.llm.retention.as_secs()),
            down: AtomicBool::new(false),
        });
        let w = me.clone();
        tokio::spawn(async move {
            while let Some(rows) = batch(&mut rx).await {
                let r = w.write(&rows).await;
                let result = if r.is_ok() { "ok" } else { "error" };
                ::metrics::counter!("dvarapala_llm_store_rows_total", "result" => result)
                    .increment(rows.len() as u64);
                w.health(r.err().as_ref());
            }
        });
        let s = me.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(SWEEP);
            loop {
                tick.tick().await;
                let keep = s.retention_secs.load(Ordering::Relaxed) * 1000;
                let r = s.expire(now_ms().saturating_sub(keep)).await;
                if let Ok(n) = r {
                    ::metrics::counter!("dvarapala_llm_store_rows_deleted_total").increment(n);
                }
                s.health(r.err().as_ref());
            }
        });
        Ok(me)
    }

    /// Queues a row for the writer; a full queue drops it.
    pub fn push(&self, row: LabelRow) {
        push(&self.tx, row);
    }

    /// `ml.llm.retention` after a reload.
    pub fn set_retention(&self, d: Duration) {
        self.retention_secs.store(d.as_secs(), Ordering::Relaxed);
    }

    /// The cluster's counts over the last 24 h and its recent rows;
    /// `None` on a failure.
    pub async fn read(&self) -> Option<Read> {
        let since = now_ms().saturating_sub(COUNTS.as_millis() as u64);
        let r = async {
            let mut pg = self.lock().await?;
            timed(self.timeout, pg.labels_read(&self.cluster, since, RECENT)).await
        }
        .await;
        self.health(r.as_ref().err());
        r.ok()
    }

    /// The rows of `q` as JSON lines, a page per message; an error ends it.
    pub fn export(self: &Arc<Self>, q: ExportQuery) -> mpsc::Receiver<Result<String, Error>> {
        let (tx, rx) = mpsc::channel(2);
        let me = self.clone();
        tokio::spawn(async move {
            let lq = LabelQuery {
                since_ms: q.since_ms,
                until_ms: q.until_ms,
                labels: &q.labels,
                triggers: &q.triggers,
            };
            let mut after = None;
            loop {
                let page = async {
                    let mut pg = me.lock().await?;
                    timed(me.timeout, pg.labels_page(&me.cluster, &lq, after, PAGE)).await
                }
                .await;
                let page = match page {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!(msg = "llm export failed", error = %e);
                        let _ = tx.send(Err(e)).await;
                        return;
                    }
                };
                let Some(last) = page.last() else { return };
                after = Some((last.at_ms, last.id));
                let chunk: String = page.iter().map(|r| export_line(r) + "\n").collect();
                ::metrics::counter!("dvarapala_llm_export_rows_total").increment(page.len() as u64);
                // a closed receiver: the client went away
                if tx.send(Ok(chunk)).await.is_err() || page.len() < PAGE as usize {
                    return;
                }
            }
        });
        rx
    }

    async fn write(&self, rows: &[LabelRow]) -> Result<(), Error> {
        let mut pg = self.lock().await?;
        let replica = crate::store::replica();
        timed(self.timeout, pg.labels_write(&self.cluster, replica, rows)).await
    }

    async fn expire(&self, before_ms: u64) -> Result<u64, Error> {
        let mut pg = self.lock().await?;
        timed(self.timeout, pg.labels_expire(&self.cluster, before_ms)).await
    }

    async fn lock(&self) -> Result<tokio::sync::MutexGuard<'_, dvarapala_store::Postgres>, Error> {
        tokio::time::timeout(self.timeout, self.db.lock())
            .await
            .map_err(|_| Error("busy".into()))
    }

    /// Logs the first failure of an outage and the recovery.
    fn health(&self, e: Option<&Error>) {
        match e {
            Some(e) if !self.down.swap(true, Ordering::Relaxed) => {
                tracing::warn!(msg = "llm store unavailable", error = %e);
            }
            None if self.down.swap(false, Ordering::Relaxed) => {
                tracing::info!(msg = "llm store recovered");
            }
            _ => {}
        }
    }
}

async fn timed<T>(t: Duration, f: impl Future<Output = Result<T, Error>>) -> Result<T, Error> {
    tokio::time::timeout(t, f)
        .await
        .map_err(|_| Error("timed out".into()))?
}

/// `false` and counted when the queue is full.
fn push(tx: &mpsc::Sender<LabelRow>, row: LabelRow) -> bool {
    let ok = tx.try_send(row).is_ok();
    if !ok {
        ::metrics::counter!("dvarapala_llm_store_rows_total", "result" => "dropped").increment(1);
    }
    ok
}

/// Up to [`BATCH`] rows, waiting at most [`FLUSH`] after the first; `None`
/// once the queue is closed and empty.
async fn batch(rx: &mut mpsc::Receiver<LabelRow>) -> Option<Vec<LabelRow>> {
    let mut rows = Vec::with_capacity(BATCH);
    if rx.recv_many(&mut rows, BATCH).await == 0 {
        return None;
    }
    let end = tokio::time::Instant::now() + FLUSH;
    while rows.len() < BATCH {
        let room = BATCH - rows.len();
        let more = tokio::time::timeout_at(end, rx.recv_many(&mut rows, room));
        if !matches!(more.await, Ok(n) if n > 0) {
            break;
        }
    }
    Some(rows)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(at_ms: u64) -> LabelRow {
        LabelRow {
            at_ms,
            ..LabelRow::default()
        }
    }

    // RFC 0024 case 3
    #[test]
    fn a_full_queue_drops_new_rows() {
        let (tx, mut rx) = mpsc::channel(2);
        let pushed: Vec<bool> = (0..3).map(|i| push(&tx, row(i))).collect();
        assert_eq!(pushed, [true, true, false]);
        assert_eq!(rx.try_recv().unwrap().at_ms, 0);
        assert_eq!(rx.try_recv().unwrap().at_ms, 1);
        assert!(rx.try_recv().is_err());
    }

    // RFC 0024 case 4
    #[tokio::test]
    async fn batches_of_a_hundred_in_order() {
        let (tx, mut rx) = mpsc::channel(1024);
        for i in 0..250 {
            assert!(push(&tx, row(i)));
        }
        drop(tx);
        let mut sizes = Vec::new();
        let mut at = Vec::new();
        while let Some(b) = batch(&mut rx).await {
            sizes.push(b.len());
            at.extend(b.iter().map(|r| r.at_ms));
        }
        assert_eq!(sizes, [100, 100, 50]);
        assert_eq!(at, (0..250).collect::<Vec<_>>());
    }
}
