use std::collections::HashMap;
use std::time::Duration;

use dvarapala_engine::Reply;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use tokio_postgres::{Client, Config, Transaction};
use tokio_postgres_rustls::MakeRustlsConnect;

use crate::migrate::{LATEST, MIGRATIONS, apply, version};
use crate::{Error, Round, Store};

/// Every this many rounds, one replica deletes expired rows.
const SWEEP_EVERY: u64 = 10;
/// Rows deleted per table and sweep at most.
const SWEEP_ROWS: i64 = 10_000;

/// PostgreSQL backend (RFC 0010): `UNLOGGED` tables in the `dvarapala`
/// schema, one transaction per round, statements prepared inside it so a
/// pooler in transaction mode works.
pub struct Postgres {
    config: Config,
    tls: MakeRustlsConnect,
    migrate: bool,
    timeout: Duration,
    client: Option<Client>,
    rounds: u64,
}

fn pg(e: tokio_postgres::Error) -> Error {
    // the driver's errors carry no URL or password
    match e.as_db_error() {
        // the message only, never the detail: it can hold row values
        Some(d) => Error(format!("postgres: {} ({})", d.message(), d.code().code())),
        None => Error(format!("postgres: {e}")),
    }
}

impl Postgres {
    /// `url` is a libpq URL; TLS unless `sslmode=disable`, verified against
    /// `ca` (PEM) or the system roots. `verify-ca` and `verify-full` mean
    /// `require`, which always verifies here. `migrate` applies missing
    /// schema versions on connect; otherwise the version must match.
    pub fn new(
        url: &str,
        ca: Option<&[u8]>,
        migrate: bool,
        timeout: Duration,
    ) -> Result<Self, Error> {
        let url = url
            .replace("sslmode=verify-full", "sslmode=require")
            .replace("sslmode=verify-ca", "sslmode=require");
        let config: Config = url
            .parse()
            .map_err(|e| Error(format!("store.url is not a PostgreSQL URL: {e}")))?;
        Ok(Self {
            config,
            tls: MakeRustlsConnect::new(tls(ca)?),
            migrate,
            timeout,
            client: None,
            rounds: 0,
        })
    }

    async fn client(&mut self) -> Result<&mut Client, Error> {
        if self.client.as_ref().is_some_and(Client::is_closed) {
            self.client = None;
        }
        if self.client.is_none() {
            let (mut client, conn) = self.config.connect(self.tls.clone()).await.map_err(pg)?;
            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    tracing::debug!(msg = "store connection closed", error = %e);
                }
            });
            let v = if self.migrate {
                apply(&mut client, MIGRATIONS).await?
            } else {
                // inside a transaction: a pooler in transaction mode keeps
                // the prepare and the execute on one server connection
                let tx = client.transaction().await.map_err(pg)?;
                let v = version(&tx).await?;
                tx.commit().await.map_err(pg)?;
                v
            };
            if v != LATEST {
                return Err(Error(format!(
                    "schema version {v}, this binary needs {LATEST} (store.migrate is off)"
                )));
            }
            self.client = Some(client);
        }
        Ok(self.client.as_mut().expect("connected above"))
    }
}

fn tls(ca: Option<&[u8]>) -> Result<ClientConfig, Error> {
    let mut roots = RootCertStore::empty();
    match ca {
        Some(pem) => {
            for cert in CertificateDer::pem_slice_iter(pem) {
                let cert = cert.map_err(|e| Error(format!("store.ca_file: {e}")))?;
                roots
                    .add(cert)
                    .map_err(|e| Error(format!("store.ca_file: {e}")))?;
            }
        }
        None => {
            for cert in rustls_native_certs::load_native_certs().certs {
                let _ = roots.add(cert);
            }
        }
    }
    Ok(ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

impl Store for Postgres {
    async fn connect(&mut self) -> Result<(), Error> {
        self.client().await.map(drop)
    }

    async fn round(&mut self, r: &Round<'_>) -> Result<Reply, Error> {
        // not the first round: a starting replica waits on it
        let sweep = self.rounds % SWEEP_EVERY == SWEEP_EVERY - 1;
        let timeout = self.timeout.as_millis().max(1);
        let result = async {
            let client = self.client().await?;
            let tx = client.transaction().await.map_err(pg)?;
            // a stuck round must not hold row locks past the timeout
            tx.batch_execute(&format!("SET LOCAL statement_timeout = {timeout}"))
                .await
                .map_err(pg)?;
            let reply = round(&tx, r).await?;
            if sweep {
                self::sweep(&tx).await?;
            }
            tx.commit().await.map_err(pg)?;
            Ok(reply)
        }
        .await;
        if result.is_err() {
            self.client = None;
        }
        self.rounds += 1;
        result
    }
}

fn ms(d: Duration) -> i64 {
    d.as_millis().min(i64::MAX as u128) as i64
}

async fn round(tx: &Transaction<'_>, r: &Round<'_>) -> Result<Reply, Error> {
    let c = r.cluster;
    tx.execute(
        "INSERT INTO dvarapala.heartbeats (cluster, replica, expires_at) \
         VALUES ($1, $2, now() + $3 * interval '1 millisecond') \
         ON CONFLICT (cluster, replica) DO UPDATE SET expires_at = EXCLUDED.expires_at",
        &[&c, &r.replica, &(ms(r.heartbeat) as f64)],
    )
    .await
    .map_err(pg)?;
    let replicas: i64 = tx
        .query_one(
            "SELECT count(*) FROM dvarapala.heartbeats WHERE cluster = $1 AND expires_at > clock_timestamp()",
            &[&c],
        )
        .await
        .map_err(pg)?
        .get(0);

    // sorted by key: replicas lock the same rows in the same order, no deadlock
    let mut counts: Vec<_> = r
        .batch
        .counts
        .iter()
        .map(|(k, n)| (k.to_string(), (*k, i64::from(*n))))
        .collect();
    counts.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    let keys: Vec<&str> = counts.iter().map(|(s, _)| s.as_str()).collect();
    let ns: Vec<i64> = counts.iter().map(|(_, (_, n))| *n).collect();
    let by_name: HashMap<&str, _> = counts.iter().map(|(s, (k, _))| (s.as_str(), *k)).collect();
    let rows = tx
        .query(
            "INSERT INTO dvarapala.counters AS t (cluster, key, window_start, count, expires_at) \
             SELECT $1, k, $2, n, now() + $3 * interval '1 millisecond' \
             FROM unnest($4::text[], $5::bigint[]) AS u(k, n) \
             ON CONFLICT (cluster, key, window_start) DO UPDATE SET count = t.count + EXCLUDED.count \
             RETURNING key, count",
            &[
                &c,
                &(r.batch.window_start as i64),
                &(ms(r.window * 2) as f64),
                &keys,
                &ns,
            ],
        )
        .await
        .map_err(pg)?;
    let totals = rows
        .iter()
        .filter_map(|row| {
            let key = *by_name.get(row.get::<_, &str>(0))?;
            Some((key, row.get::<_, i64>(1).max(0) as u64))
        })
        .collect();

    // one row per mark, the longest ttl wins
    let mut marks: HashMap<(&str, String), i64> = HashMap::new();
    for (net, ttl) in &r.batch.heavy {
        let e = marks.entry(("heavy", net.to_string())).or_default();
        *e = (*e).max(ms(*ttl));
    }
    for (name, ttl) in &r.batch.pauses {
        let e = marks.entry(("pause", name.clone())).or_default();
        *e = (*e).max(ms(*ttl));
    }
    let mut marks: Vec<_> = marks.into_iter().collect();
    marks.sort_unstable();
    let kinds: Vec<&str> = marks.iter().map(|((k, _), _)| *k).collect();
    let names: Vec<&str> = marks.iter().map(|((_, n), _)| n.as_str()).collect();
    let ttls: Vec<f64> = marks.iter().map(|(_, t)| *t as f64).collect();
    tx.execute(
        "INSERT INTO dvarapala.marks AS t (cluster, kind, key, expires_at) \
         SELECT $1, kd, k, now() + ms * interval '1 millisecond' \
         FROM unnest($2::text[], $3::text[], $4::float8[]) AS u(kd, k, ms) \
         ON CONFLICT (cluster, kind, key) DO UPDATE SET expires_at = greatest(t.expires_at, EXCLUDED.expires_at)",
        &[&c, &kinds, &names, &ttls],
    )
    .await
    .map_err(pg)?;

    // clock_timestamp, not now(): now() is when the transaction began,
    // and a mark written meanwhile would look longer than its ttl
    let rows = tx
        .query(
            "SELECT kind, key, (extract(epoch FROM expires_at - clock_timestamp()) * 1000)::bigint \
             FROM dvarapala.marks WHERE cluster = $1 AND expires_at > clock_timestamp() LIMIT $2",
            &[&c, &(r.max_list as i64)],
        )
        .await
        .map_err(pg)?;
    let mut reply = Reply {
        replicas: replicas.clamp(1, i64::from(u32::MAX)) as u32,
        totals,
        ..Reply::default()
    };
    for row in &rows {
        let left = Duration::from_millis(row.get::<_, i64>(2).max(0) as u64);
        let key: String = row.get(1);
        match row.get::<_, &str>(0) {
            // a row that does not parse is skipped, never a reason to drop
            "heavy" => {
                if let Ok(net) = key.parse() {
                    reply.heavy.push((net, left));
                }
            }
            "pause" => reply.pauses.push((key, left)),
            _ => {}
        }
    }
    Ok(reply)
}

/// Deletes expired rows when no other replica is sweeping.
async fn sweep(tx: &Transaction<'_>) -> Result<(), Error> {
    let locked: bool = tx
        .query_one(
            "SELECT pg_try_advisory_xact_lock(hashtext('dvarapala.sweep'))",
            &[],
        )
        .await
        .map_err(pg)?
        .get(0);
    if !locked {
        return Ok(());
    }
    for table in ["counters", "heartbeats", "marks"] {
        tx.execute(
            &format!(
                "DELETE FROM dvarapala.{table} WHERE ctid = ANY(ARRAY( \
                 SELECT ctid FROM dvarapala.{table} WHERE expires_at < now() LIMIT $1))"
            ),
            &[&SWEEP_ROWS],
        )
        .await
        .map_err(pg)?;
    }
    Ok(())
}

impl Postgres {
    /// Sweeps now, whatever the round count (tests).
    pub async fn sweep_now(&mut self) -> Result<(), Error> {
        let client = self.client().await?;
        let tx = client.transaction().await.map_err(pg)?;
        sweep(&tx).await?;
        tx.commit().await.map_err(pg)
    }
}

impl std::fmt::Debug for Postgres {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // the config holds the password
        f.write_str("Postgres { .. }")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "postgres://u:<token>@127.0.0.1:5432/d?sslmode=verify-full";

    fn new(url: &str, ca: Option<&[u8]>) -> Result<Postgres, Error> {
        Postgres::new(url, ca, false, Duration::from_secs(1))
    }

    #[test]
    fn debug_hides_the_password() {
        let p = new(URL, Some(b"")).unwrap();
        assert_eq!(format!("{p:?}"), "Postgres { .. }");
    }

    #[test]
    fn a_bad_url_is_refused() {
        let e = new("postgres://u@127.0.0.1:5432/d?sslmode=bogus", None).unwrap_err();
        assert!(e.0.starts_with("store.url is not a PostgreSQL URL"), "{e}");
    }

    #[test]
    fn a_bad_ca_file_is_refused() {
        let not_base64 = b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n";
        let not_der = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        for pem in [&not_base64[..], &not_der[..]] {
            let e = new(URL, Some(pem)).unwrap_err();
            assert!(e.0.starts_with("store.ca_file: "), "{e}");
        }
    }
}
