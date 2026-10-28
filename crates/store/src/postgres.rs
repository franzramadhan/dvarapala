#![allow(unused_variables, unused_imports, unused_mut, dead_code)]
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
    todo!("rfc 0010")
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
        todo!("rfc 0010")
    }

    async fn connect(&mut self) -> Result<&mut Client, Error> {
        todo!("rfc 0010")
    }
}

fn tls(ca: Option<&[u8]>) -> Result<ClientConfig, Error> {
    todo!("rfc 0010")
}

impl Store for Postgres {
    async fn round(&mut self, r: &Round<'_>) -> Result<Reply, Error> {
        todo!("rfc 0010")
    }
}

fn ms(d: Duration) -> i64 {
    todo!("rfc 0010")
}

async fn round(tx: &Transaction<'_>, r: &Round<'_>) -> Result<Reply, Error> {
    todo!("rfc 0010")
}

/// Deletes expired rows when no other replica is sweeping.
async fn sweep(tx: &Transaction<'_>) -> Result<(), Error> {
    todo!("rfc 0010")
}

impl Postgres {
    /// Sweeps now, whatever the round count (tests).
    pub async fn sweep_now(&mut self) -> Result<(), Error> {
        todo!("rfc 0010")
    }
}

impl std::fmt::Debug for Postgres {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!("rfc 0010")
    }
}
