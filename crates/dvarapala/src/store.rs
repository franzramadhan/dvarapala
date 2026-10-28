//! Starts the RFC 0010 sync task for a shared `[store]`.

use std::error::Error;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use dvarapala_engine::{Cluster, ClusterConfig, Limit};
use dvarapala_store::SyncConfig;

use crate::config;

/// The replica's cluster view with its sync task running, or `None` for
/// `backend = "memory"` (no task, no socket). `limit` is the per-client
/// limit, `None` in forward mode.
pub fn start(
    cfg: &config::Store,
    limit: Option<Limit>,
    max_clients: usize,
) -> Result<Option<Arc<Mutex<Cluster>>>, Box<dyn Error>> {
    let Some(url) = cfg.shared_url()? else {
        return Ok(None);
    };
    let ca = cfg
        .ca_file
        .as_ref()
        .map(|p| std::fs::read(p).map_err(|e| format!("store.ca_file {}: {e}", p.display())))
        .transpose()?;
    let cluster = Arc::new(Mutex::new(Cluster::new(ClusterConfig {
        limit,
        // ponytail: ten sync rounds per window, a knob if anyone needs one
        window: cfg.sync_interval * 10,
        max_keys: cfg.max_keys,
        max_clients,
    })));
    let sync = SyncConfig {
        cluster: cfg.cluster.clone(),
        replica: replica(),
        interval: cfg.sync_interval,
        timeout: cfg.timeout,
        max_list: cfg.max_keys,
    };
    spawn(cfg, url, ca.as_deref(), cluster.clone(), sync.clone())?;
    tracing::info!(
        backend = ?cfg.backend,
        cluster = %sync.cluster,
        replica = %sync.replica,
        interval = ?sync.interval,
        "store sync started"
    );
    Ok(Some(cluster))
}

/// Starts the backend's sync task; a backend the binary was built
/// without is a config error.
#[allow(unused_variables)]
fn spawn(
    cfg: &config::Store,
    url: &str,
    ca: Option<&[u8]>,
    cluster: Arc<Mutex<Cluster>>,
    sync: SyncConfig,
) -> Result<(), Box<dyn Error>> {
    match cfg.backend {
        #[cfg(feature = "redis")]
        config::Backend::Redis => {
            let s = dvarapala_store::Redis::new(url, ca)?;
            dvarapala_store::spawn(s, cluster, sync);
            Ok(())
        }
        #[cfg(feature = "postgres")]
        config::Backend::Postgres => {
            let s = dvarapala_store::Postgres::new(url, ca, cfg.migrate, cfg.timeout)?;
            dvarapala_store::spawn(s, cluster, sync);
            Ok(())
        }
        b => {
            let name = format!("{b:?}").to_lowercase();
            Err(
                format!("store.backend = \"{name}\" needs a binary built with the {name} feature")
                    .into(),
            )
        }
    }
}

/// Unique enough while it runs: the process id and the start time.
fn replica() -> String {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{}-{t:x}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Backend;

    // RFC 0010 case 1
    #[test]
    fn memory_starts_nothing() {
        let c = start(&config::Store::default(), None, 10).unwrap();
        assert!(c.is_none());
    }

    #[cfg(not(feature = "redis"))]
    #[test]
    fn redis_needs_the_feature() {
        let cfg = config::Store {
            backend: Backend::Redis,
            url: Some("redis://<host>:6379/0".into()),
            ..config::Store::default()
        };
        let e = start(&cfg, None, 10).unwrap_err().to_string();
        assert!(e.contains("redis feature"), "{e}");
    }

    // RFC 0010 case 12: a bad URL's error does not echo the password
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn url_errors_hide_the_password() {
        for url in [
            "postgres://user:<token>@<host>:notaport/db",
            "postgres://user:<token>@192.0.2.1/db?sslmode=nonsense",
        ] {
            let cfg = config::Store {
                backend: Backend::Postgres,
                url: Some(url.into()),
                ..config::Store::default()
            };
            let e = start(&cfg, None, 10).unwrap_err().to_string();
            assert!(!e.contains("<token>"), "{e}");
        }
    }
}
