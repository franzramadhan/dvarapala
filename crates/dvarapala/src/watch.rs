//! RFC 0019 `config_watch`: reload when the `--config` file changes on
//! disk, as kubelet does to a mounted ConfigMap.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::time::MissedTickBehavior;

use crate::reload::Reloader;

/// Shortest interval: polling faster only burns reads.
const MIN: Duration = Duration::from_millis(100);

/// Polls `path` every `every` and reloads on a change; off when `every` is
/// `None`.
pub fn start(path: Option<&Path>, every: Option<Duration>, r: Arc<Reloader>) -> Result<(), String> {
    let Some(every) = every else {
        return Ok(());
    };
    let path = path.ok_or("config_watch needs serve --config <file>")?;
    if every < MIN {
        return Err("config_watch must be at least 100ms".into());
    }
    let path = path.to_owned();
    tokio::spawn(watch(path, every, r));
    Ok(())
}

async fn watch(path: PathBuf, every: Duration, r: Arc<Reloader>) {
    let mut last = std::fs::read(&path).ok();
    let mut tick = tokio::time::interval(every);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        // reads through symlinks; a file missing mid-swap is skipped, not a change
        let Ok(now) = std::fs::read(&path) else {
            continue;
        };
        if last.as_ref() != Some(&now) {
            tracing::info!(msg = "config changed on disk");
            r.reload();
            last = Some(now);
        }
    }
}

#[cfg(test)]
// figment::Jail closures return figment::Error by value; not ours to box
#[allow(clippy::result_large_err)]
mod tests {
    use std::path::Path;

    use figment::Jail;

    use super::*;
    use crate::config;

    #[test]
    fn empty_is_off_and_durations_parse() {
        Jail::expect_with(|j| {
            j.create_file("d.toml", "upstream = \"http://127.0.0.1:1\"\n")?;
            assert_eq!(
                config::load(Some(Path::new("d.toml")))
                    .unwrap()
                    .config_watch,
                None
            );
            j.set_env("DVARAPALA__CONFIG_WATCH", "10s");
            let cfg = config::load(Some(Path::new("d.toml"))).unwrap();
            assert_eq!(cfg.config_watch, Some(Duration::from_secs(10)));
            j.set_env("DVARAPALA__CONFIG_WATCH", "soon");
            assert!(config::load(Some(Path::new("d.toml"))).is_err());
            Ok(())
        });
    }

    #[tokio::test]
    async fn needs_a_file_and_a_sane_interval() {
        let cfg = config::Config {
            upstream: Some("http://127.0.0.1:1".into()),
            ..config::load(None).unwrap()
        };
        let r = Arc::new(Reloader::new(None, None, Default::default(), false, cfg));
        let ms = |n| Some(Duration::from_millis(n));
        assert!(start(None, None, r.clone()).is_ok());
        assert!(
            start(None, ms(1000), r.clone())
                .unwrap_err()
                .contains("--config")
        );
        let p = Path::new("d.toml");
        assert!(
            start(Some(p), ms(10), r.clone())
                .unwrap_err()
                .contains("100ms")
        );
    }
}
