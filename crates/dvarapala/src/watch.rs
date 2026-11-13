//! RFC 0019 `config_watch`: reload when the `--config` file changes on
//! disk, as kubelet does to a mounted ConfigMap. RFC 0029: the `ml.model`
//! file too; RFC 0031: the `path` feeds and `intel.geoip`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

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
    let mut model = model_file(&r);
    let mut intel = intel_files(&r);
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
            model = model_file(&r);
            intel = intel_files(&r);
            continue;
        }
        // RFC 0031: by size and time, a database is tens of MB
        let i = intel_files(&r);
        if i.len() == intel.len()
            && i.iter()
                .zip(&intel)
                .any(|(a, b)| a.0 == b.0 && a.1.is_some() && a.1 != b.1)
        {
            tracing::info!(msg = "intel file changed on disk");
            r.reload();
        }
        intel = i;
        // RFC 0029: the model file too, under the path in force; a file
        // missing mid-swap is skipped as above
        let m = model_file(&r);
        if m.0 == model.0 && m.1.is_some() && m.1 != model.1 {
            tracing::info!(msg = "model changed on disk");
            r.reload();
        }
        model = m;
    }
}

/// The intel files in force, with their size and modification time.
fn intel_files(r: &Reloader) -> Vec<(PathBuf, Option<(u64, SystemTime)>)> {
    r.intel_files()
        .into_iter()
        .map(|p| {
            let m = std::fs::metadata(&p).ok();
            let stamp = m.and_then(|m| Some((m.len(), m.modified().ok()?)));
            (p, stamp)
        })
        .collect()
}

/// The `ml.model` path in force and its bytes, if it reads.
fn model_file(r: &Reloader) -> (Option<PathBuf>, Option<Vec<u8>>) {
    let path = r.configs().1.ml.model;
    let bytes = path.as_ref().and_then(|p| std::fs::read(p).ok());
    (path, bytes)
}

#[cfg(test)]
// figment::Jail closures return figment::Error by value; not ours to box
#[allow(clippy::result_large_err)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::config;

    #[test]
    fn empty_is_off_and_durations_parse() {
        crate::config::jail(|j| {
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
        let r = Arc::new(Reloader::new(
            None,
            None,
            Default::default(),
            false,
            cfg,
            None,
        ));
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

    /// Waits up to 5 s for `n` reloads.
    async fn reloads(count: &std::sync::atomic::AtomicUsize, n: usize) {
        use std::sync::atomic::Ordering;
        for _ in 0..100 {
            if count.load(Ordering::Relaxed) >= n {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(count.load(Ordering::Relaxed), n);
    }

    #[tokio::test]
    async fn reloads_on_a_config_or_feed_change() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let dir = std::env::temp_dir().join(format!("watch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (file, feed) = (dir.join("d.toml"), dir.join("feed.txt"));
        std::fs::write(&feed, "192.0.2.0/24\n").unwrap();
        let toml = format!(
            "upstream = \"http://127.0.0.1:1\"\n\
             [[intel.feed]]\nname = \"f\"\npath = \"{}\"\naction = \"deny\"\n",
            feed.display()
        );
        std::fs::write(&file, &toml).unwrap();
        let cfg = config::load(Some(&file)).unwrap();
        let r = Arc::new(Reloader::new(
            Some(file.clone()),
            None,
            Default::default(),
            false,
            cfg,
            None,
        ));
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        let _ = r.on_reload.set(Box::new(move |_| {
            c.fetch_add(1, Ordering::Relaxed);
        }));
        start(Some(&file), Some(MIN), r.clone()).unwrap();
        tokio::time::sleep(MIN * 3).await;

        std::fs::write(&file, toml.clone() + "# changed\n").unwrap();
        reloads(&count, 1).await;
        // a file missing mid-swap is not a change
        std::fs::remove_file(&file).unwrap();
        tokio::time::sleep(MIN * 3).await;
        std::fs::write(&file, toml + "# changed\n").unwrap();
        tokio::time::sleep(MIN * 3).await;
        assert_eq!(count.load(Ordering::Relaxed), 1);

        std::fs::write(&feed, "192.0.2.0/24\n198.51.100.0/24\n").unwrap();
        reloads(&count, 2).await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
