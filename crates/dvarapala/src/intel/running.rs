use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use dvarapala_l7::{Feed, FeedList, Intel, RateLimitLayer};

use super::feeds::{apply, read};
use super::geoip::{self, Geo};
use crate::config::{self, Config};

/// A feed in force: the config it came from, its list and, for a `url`
/// feed, its refresh task.
struct Loaded {
    source: config::Feed,
    list: FeedList,
    task: Option<tokio::task::AbortHandle>,
}

/// What a reload checked and read, put in force by [`Running::commit`].
pub struct Prepared {
    feeds: Vec<(config::Feed, FeedList)>,
    geo: Option<Geo>,
    max_bytes: usize,
}

/// The feeds and the database in force.
#[derive(Default)]
pub struct Running {
    feeds: Mutex<HashMap<String, Loaded>>,
    geo: Mutex<Option<Geo>>,
}

impl Running {
    /// Validates `[intel]` and reads every `path` feed and the database;
    /// changes nothing. A `url` feed with the same config keeps its list.
    pub fn prepare(&self, cfg: &Config) -> Result<Prepared, String> {
        let intel = &cfg.intel;
        intel.check(cfg.challenge.config(cfg.detection.enabled)?.is_some())?;
        let running = lock(&self.feeds);
        let mut feeds = Vec::with_capacity(intel.feed.len());
        for f in &intel.feed {
            let kept = running
                .get(&f.name)
                .filter(|l| l.source == *f && f.url.is_some());
            let list = match (&f.path, kept) {
                (_, Some(l)) => l.list.clone(),
                (Some(p), None) => {
                    let list = FeedList::default();
                    apply(&f.name, &list, read(p, intel.max_bytes), f.max_entries)
                        .map_err(|e| format!("intel.feed {:?}: {}: {e}", f.name, p.display()))?;
                    list
                }
                // empty until its task fetches it
                (None, None) => FeedList::default(),
            };
            feeds.push((f.clone(), list));
        }
        drop(running);
        let geo = match &intel.geoip {
            Some(p) => Some(geoip::load(p, lock(&self.geo).as_ref())?),
            None => None,
        };
        Ok(Prepared {
            feeds,
            geo,
            max_bytes: intel.max_bytes,
        })
    }

    /// Puts `p` in force in `layer`: starts the refresh tasks of new `url`
    /// feeds, stops those of removed or changed ones.
    pub fn commit(&self, p: Prepared, layer: &RateLimitLayer) {
        let mut running = lock(&self.feeds);
        let mut next = HashMap::with_capacity(p.feeds.len());
        let mut feeds = Vec::with_capacity(p.feeds.len());
        for (f, list) in p.feeds {
            let task = match running.remove(&f.name).filter(|l| l.source == f) {
                Some(old) => old.task,
                None => spawn(&f, p.max_bytes, &list),
            };
            feeds.push(Feed {
                name: f.name.clone(),
                action: f.action.into(),
                enforce: f.mode == config::Mode::Enforce,
                list: list.clone(),
            });
            next.insert(
                f.name.clone(),
                Loaded {
                    source: f,
                    list,
                    task,
                },
            );
        }
        for task in running.drain().filter_map(|(_, l)| l.task) {
            task.abort();
        }
        *running = next;
        let intel = Intel::new(feeds);
        #[cfg(feature = "geoip")]
        let intel = intel.with_geo(p.geo.as_ref().map(|g| g.db.clone()));
        layer.set_intel(Arc::new(intel));
        *lock(&self.geo) = p.geo;
    }

    /// Each `path` feed and the database, the files `config_watch` polls.
    pub fn files(cfg: &Config) -> Vec<std::path::PathBuf> {
        let feeds = cfg.intel.feed.iter().filter_map(|f| f.path.clone());
        feeds.chain(cfg.intel.geoip.clone()).collect()
    }
}

fn spawn(f: &config::Feed, max_bytes: usize, list: &FeedList) -> Option<tokio::task::AbortHandle> {
    #[cfg(feature = "tls")]
    if let Some(url) = &f.url {
        return super::fetch::spawn(f, url, max_bytes, list.clone());
    }
    // the config refuses a url feed without the tls feature
    let _ = (f, max_bytes, list);
    None
}

impl Drop for Running {
    fn drop(&mut self) {
        let feeds = self.feeds.get_mut().unwrap_or_else(PoisonError::into_inner);
        for task in feeds.drain().filter_map(|(_, l)| l.task) {
            task.abort();
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}
