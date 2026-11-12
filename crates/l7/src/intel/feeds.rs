use std::net::IpAddr;
use std::sync::{Arc, PoisonError, RwLock};

use dvarapala_engine::{Origin, PrefixSet};

/// Feeds a policy holds at most: one route bit each.
pub const MAX_FEEDS: usize = 64;

/// What a feed does to the clients it lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// `403` and the connection closed, before any bucket.
    Deny,
    /// The proof-of-work challenge until the client holds a pass.
    Challenge,
    /// No verdict; routes can match the feed.
    Tag,
}

impl Action {
    pub fn name(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Challenge => "challenge",
            Self::Tag => "tag",
        }
    }
}

/// The list in force for one feed. A refresh swaps it without a reload;
/// clones share it.
#[derive(Debug, Clone, Default)]
pub struct FeedList(Arc<RwLock<Arc<PrefixSet>>>);

impl FeedList {
    pub fn new(set: PrefixSet) -> Self {
        Self(Arc::new(RwLock::new(Arc::new(set))))
    }

    pub fn set(&self, set: PrefixSet) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(set);
    }

    /// Membership under the read guard, without cloning the shared set.
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(ip)
    }

    pub fn get(&self) -> Arc<PrefixSet> {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[derive(Debug, Clone)]
pub struct Feed {
    /// The `feed` label in metrics.
    pub name: String,
    pub action: Action,
    /// `false` counts what the action would do and lets the request on.
    pub enforce: bool,
    pub list: FeedList,
}

/// What the feeds decide for a request, the strongest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Effect {
    None,
    Challenge,
    Deny,
}

/// The feeds and the GeoIP databases in force; a reload swaps it whole.
#[derive(Debug, Default)]
pub struct Intel {
    feeds: Vec<Feed>,
    /// `dvarapala_intel_hits_total` per feed, made once: the labels are fixed.
    hits: Vec<metrics::Counter>,
    #[cfg(feature = "geoip")]
    geo: Vec<Arc<crate::GeoIp>>,
}

impl Intel {
    /// Feeds past [`MAX_FEEDS`] are ignored; the config refuses them.
    pub fn new(mut feeds: Vec<Feed>) -> Self {
        feeds.truncate(MAX_FEEDS);
        let hits = feeds
            .iter()
            .map(|f| {
                let mode = if f.enforce { "enforce" } else { "observe" };
                metrics::counter!(
                    "dvarapala_intel_hits_total",
                    "feed" => f.name.clone(),
                    "action" => f.action.name(),
                    "mode" => mode
                )
            })
            .collect();
        Self {
            feeds,
            hits,
            #[cfg(feature = "geoip")]
            geo: Vec::new(),
        }
    }

    /// Countries and ASNs for route conditions. Each comes from the first
    /// database that has one, so a Country file and an ASN file combine.
    #[cfg(feature = "geoip")]
    pub fn with_geo(mut self, geo: impl IntoIterator<Item = Arc<crate::GeoIp>>) -> Self {
        self.geo = geo.into_iter().collect();
        self
    }

    /// Where `ip` comes from, and what its feeds in enforce mode decide.
    /// Feed `i` sets bit `i` of [`Origin::feeds`] in enforce mode only.
    pub(crate) fn check(&self, ip: IpAddr) -> (Origin, Effect) {
        let mut origin = Origin::default();
        let mut effect = Effect::None;
        for (i, f) in self.feeds.iter().enumerate() {
            if !f.list.contains(ip) {
                continue;
            }
            self.hits[i].increment(1);
            if f.enforce {
                origin.feeds |= 1 << i;
                effect = effect.max(match f.action {
                    Action::Deny => Effect::Deny,
                    Action::Challenge => Effect::Challenge,
                    Action::Tag => Effect::None,
                });
            }
        }
        #[cfg(feature = "geoip")]
        for g in &self.geo {
            let (country, asn) = g.lookup(ip);
            origin.country = origin.country.or(country);
            origin.asn = origin.asn.or(asn);
            if origin.country.is_some() && origin.asn.is_some() {
                break;
            }
        }
        (origin, effect)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(name: &str, action: Action, enforce: bool, nets: &[&str]) -> Feed {
        let set = PrefixSet::new(nets.iter().map(|n| n.parse().unwrap()));
        Feed {
            name: name.into(),
            action,
            enforce,
            list: FeedList::new(set),
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn enforced_feeds_set_bits_and_the_strongest_effect() {
        let intel = Intel::new(vec![
            feed("tor", Action::Tag, true, &["192.0.2.0/24"]),
            feed("drop", Action::Deny, false, &["192.0.2.0/24"]),
            feed("bots", Action::Challenge, true, &["192.0.2.7"]),
            feed("bad", Action::Deny, true, &["198.51.100.0/24"]),
        ]);
        let (o, e) = intel.check(ip("192.0.2.7"));
        assert_eq!((o.feeds, e), (0b101, Effect::Challenge));
        let (o, e) = intel.check(ip("192.0.2.8"));
        assert_eq!((o.feeds, e), (0b1, Effect::None));
        assert_eq!(intel.check(ip("198.51.100.1")).1, Effect::Deny);
        assert_eq!(
            intel.check(ip("203.0.113.1")),
            (Origin::default(), Effect::None)
        );
    }

    #[test]
    fn a_refresh_swaps_the_list_in_place() {
        let f = feed("drop", Action::Deny, true, &["192.0.2.0/24"]);
        let list = f.list.clone();
        let intel = Intel::new(vec![f]);
        assert_eq!(intel.check(ip("192.0.2.1")).1, Effect::Deny);
        list.set(PrefixSet::new(["198.51.100.0/24".parse().unwrap()]));
        assert_eq!(intel.check(ip("192.0.2.1")).1, Effect::None);
        assert_eq!(list.get().len(), 1);
    }

    /// Counts registry lookups and keeps each counter's value by series.
    #[derive(Default)]
    struct Lookups {
        count: std::sync::atomic::AtomicUsize,
        series:
            std::sync::Mutex<std::collections::BTreeMap<String, Arc<std::sync::atomic::AtomicU64>>>,
    }

    impl metrics::Recorder for Lookups {
        fn describe_counter(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }
        fn describe_gauge(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }
        fn describe_histogram(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }
        fn register_counter(
            &self,
            k: &metrics::Key,
            _: &metrics::Metadata<'_>,
        ) -> metrics::Counter {
            self.count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let labels: Vec<_> = k
                .labels()
                .map(|l| format!("{}={}", l.key(), l.value()))
                .collect();
            let id = format!("{}{{{}}}", k.name(), labels.join(","));
            let c = self.series.lock().unwrap().entry(id).or_default().clone();
            metrics::Counter::from_arc(c)
        }
        fn register_gauge(&self, _: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Gauge {
            metrics::Gauge::noop()
        }
        fn register_histogram(
            &self,
            _: &metrics::Key,
            _: &metrics::Metadata<'_>,
        ) -> metrics::Histogram {
            metrics::Histogram::noop()
        }
    }

    // issue 349: hits reuse handles made in `Intel::new`; series and values stay
    #[test]
    fn hit_metrics_are_not_looked_up_per_request() {
        use std::sync::atomic::Ordering;
        let rec = Lookups::default();
        metrics::with_local_recorder(&rec, || {
            let intel = Intel::new(vec![
                feed("drop", Action::Deny, true, &["192.0.2.0/24"]),
                feed("tor", Action::Tag, false, &["192.0.2.0/24"]),
            ]);
            let built = rec.count.load(Ordering::Relaxed);
            for _ in 0..5 {
                intel.check(ip("192.0.2.7"));
            }
            assert_eq!(rec.count.load(Ordering::Relaxed), built);
        });
        let values: Vec<_> = rec
            .series
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.load(Ordering::Relaxed)))
            .collect();
        let id = |f, a, m| format!("dvarapala_intel_hits_total{{feed={f},action={a},mode={m}}}");
        assert_eq!(
            values,
            vec![
                (id("drop", "deny", "enforce"), 5),
                (id("tor", "tag", "observe"), 5)
            ]
        );
    }
}
