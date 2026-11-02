//! The `[intel]` section (RFC 0031): reputation feeds and the GeoIP
//! database.

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use dvarapala_l7::{Action, MAX_FEEDS};
use serde::{Deserialize, Serialize};

use super::waf::size;
use super::{Mode, duration};

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Intel {
    pub feed: Vec<Feed>,
    /// A MaxMind DB file; unset turns `routes[].country` and `asn` off.
    pub geoip: Option<PathBuf>,
    /// Largest feed body or file read.
    #[serde(deserialize_with = "size")]
    pub max_bytes: usize,
}

impl Default for Intel {
    fn default() -> Self {
        Self {
            feed: Vec::new(),
            geoip: None,
            max_bytes: 16 << 20,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Feed {
    pub name: String,
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default)]
    pub url: Option<String>,
    pub action: FeedAction,
    #[serde(default = "observe")]
    pub mode: Mode,
    #[serde(
        default = "hour",
        deserialize_with = "duration",
        serialize_with = "crate::config::view::ser_duration"
    )]
    pub refresh: Duration,
    #[serde(default = "max_entries")]
    pub max_entries: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FeedAction {
    Deny,
    Challenge,
    Tag,
}

impl From<FeedAction> for Action {
    fn from(a: FeedAction) -> Self {
        match a {
            FeedAction::Deny => Self::Deny,
            FeedAction::Challenge => Self::Challenge,
            FeedAction::Tag => Self::Tag,
        }
    }
}

fn observe() -> Mode {
    Mode::Observe
}

fn hour() -> Duration {
    Duration::from_secs(3600)
}

fn max_entries() -> usize {
    200_000
}

impl Intel {
    /// `challenge` is whether `[challenge]` is on. Errors name the feed
    /// and the key.
    pub fn check(&self, challenge: bool) -> Result<(), String> {
        if self.feed.len() > MAX_FEEDS {
            return Err(format!("intel.feed: at most {MAX_FEEDS} feeds"));
        }
        if self.max_bytes == 0 {
            return Err("intel.max_bytes must be above 0".into());
        }
        let mut names = HashSet::new();
        for f in &self.feed {
            let err = |key: &str, e: &str| Err(format!("intel.feed {:?}: {key}: {e}", f.name));
            if f.name.is_empty() {
                return Err("intel.feed: every feed needs a name".into());
            }
            if !names.insert(f.name.as_str()) {
                return err("name", "used by another feed");
            }
            match (&f.path, &f.url) {
                (Some(_), None) => {}
                (None, Some(u)) if !u.starts_with("https://") => {
                    return err("url", "must start with https://");
                }
                (None, Some(_)) if !cfg!(feature = "tls") => {
                    return err("url", "needs a build with the tls feature");
                }
                (None, Some(_)) => {}
                _ => return err("path", "set exactly one of path and url"),
            }
            if f.refresh < Duration::from_secs(300) {
                return err("refresh", "must be at least 5m");
            }
            if f.max_entries == 0 {
                return err("max_entries", "must be above 0");
            }
            if f.action == FeedAction::Challenge && !challenge {
                return err("action", "\"challenge\" needs [challenge] on");
            }
        }
        Ok(())
    }

    /// The route bit of the feed named `name`.
    pub fn bit(&self, name: &str) -> Option<usize> {
        self.feed.iter().position(|f| f.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(name: &str) -> Feed {
        Feed {
            name: name.into(),
            path: Some("drop.txt".into()),
            url: None,
            action: FeedAction::Deny,
            mode: observe(),
            refresh: hour(),
            max_entries: max_entries(),
        }
    }

    fn intel(feeds: Vec<Feed>) -> Intel {
        Intel {
            feed: feeds,
            ..Intel::default()
        }
    }

    #[test]
    fn bad_feeds_name_the_feed_and_key() {
        let err = |f: fn(&mut Feed)| {
            let mut x = feed("drop");
            f(&mut x);
            intel(vec![x]).check(false).unwrap_err()
        };
        assert!(intel(vec![feed("drop")]).check(false).is_ok());
        let dup = intel(vec![feed("a"), feed("a")]).check(false).unwrap_err();
        assert!(dup.contains("\"a\": name"), "{dup}");
        let e = err(|f| f.url = Some("https://example.com/drop.txt".into()));
        assert!(e.contains("\"drop\": path"), "{e}");
        let e = err(|f| {
            f.path = None;
            f.url = Some("http://example.com/drop.txt".into());
        });
        assert!(e.contains("\"drop\": url"), "{e}");
        let e = err(|f| f.refresh = Duration::from_secs(60));
        assert!(e.contains("\"drop\": refresh"), "{e}");
        let e = err(|f| f.action = FeedAction::Challenge);
        assert!(e.contains("[challenge]"), "{e}");
        assert!(err(|f| f.name.clear()).contains("name"));
        let many = (0..65).map(|i| feed(&i.to_string())).collect();
        assert!(intel(many).check(false).is_err());
    }

    #[test]
    fn geoip_is_one_path_or_a_list() {
        let one: Intel = toml::from_str("geoip = \"Country.mmdb\"").unwrap();
        assert_eq!(one.geoip, Some(vec!["Country.mmdb".into()]));
        assert!(one.check(false).is_ok());
        let two: Intel = toml::from_str("geoip = [\"Country.mmdb\", \"ASN.mmdb\"]").unwrap();
        assert_eq!(
            two.geoip,
            Some(vec!["Country.mmdb".into(), "ASN.mmdb".into()])
        );
        assert!(two.check(false).is_ok());
        let err = |s: &str| {
            toml::from_str::<Intel>(s)
                .unwrap()
                .check(false)
                .unwrap_err()
        };
        let e = err("geoip = []");
        assert!(e.contains("intel.geoip: at least one file"), "{e}");
        let e = err("geoip = [\"a.mmdb\", \"b.mmdb\", \"a.mmdb\"]");
        assert!(e.contains("intel.geoip a.mmdb: listed twice"), "{e}");
        let e = err("geoip = [\"1\", \"2\", \"3\", \"4\", \"5\"]");
        assert!(e.contains("intel.geoip: at most 4 files"), "{e}");
    }

    #[test]
    fn bits_follow_the_feed_order() {
        let i = intel(vec![feed("drop"), feed("tor")]);
        assert_eq!(i.bit("tor"), Some(1));
        assert_eq!(i.bit("nope"), None);
    }
}
