//! RFC 0031: reputation feeds and the GeoIP database, checked once per
//! request in the rate limiter.

mod feeds;
#[cfg(feature = "geoip")]
mod geoip;

pub(crate) use feeds::Effect;
pub use feeds::{Action, Feed, FeedList, Intel, MAX_FEEDS};
#[cfg(feature = "geoip")]
pub use geoip::{GeoIp, fuzz_geoip, test_db, test_db_fields};
