//! RFC 0031: the feeds and the GeoIP database in force. Loaded at start,
//! swapped by a reload, `url` feeds refreshed in the background.

mod feeds;
#[cfg(feature = "tls")]
mod fetch;
mod geoip;
mod running;

pub use running::Running;
