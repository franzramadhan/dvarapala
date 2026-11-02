//! RFC 0031: lists of networks from reputation feeds, parsed off the
//! request path and kept as sorted ranges.

mod parse;
mod set;

pub use parse::{FeedError, MAX_LINE, parse_feed};
pub use set::PrefixSet;
