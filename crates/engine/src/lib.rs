//! Verdict engine. No I/O and no async runtime: callers pass the current
//! time in, so every decision is deterministic and testable.

mod blocks;
mod bucket;
mod cidr;
mod cluster;
mod concurrency;
mod conns;
mod detect;
mod guard;
mod history;
mod intel;
mod key;
mod routes;
mod sample;
mod schedule;
mod score;
mod table;
mod verdict;

pub use blocks::{Blocks, BlocksFull};
pub use bucket::{Bucket, Limit, LimitError};
pub use cidr::{BlockSink, Cidr, CidrError, TrustedProxies};
pub use cluster::{Batch, Cluster, ClusterConfig, Reply, overshoot, split};
pub use concurrency::{
    Class, Concurrency, ConcurrencyConfig, ConcurrencyError, LimitMode, Outcome, Priority, Update,
};
pub use conns::{ConnKey, Conns, ConnsConfig, ConnsError, Refused};
pub use detect::{DetectConfig, DetectError, Detector, State, WindowReport};
pub use guard::{ChallengeMode, Decision, Guard, GuardConfig, GuardDetection, Pass};
pub use history::{Minute, Ring, Sample, Sampler, VERDICTS};
pub use intel::{FeedError, MAX_LINE, PrefixSet, parse_feed};
pub use key::{ClientKey, client_ip, client_key};
pub use routes::{
    Host, Matcher, Origin, PathMatch, RouteKey, RouteLimits, parse_country, parse_method,
    strip_port,
};
pub use sample::{Admit, Gate};
pub use schedule::{Schedule, ScheduleConfig, ScheduleError, Slot};
pub use score::{ClientStats, FEATURE_NAMES, FEATURES, Features, Scorer};
#[cfg(feature = "ml")]
pub use score::{ModelError, TreeEnsemble};
pub use table::Table;
pub use verdict::Verdict;
