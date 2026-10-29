//! Verdict engine. No I/O and no async runtime: callers pass the current
//! time in, so every decision is deterministic and testable.

mod blocks;
mod bucket;
mod cidr;
mod cluster;
mod conns;
mod detect;
mod guard;
mod key;
mod schedule;
mod score;
mod table;
mod verdict;

pub use blocks::{Blocks, BlocksFull};
pub use bucket::{Bucket, Limit, LimitError};
pub use cidr::{BlockSink, Cidr, CidrError, TrustedProxies};
pub use cluster::{Batch, Cluster, ClusterConfig, Reply, overshoot, split};
pub use conns::{ConnKey, Conns, ConnsConfig, ConnsError, Refused};
pub use detect::{DetectConfig, DetectError, Detector, State, WindowReport};
pub use guard::{ChallengeMode, Decision, Guard, GuardConfig, GuardDetection, Pass};
pub use key::{ClientKey, client_ip, client_key};
pub use schedule::{Schedule, ScheduleConfig, ScheduleError, Slot};
pub use score::{ClientStats, FEATURE_NAMES, FEATURES, Features, Scorer};
#[cfg(feature = "ml")]
pub use score::{ModelError, TreeEnsemble};
pub use table::Table;
pub use verdict::Verdict;
