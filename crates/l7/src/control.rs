//! What an operator changes at run time (RFC 0014): the reloadable policy
//! and the manual block list.

use std::sync::{Arc, PoisonError, RwLockWriteGuard};
use std::time::Duration;

use dvarapala_engine::{
    Blocks, BlocksFull, ChallengeMode, Cidr, DetectError, Limit, TrustedProxies,
};

use crate::challenge::Challenge;
use crate::rate_limit::RateLimitLayer;
use crate::{ChallengeConfig, Fingerprints, RouteConfig, Routes, Scoring};

/// The parts of the layer a request reads once and a reload swaps whole.
pub(crate) struct Policy {
    pub(crate) trusted: TrustedProxies,
    pub(crate) challenge: Option<Challenge>,
    pub(crate) fingerprints: Fingerprints,
    pub(crate) routes: Arc<Routes>,
    /// detection in enforce mode, so heavy hitters are published
    pub(crate) enforce: bool,
}

/// The keys a reload applies in place.
#[derive(Debug, Clone)]
pub struct Reload {
    pub limit: Limit,
    pub trusted: TrustedProxies,
    /// Ignored without detection.
    pub enforce: bool,
    /// Ignored without detection.
    pub attack_rate_factor: f64,
    pub challenge: Option<ChallengeConfig>,
    pub fingerprints: Fingerprints,
    /// `None` keeps the running routes and their buckets.
    pub routes: Option<Vec<RouteConfig>>,
    /// RFC 0029: `None` keeps the running scorer, `Some(None)` turns
    /// scoring off. Client features stay either way.
    pub scoring: Option<Option<Scoring>>,
}

/// A snapshot for the admin API.
#[derive(Debug, Clone)]
pub struct Status {
    pub clients: usize,
    /// `None` without detection.
    pub detection: Option<&'static str>,
    pub blocks: usize,
}

/// A manual block in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Block {
    pub net: Cidr,
    pub remaining: Duration,
}

impl RateLimitLayer {
    /// Applies `r` without touching the table or the detector: clients keep
    /// their buckets, the detector its baseline. Fails, changing nothing,
    /// on an attack factor the engine rejects.
    pub fn reload(&self, r: Reload) -> Result<(), DetectError> {
        let s = &self.shared;
        let mode = r.challenge.as_ref().map_or(ChallengeMode::Off, |c| c.mode);
        let mut inner = s.lock();
        inner
            .guard
            .retune(r.limit, r.enforce, r.attack_rate_factor, mode)?;
        let enforce = r.enforce && inner.guard.detector().is_some();
        let mut policy = s.policy.write().unwrap_or_else(PoisonError::into_inner);
        let challenge = r
            .challenge
            .map(|c| Challenge::reload(policy.challenge.as_ref(), c));
        let routes = r
            .routes
            .map_or_else(|| policy.routes.clone(), |v| Arc::new(Routes::new(v)));
        *policy = Arc::new(Policy {
            trusted: r.trusted,
            challenge,
            fingerprints: r.fingerprints,
            routes,
            enforce,
        });
        Ok(())
    }

    /// Blocks `net` for `ttl`, also at the XDP block list when there is one.
    pub fn block(&self, net: Cidr, ttl: Duration) -> Result<(), BlocksFull> {
        let now = (self.shared.now)();
        let mut b = self.blocks_mut();
        b.add(net, now + ttl, now)?;
        metrics::gauge!("dvarapala_blocks").set(b.list(now).len() as f64);
        drop(b);
        if let Some(sink) = &self.shared.block {
            sink.block(net);
        }
        Ok(())
    }

    /// `true` when `net` was blocked. An XDP entry stays until its own
    /// expiry.
    pub fn unblock(&self, net: Cidr) -> bool {
        let now = (self.shared.now)();
        let mut b = self.blocks_mut();
        let removed = b.remove(net);
        metrics::gauge!("dvarapala_blocks").set(b.list(now).len() as f64);
        removed
    }

    pub fn blocks(&self) -> Vec<Block> {
        let now = (self.shared.now)();
        self.blocks_mut()
            .list(now)
            .iter()
            .map(|&(net, until)| Block {
                net,
                remaining: until.saturating_duration_since(now),
            })
            .collect()
    }

    pub fn status(&self) -> Status {
        let blocks = self.blocks().len();
        let inner = self.shared.lock();
        Status {
            clients: inner.guard.clients(),
            detection: inner.guard.detector().map(|d| d.state().name()),
            blocks,
        }
    }

    /// The heavy hitters of the last closed window, with their counts.
    pub fn top(&self) -> Vec<(Cidr, u32)> {
        let inner = self.shared.lock();
        inner
            .guard
            .detector()
            .map_or_else(Vec::new, |d| d.heavy().to_vec())
    }

    fn blocks_mut(&self) -> RwLockWriteGuard<'_, Blocks> {
        self.shared
            .blocks
            .write()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

impl Challenge {
    /// The new settings, keeping the old key when the secret is the same
    /// (an empty secret keeps its random key), so passes stay valid.
    pub(crate) fn reload(old: Option<&Challenge>, config: ChallengeConfig) -> Self {
        match old {
            Some(o) if o.config.secret == config.secret => Self {
                keys: o.keys.clone(),
                config,
            },
            _ => Self::new(config),
        }
    }
}
