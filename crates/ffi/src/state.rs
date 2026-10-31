//! What a guard's one lock holds (RFC 0028): the engine guard, the trusted
//! proxies, the routes, the blocks and the egress schedules, so a reload
//! swaps them in one step and a check sees the old config or the new one.

use std::collections::{HashMap, VecDeque};
use std::ffi::{CStr, CString};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dvarapala_engine::{
    Blocks, Guard, Matcher, RouteKey, RouteLimits, Schedule, ScheduleConfig, TrustedProxies,
};

use crate::config::Built;
use crate::lists::RouteSpec;

pub(crate) struct State {
    pub(crate) guard: Guard,
    pub(crate) trusted: TrustedProxies,
    pub(crate) routes: Vec<Route>,
    routes_src: String,
    /// `dv_route_headers`: the header names route keys read, comma separated
    pub(crate) headers: Arc<CStr>,
    pub(crate) blocks: Blocks,
    pub(crate) max_block_ttl: Duration,
    pub(crate) egress: HashMap<String, Egress>,
    /// what the guard was built from, for the restart-only keys
    built: Built,
    /// every string handed to the caller, so a pointer outlives a reload
    // ponytail: grows with each distinct route name ever configured; fine
    // for configs reloaded by hand
    strings: Vec<Arc<CStr>>,
}

pub(crate) struct Route {
    pub(crate) name: Arc<CStr>,
    pub(crate) matcher: Matcher,
    pub(crate) deny: bool,
    /// the header the bucket counts per; `None` counts per client
    pub(crate) header: Option<String>,
    pub(crate) limits: Option<RouteLimits>,
}

/// A destination's schedule and the deadlines of the `wait` slots it gave
/// out, which hold a queue place until their time.
pub(crate) struct Egress {
    pub(crate) schedule: Schedule,
    pub(crate) waiting: VecDeque<Instant>,
}

impl State {
    pub(crate) fn new(b: Built) -> Result<Self, String> {
        let guard = Guard::new(b.guard.clone()).map_err(|e| format!("detection: {}", e.0))?;
        let mut s = Self {
            guard,
            trusted: b.trusted.clone(),
            routes: Vec::new(),
            routes_src: String::new(),
            headers: Arc::from(c""),
            blocks: Blocks::new(b.max_blocks),
            max_block_ttl: b.max_block_ttl,
            egress: HashMap::new(),
            built: b,
            strings: Vec::new(),
        };
        s.set_routes(&s.built.routes.clone());
        s.routes_src.clone_from(&s.built.routes_src);
        s.set_destinations(&s.built.destinations.clone())?;
        Ok(s)
    }

    /// Applies `b` in place: counts, the detection baseline, blocks and
    /// egress queues stay. Changes nothing when `b` touches a key that only
    /// applies at start.
    pub(crate) fn reload(&mut self, b: Built) -> Result<(), String> {
        if let Some(k) = self.built.restart(&b) {
            return Err(format!("{k} only applies when the guard is created"));
        }
        let (det, g) = (b.guard.detection.as_ref(), &b.guard);
        let (enforce, factor) = det.map_or((false, 1.0), |d| (d.enforce, d.attack_rate_factor));
        // the one step that can refuse, and it checks before it changes
        // anything; the destinations were validated with the config
        self.guard
            .retune(g.limit, enforce, factor, g.challenge)
            .map_err(|e| format!("detection: {}", e.0))?;
        self.trusted = b.trusted.clone();
        if b.routes_src != self.routes_src {
            self.set_routes(&b.routes);
            self.routes_src.clone_from(&b.routes_src);
        }
        self.set_destinations(&b.destinations)?;
        self.max_block_ttl = b.max_block_ttl;
        self.built = b;
        Ok(())
    }

    fn set_routes(&mut self, specs: &[RouteSpec]) {
        let mut headers = Vec::new();
        self.routes = specs
            .iter()
            .map(|r| {
                let header = match &r.key {
                    RouteKey::Header(h) => Some(h.clone()),
                    _ => None,
                };
                if let Some(h) = header.as_ref().filter(|_| r.limit.is_some())
                    && !headers.contains(h)
                {
                    headers.push(h.clone());
                }
                Route {
                    name: self.keep(&r.name),
                    matcher: r.matcher.clone(),
                    deny: r.deny,
                    header,
                    limits: r.limit.map(|l| RouteLimits::new(l, r.max_keys)),
                }
            })
            .collect();
        self.headers = self.keep(&headers.join(","));
    }

    /// New destinations start empty, kept ones keep their slots and queue,
    /// dropped ones go.
    fn set_destinations(&mut self, list: &[(String, ScheduleConfig)]) -> Result<(), String> {
        let mut next = HashMap::new();
        for (name, c) in list {
            let e = match self.egress.remove(name) {
                Some(mut e) => {
                    e.schedule.reconfigure(*c).map_err(|e| e.0)?;
                    e
                }
                None => Egress {
                    schedule: Schedule::new(*c).map_err(|e| e.0)?,
                    waiting: VecDeque::new(),
                },
            };
            next.insert(name.clone(), e);
        }
        self.egress = next;
        Ok(())
    }

    fn keep(&mut self, s: &str) -> Arc<CStr> {
        if let Some(k) = self.strings.iter().find(|k| k.to_bytes() == s.as_bytes()) {
            return k.clone();
        }
        // names come from the config, which is UTF-8 text without NUL
        let k: Arc<CStr> = CString::new(s.replace('\0', " "))
            .unwrap_or_default()
            .into();
        self.strings.push(k.clone());
        k
    }
}
