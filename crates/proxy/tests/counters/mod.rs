//! A metrics recorder that keeps every counter, shared by the test binaries.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

static COUNTERS: LazyLock<Mutex<HashMap<String, u64>>> = LazyLock::new(Default::default);

/// Keeps every counter as `name{k=v,...}`, labels in emitted order.
struct Counters;

struct Named(String);

impl metrics::CounterFn for Named {
    fn increment(&self, n: u64) {
        *COUNTERS.lock().unwrap().entry(self.0.clone()).or_default() += n;
    }
    fn absolute(&self, _: u64) {}
}

impl metrics::Recorder for Counters {
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
    fn register_counter(&self, key: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Counter {
        let labels: Vec<String> = key
            .labels()
            .map(|l| format!("{}={}", l.key(), l.value()))
            .collect();
        let name = format!("{}{{{}}}", key.name(), labels.join(","));
        metrics::Counter::from_arc(Arc::new(Named(name)))
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

/// Installs the recorder once per test binary; call it first in each test.
pub fn record() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| metrics::set_global_recorder(Counters).unwrap());
}

/// A counter's value, `name{k=v,...}` as emitted.
pub fn counter(key: &str) -> u64 {
    COUNTERS.lock().unwrap().get(key).copied().unwrap_or(0)
}
