//! RFC 0021: the mode switches in force, until the next reload.

use std::sync::{Mutex, PoisonError};

use dvarapala_l7::{ModeLayer, unix_now};

/// One layer switched away from the file's mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Switch {
    pub layer: ModeLayer,
    pub enforce: bool,
    /// What the file says.
    pub file_enforce: bool,
    pub actor: String,
    /// Unix seconds.
    pub at: u64,
}

impl Switch {
    pub fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "layer": self.layer.name(),
            "mode": mode(self.enforce),
            "file_mode": mode(self.file_enforce),
            "actor": self.actor,
            "at": self.at,
        })
    }
}

#[derive(Debug, Default)]
pub struct Switches(Mutex<Vec<Switch>>);

impl Switches {
    /// Records a switch and returns the mode it replaces. Switching back
    /// to the file's mode removes the switch.
    pub fn set(&self, layer: ModeLayer, enforce: bool, file_enforce: bool, actor: &str) -> bool {
        let mut s = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let previous = s
            .iter()
            .find(|w| w.layer == layer)
            .map_or(file_enforce, |w| w.enforce);
        s.retain(|w| w.layer != layer);
        if enforce != file_enforce {
            s.push(Switch {
                layer,
                enforce,
                file_enforce,
                actor: actor.to_owned(),
                at: unix_now(),
            });
        }
        gauge(layer, enforce != file_enforce);
        previous
    }

    /// The running mode of `layer`, when it is switched.
    pub fn get(&self, layer: ModeLayer) -> Option<Switch> {
        let s = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        s.iter().find(|w| w.layer == layer).cloned()
    }

    pub fn all(&self) -> Vec<Switch> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// A reload applied the file: every switch ends, each logged.
    pub fn clear(&self, file_enforce: impl Fn(ModeLayer) -> bool) {
        let mut s = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        for w in s.drain(..) {
            tracing::info!(
                msg = "mode switch cleared",
                layer = w.layer.name(),
                switched = mode(w.enforce),
                file = mode(file_enforce(w.layer)),
            );
            gauge(w.layer, false);
        }
    }
}

pub fn mode(enforce: bool) -> &'static str {
    if enforce { "enforce" } else { "observe" }
}

fn gauge(layer: ModeLayer, on: bool) {
    ::metrics::gauge!("dvarapala_mode_switched", "layer" => layer.name()).set(if on {
        1.0
    } else {
        0.0
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_get_and_back_to_the_file() {
        let s = Switches::default();
        assert!(s.set(ModeLayer::Waf, false, true, "token"));
        let w = s.get(ModeLayer::Waf).unwrap();
        assert_eq!(
            (w.enforce, w.file_enforce, w.actor.as_str()),
            (false, true, "token")
        );
        assert!(!s.set(ModeLayer::Waf, true, true, "token"));
        assert_eq!(s.get(ModeLayer::Waf), None);
        s.set(ModeLayer::Detection, true, false, "a");
        s.clear(|_| false);
        assert!(s.all().is_empty());
    }
}
