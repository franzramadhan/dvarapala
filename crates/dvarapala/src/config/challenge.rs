//! The `[challenge]` and `[fingerprint]` sections (RFC 0012).

use std::time::Duration;

use dvarapala_engine::ChallengeMode;
use dvarapala_l7::{ChallengeConfig, Fingerprints, unix_now};
use serde::Deserialize;

use super::duration;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Off,
    Attack,
    Always,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Challenge {
    pub mode: Mode,
    pub difficulty: u8,
    #[serde(deserialize_with = "duration")]
    pub timeout: Duration,
    #[serde(deserialize_with = "duration")]
    pub pass_ttl: Duration,
    /// Empty: a random key per process.
    pub secret: String,
    pub cookie_secure: bool,
}

impl Default for Challenge {
    fn default() -> Self {
        Self {
            mode: Mode::Off,
            difficulty: 16,
            timeout: Duration::from_secs(60),
            pass_ttl: Duration::from_secs(3600),
            secret: String::new(),
            cookie_secure: true,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Fingerprint {
    pub deny: Vec<String>,
    pub challenge: Vec<String>,
    /// Empty sends no header to the upstream.
    pub header: String,
}

impl Challenge {
    /// The layer's settings; `None` with `mode = "off"`. `detection` is
    /// whether detection is on, which `"attack"` needs.
    pub fn config(&self, detection: bool) -> Result<Option<ChallengeConfig>, String> {
        let mode = match self.mode {
            Mode::Off => return Ok(None),
            Mode::Attack => ChallengeMode::Attack,
            Mode::Always => ChallengeMode::Always,
        };
        if mode == ChallengeMode::Attack && !detection {
            return Err("challenge.mode = \"attack\" needs detection.enabled".into());
        }
        if !(8..=24).contains(&self.difficulty) {
            return Err(format!(
                "challenge.difficulty {}: must be 8 to 24",
                self.difficulty
            ));
        }
        if !self.secret.is_empty() && self.secret.len() < 32 {
            return Err("challenge.secret must be at least 32 bytes, or empty".into());
        }
        if self.timeout.is_zero() || self.pass_ttl.is_zero() {
            return Err("challenge.timeout and challenge.pass_ttl must be above 0".into());
        }
        Ok(Some(ChallengeConfig {
            mode,
            difficulty: self.difficulty,
            timeout: self.timeout,
            pass_ttl: self.pass_ttl,
            secret: self.secret.as_bytes().to_vec(),
            cookie_secure: self.cookie_secure,
            unix: unix_now,
        }))
    }
}

impl Fingerprint {
    /// The rules; `challenge` entries need a challenge mode to serve the page.
    pub fn rules(&self, challenge: Mode) -> Result<Fingerprints, String> {
        if !self.challenge.is_empty() && challenge == Mode::Off {
            return Err(
                "fingerprint.challenge needs challenge.mode \"attack\" or \"always\"".into(),
            );
        }
        Fingerprints::new(&self.deny, &self.challenge, &self.header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_values_name_the_key() {
        let c = |f: fn(&mut Challenge)| {
            let mut c = Challenge {
                mode: Mode::Always,
                ..Challenge::default()
            };
            f(&mut c);
            c.config(true).unwrap_err()
        };
        assert!(c(|c| c.secret = "short".into()).contains("challenge.secret"));
        assert!(c(|c| c.difficulty = 30).contains("challenge.difficulty"));
        assert!(c(|c| c.pass_ttl = Duration::ZERO).contains("challenge.pass_ttl"));
        let attack = Challenge {
            mode: Mode::Attack,
            ..Challenge::default()
        };
        assert!(
            attack
                .config(false)
                .unwrap_err()
                .contains("detection.enabled")
        );
        assert!(attack.config(true).unwrap().is_some());
        assert!(Challenge::default().config(false).unwrap().is_none());
    }

    #[test]
    fn fingerprint_rules() {
        let f = Fingerprint {
            challenge: vec!["t13d*".into()],
            ..Fingerprint::default()
        };
        assert!(f.rules(Mode::Off).unwrap_err().contains("challenge.mode"));
        assert!(f.rules(Mode::Attack).unwrap().enabled());
        let bad = Fingerprint {
            deny: vec!["nope".into()],
            ..Fingerprint::default()
        };
        assert!(bad.rules(Mode::Off).is_err());
    }
}
