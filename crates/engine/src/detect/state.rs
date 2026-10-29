use std::fmt;

/// Attack state of one instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Normal,
    Suspect,
    Attack,
    Cooldown,
}

impl State {
    /// Gauge value: 0 normal, 1 suspect, 2 attack, 3 cooldown.
    pub fn code(self) -> u8 {
        self as u8
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Suspect => "suspect",
            Self::Attack => "attack",
            Self::Cooldown => "cooldown",
        }
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// `Suspect` after one anomalous window, `Attack` after `trigger` in a row.
/// The first normal window in `Attack` starts `Cooldown`; `cooldown` normal
/// windows in all return to `Normal`. An anomalous window in `Cooldown`
/// goes straight back to `Attack`.
pub(crate) struct Machine {
    state: State,
    streak: u32,
    trigger: u32,
    cooldown: u32,
}

impl Machine {
    pub(crate) fn new(trigger: u32, cooldown: u32) -> Self {
        Self {
            state: State::Normal,
            streak: 0,
            trigger,
            cooldown,
        }
    }

    pub(crate) fn state(&self) -> State {
        self.state
    }

    /// Feeds one closed window; returns the new state.
    pub(crate) fn step(&mut self, anomalous: bool) -> State {
        use State::*;
        (self.state, self.streak) = match (self.state, anomalous) {
            (Normal, true) => (Suspect, 1),
            (Suspect, true) => (Suspect, self.streak + 1),
            (Normal | Suspect, false) => (Normal, 0),
            (Attack | Cooldown, true) => (Attack, 0),
            (Attack, false) => (Cooldown, 1),
            (Cooldown, false) => (Cooldown, self.streak + 1),
        };
        if self.state == Suspect && self.streak >= self.trigger {
            (self.state, self.streak) = (Attack, 0);
        }
        if self.state == Cooldown && self.streak >= self.cooldown {
            (self.state, self.streak) = (Normal, 0);
        }
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(m: &mut Machine, windows: &[bool]) -> State {
        windows.iter().fold(m.state(), |_, &a| m.step(a))
    }

    #[test]
    fn one_anomaly_is_suspect() {
        let mut m = Machine::new(3, 30);
        assert_eq!(m.step(true), State::Suspect);
    }

    #[test]
    fn states_display_as_their_label() {
        let shown = [
            State::Normal,
            State::Suspect,
            State::Attack,
            State::Cooldown,
        ]
        .map(|s| s.to_string());
        assert_eq!(shown, ["normal", "suspect", "attack", "cooldown"]);
    }

    #[test]
    fn suspect_clears_on_normal_window() {
        let mut m = Machine::new(3, 30);
        assert_eq!(run(&mut m, &[true, false]), State::Normal);
    }

    #[test]
    fn trigger_windows_in_a_row_is_attack() {
        let mut m = Machine::new(3, 30);
        assert_eq!(run(&mut m, &[true, true]), State::Suspect);
        assert_eq!(m.step(true), State::Attack);
        // a break resets the streak
        let mut m = Machine::new(3, 30);
        assert_eq!(
            run(&mut m, &[true, true, false, true, true]),
            State::Suspect
        );
    }

    #[test]
    fn attack_cools_down_then_normal() {
        let mut m = Machine::new(3, 30);
        run(&mut m, &[true; 3]);
        assert_eq!(m.step(false), State::Cooldown);
        assert_eq!(run(&mut m, &[false; 28]), State::Cooldown);
        assert_eq!(m.step(false), State::Normal);
    }

    #[test]
    fn cooldown_relapse_skips_suspect() {
        let mut m = Machine::new(3, 30);
        run(&mut m, &[true, true, true, false]);
        assert_eq!(m.state(), State::Cooldown);
        assert_eq!(m.step(true), State::Attack);
    }

    #[test]
    fn trigger_of_one_goes_straight_to_attack() {
        let mut m = Machine::new(1, 1);
        assert_eq!(m.step(true), State::Attack);
        assert_eq!(m.step(false), State::Normal);
    }
}
