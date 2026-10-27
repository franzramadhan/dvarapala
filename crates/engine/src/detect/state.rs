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
    pub(crate) fn new(_trigger: u32, _cooldown: u32) -> Self {
        todo!("rfc 0002")
    }

    pub(crate) fn state(&self) -> State {
        self.state
    }

    /// Feeds one closed window; returns the new state.
    pub(crate) fn step(&mut self, _anomalous: bool) -> State {
        todo!("rfc 0002")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(m: &mut Machine, windows: &[bool]) -> State {
        windows.iter().fold(m.state(), |_, &a| m.step(a))
    }

    #[test]
    #[ignore = "rfc 0002 case 11"]
    fn one_anomaly_is_suspect() {
        let mut m = Machine::new(3, 30);
        assert_eq!(m.step(true), State::Suspect);
    }

    #[test]
    #[ignore = "rfc 0002 case 12"]
    fn suspect_clears_on_normal_window() {
        let mut m = Machine::new(3, 30);
        assert_eq!(run(&mut m, &[true, false]), State::Normal);
    }

    #[test]
    #[ignore = "rfc 0002 case 13"]
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
    #[ignore = "rfc 0002 case 14"]
    fn attack_cools_down_then_normal() {
        let mut m = Machine::new(3, 30);
        run(&mut m, &[true; 3]);
        assert_eq!(m.step(false), State::Cooldown);
        assert_eq!(run(&mut m, &[false; 28]), State::Cooldown);
        assert_eq!(m.step(false), State::Normal);
    }

    #[test]
    #[ignore = "rfc 0002 case 15"]
    fn cooldown_relapse_skips_suspect() {
        let mut m = Machine::new(3, 30);
        run(&mut m, &[true, true, true, false]);
        assert_eq!(m.state(), State::Cooldown);
        assert_eq!(m.step(true), State::Attack);
    }

    #[test]
    #[ignore = "rfc 0002"]
    fn trigger_of_one_goes_straight_to_attack() {
        let mut m = Machine::new(1, 1);
        assert_eq!(m.step(true), State::Attack);
        assert_eq!(m.step(false), State::Normal);
    }
}
