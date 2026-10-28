#![allow(unused_variables, unused_imports, dead_code)]
use crate::Packet;

/// A packet rate as a GCRA: one packet per `interval` ns, up to
/// `tolerance` ns ahead (`burst` packets). `interval` 0 is off.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Rate {
    pub interval: u64,
    pub tolerance: u64,
}

impl Rate {
    pub const fn new(pps: u32, burst: u32) -> Self {
        panic!("rfc 0011")
    }

    /// Whether one more packet at `now` (ns) fits; `tat` is the source's
    /// theoretical arrival time, moved on only when it does.
    pub fn admit(self, tat: &mut u64, now: u64) -> bool {
        todo!("rfc 0011")
    }
}

/// The program's settings, entry 0 of the `CONFIG` array.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Config {
    pub pps: Rate,
    pub syn: Rate,
    pub udp: Rate,
    /// 0: no TCP port protected
    pub tcp_port: u16,
    /// 0: no UDP port protected
    pub udp_port: u16,
    /// 0 observe, 1 enforce
    pub enforce: u8,
    pub prefix_v4: u8,
    pub prefix_v6: u8,
    pub _pad: u8,
}

impl Config {
    pub fn protects(&self, p: &Packet) -> bool {
        todo!("rfc 0011")
    }

    /// The source address with host bits past `prefix_v4` / `prefix_v6`
    /// cleared: the key of the per-source rates.
    pub fn source(&self, p: &Packet) -> [u8; 16] {
        todo!("rfc 0011")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Pass,
    Drop,
    WouldDrop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Allow,
    Block,
    Pps,
    Syn,
    Udp,
    /// passed every check, or not to a protected port
    Other,
}

pub const ACTIONS: [(Action, &str); 3] = [
    (Action::Pass, "pass"),
    (Action::Drop, "drop"),
    (Action::WouldDrop, "would_drop"),
];

pub const REASONS: [(Reason, &str); 6] = [
    (Reason::Allow, "allow"),
    (Reason::Block, "block"),
    (Reason::Pps, "pps"),
    (Reason::Syn, "syn"),
    (Reason::Udp, "udp"),
    (Reason::Other, "other"),
];

/// Entries in the per-CPU `COUNTERS` array.
pub const COUNTERS: u32 = (ACTIONS.len() * REASONS.len()) as u32;

/// The `COUNTERS` index of one action and reason.
pub const fn counter(a: Action, r: Reason) -> u32 {
    panic!("rfc 0011")
}

#[cfg(all(feature = "aya", target_os = "linux"))]
unsafe impl aya::Pod for Config {}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::Proto;

    // RFC 0011 case 6, the arithmetic: burst 200 at once, then the rate
    #[test]
    #[ignore = "rfc 0011"]
    fn burst_then_rate() {
        let r = Rate::new(100, 200);
        let mut tat = 0;
        let now = 5_000_000_000;
        let passed = (0..300).filter(|_| r.admit(&mut tat, now)).count();
        assert_eq!(passed, 200);
        // 100 per second refill: 10 ms later, one more
        assert!(r.admit(&mut tat, now + 10_000_000));
        assert!(!r.admit(&mut tat, now + 10_000_000));
        assert!(Rate::new(0, 0).admit(&mut tat, 0), "0 is off");
    }

    #[test]
    #[ignore = "rfc 0011"]
    fn source_keeps_the_prefix() {
        let c = Config {
            prefix_v4: 24,
            prefix_v6: 64,
            ..Config::default()
        };
        let mut src = [0u8; 16];
        src[10..].copy_from_slice(&[0xff, 0xff, 192, 0, 2, 7]);
        let p = Packet {
            src,
            v4: true,
            proto: Proto::Udp,
            dst_port: 443,
        };
        assert_eq!(c.source(&p)[12..], [192, 0, 2, 0]);
        let p = Packet {
            src: [0xff; 16],
            v4: false,
            ..p
        };
        assert_eq!(c.source(&p), [[0xff; 8], [0; 8]].concat()[..]);
    }

    #[test]
    #[ignore = "rfc 0011"]
    fn counters_are_distinct() {
        let mut seen = [false; COUNTERS as usize];
        for (a, _) in ACTIONS {
            for (r, _) in REASONS {
                let i = counter(a, r) as usize;
                assert!(!seen[i]);
                seen[i] = true;
            }
        }
    }
}
