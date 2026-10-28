//! RFC 0011 cases 3 to 8 and 12: the program in the kernel, through
//! `BPF_PROG_TEST_RUN`, with the `load` feature. Needs root (CAP_BPF, CAP_NET_ADMIN): runs when
//! `DVARAPALA_TEST_XDP` is set (the CI step under sudo), skips otherwise.
#![cfg(all(feature = "load", target_os = "linux"))]

use std::process::Command;
use std::time::Duration;

use dvarapala_xdp::{Attach, Xdp, XdpConfig};
use dvarapala_xdp_common::{Action, Reason, counter};

const PORT: u16 = 8080;
const PASS: u32 = 2;
const DROP: u32 = 1;

fn enabled() -> bool {
    let on = std::env::var_os("DVARAPALA_TEST_XDP").is_some();
    if !on {
        eprintln!("skipped: DVARAPALA_TEST_XDP is not set");
    }
    on
}

fn config() -> XdpConfig {
    XdpConfig {
        enforce: true,
        allow: vec![],
        block: vec![],
        block_ttl: Duration::from_secs(600),
        max_blocks: 64,
        pps: 0,
        syn_pps: 100,
        udp_pps: 0,
        burst: 200,
        prefix_v4: 32,
        prefix_v6: 64,
        max_sources: 1024,
        tcp_port: PORT,
        udp_port: 0,
    }
}

/// An Ethernet, IPv4, TCP frame from `src` to `port`.
fn syn(src: [u8; 4], port: u16) -> Vec<u8> {
    let mut f = vec![0u8; 14 + 20 + 20];
    f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    f[14] = 0x45;
    f[14 + 9] = 6;
    f[14 + 12..14 + 16].copy_from_slice(&src);
    f[34 + 2..34 + 4].copy_from_slice(&port.to_be_bytes());
    f[34 + 12] = 0x50;
    f[34 + 13] = 0x02;
    f
}

const SRC: [u8; 4] = [192, 0, 2, 7];

fn n(x: &Xdp, a: Action, r: Reason) -> u64 {
    x.counts()[counter(a, r) as usize]
}

// case 3
#[test]
#[ignore = "rfc 0011"]
fn other_port_passes_untouched() {
    if !enabled() {
        return;
    }
    let x = Xdp::load(&config()).unwrap();
    assert_eq!(x.run(&syn(SRC, 22)).unwrap(), PASS);
    let counts = x.counts();
    let other = counter(Action::Pass, Reason::Other) as usize;
    assert_eq!(counts[other], 1);
    assert_eq!(counts.iter().sum::<u64>(), 1, "{counts:?}");
}

// case 4
#[test]
#[ignore = "rfc 0011"]
fn allow_wins_over_block() {
    if !enabled() {
        return;
    }
    let net = "192.0.2.0/24".parse().unwrap();
    let x = Xdp::load(&XdpConfig {
        allow: vec![net],
        block: vec![net],
        ..config()
    })
    .unwrap();
    assert_eq!(x.run(&syn(SRC, PORT)).unwrap(), PASS);
    assert_eq!(n(&x, Action::Pass, Reason::Allow), 1);
}

// case 5
#[test]
#[ignore = "rfc 0011"]
fn block_drops_in_enforce() {
    if !enabled() {
        return;
    }
    let x = Xdp::load(&XdpConfig {
        block: vec!["192.0.2.0/24".parse().unwrap()],
        ..config()
    })
    .unwrap();
    assert_eq!(x.run(&syn(SRC, PORT)).unwrap(), DROP);
    assert_eq!(x.run(&syn([198, 51, 100, 1], PORT)).unwrap(), PASS);
    assert_eq!(n(&x, Action::Drop, Reason::Block), 1);
}

// case 6
#[test]
#[ignore = "rfc 0011"]
fn syn_rate_drops_past_the_burst() {
    if !enabled() {
        return;
    }
    let x = Xdp::load(&config()).unwrap();
    let f = syn(SRC, PORT);
    // 300 SYNs well inside one 10 ms refill
    let passed = (0..300).filter(|_| x.run(&f).unwrap() == PASS).count();
    assert!((200..=201).contains(&passed), "{passed} passed");
    assert!(n(&x, Action::Drop, Reason::Syn) >= 99);
}

// case 7
#[test]
#[ignore = "rfc 0011"]
fn observe_passes_and_counts() {
    if !enabled() {
        return;
    }
    let x = Xdp::load(&XdpConfig {
        enforce: false,
        ..config()
    })
    .unwrap();
    let f = syn(SRC, PORT);
    assert!((0..300).all(|_| x.run(&f).unwrap() == PASS));
    let would = n(&x, Action::WouldDrop, Reason::Syn);
    assert!((99..=100).contains(&would), "{would}");
    assert_eq!(n(&x, Action::Drop, Reason::Syn), 0);
}

// case 8
#[test]
#[ignore = "rfc 0011"]
fn dynamic_block_expires() {
    if !enabled() {
        return;
    }
    let x = Xdp::load(&XdpConfig {
        block_ttl: Duration::from_millis(300),
        ..config()
    })
    .unwrap();
    x.block("192.0.2.0/24".parse().unwrap());
    assert_eq!(x.blocks(), 1);
    assert_eq!(x.run(&syn(SRC, PORT)).unwrap(), DROP);
    std::thread::sleep(Duration::from_millis(400));
    // expired in the program before the sweep removes it
    assert_eq!(x.run(&syn(SRC, PORT)).unwrap(), PASS);
    x.tick();
    assert_eq!(x.blocks(), 0);
}

fn attached(iface: &str) -> bool {
    let out = Command::new("ip")
        .args(["-d", "link", "show", "dev", iface])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).contains("prog/xdp")
}

/// The child of case 12: attaches to `lo` and waits to be killed.
#[test]
#[ignore = "rfc 0011"]
fn child_attaches_and_waits() {
    if std::env::var_os("DVARAPALA_XDP_CHILD").is_none() {
        return;
    }
    let mut x = Xdp::load(&config()).unwrap();
    x.attach("lo", Attach::Generic).unwrap();
    println!("attached");
    std::thread::sleep(Duration::from_secs(60));
}

// case 12
#[test]
#[ignore = "rfc 0011"]
fn killed_process_detaches() {
    if !enabled() {
        return;
    }
    assert!(!attached("lo"), "lo already has an XDP program");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["child_attaches_and_waits", "--exact", "--nocapture"])
        .env("DVARAPALA_XDP_CHILD", "1")
        .spawn()
        .unwrap();
    let mut up = false;
    for _ in 0..100 {
        if attached("lo") {
            up = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(up, "child never attached");
    let mut gone = false;
    for _ in 0..100 {
        if !attached("lo") {
            gone = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(gone, "still attached after SIGKILL");
}
