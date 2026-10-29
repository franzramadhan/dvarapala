//! RFC 0016 case 10: one million lines from 10000 clients replay in under
//! 10 s. A plain timing, not criterion: one run takes seconds.

use std::fmt::Write as _;
use std::fs;
use std::process::Command;
use std::time::{Duration, Instant};

const LINES: usize = 1_000_000;
const BUDGET: Duration = Duration::from_secs(10);

fn main() {
    let dir = std::env::temp_dir().join(format!("dvarapala-replay-bench-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let config = dir.join("c.toml");
    fs::write(
        &config,
        "upstream = \"http://127.0.0.1:9\"\n[detection]\nenabled = true\n",
    )
    .unwrap();
    let mut log = String::with_capacity(LINES * 80);
    for i in 0..LINES {
        let c = i % 10_000;
        let _ = writeln!(
            log,
            r#"{{"ts":{},"client":"2001:db8:{:x}::1","path":"/p{}"}}"#,
            1_700_000_000.0 + i as f64 / 1000.0,
            c,
            i % 7
        );
    }
    let path = dir.join("log");
    fs::write(&path, log).unwrap();
    let start = Instant::now();
    let o = Command::new(env!("CARGO_BIN_EXE_dvarapala"))
        .arg("replay")
        .arg("--config")
        .arg(&config)
        .arg(&path)
        .output()
        .unwrap();
    let took = start.elapsed();
    let _ = fs::remove_dir_all(&dir);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    println!("replay_1m_lines: {took:.2?} (budget {BUDGET:?})");
    assert!(took < BUDGET, "over budget");
}
