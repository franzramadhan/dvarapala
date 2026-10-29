//! RFC 0016 cases 3 to 9: `dvarapala replay` end to end.
#![cfg(feature = "replay")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn base(rate: u32, burst: u32) -> String {
    format!("upstream = \"http://127.0.0.1:9\"\n[rate_limit]\nrate = {rate}\nburst = {burst}\n")
}

struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Self {
        let d =
            std::env::temp_dir().join(format!("dvarapala-replay-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        Self(d)
    }

    fn file(&self, name: &str, body: &str) -> PathBuf {
        let p = self.0.join(name);
        fs::write(&p, body).unwrap();
        p
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn replay(config: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_dvarapala"))
        .arg("replay")
        .arg("--config")
        .arg(config)
        .args(args)
        .env_remove("RUST_LOG")
        .output()
        .unwrap()
}

fn lines(it: impl IntoIterator<Item = (f64, String, &'static str)>) -> String {
    it.into_iter()
        .map(|(ts, client, path)| {
            format!("{{\"ts\":{ts},\"client\":\"{client}\",\"path\":\"{path}\"}}\n")
        })
        .collect()
}

fn stdout(o: &Output) -> String {
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8(o.stdout.clone()).unwrap()
}

/// The value of the first report line starting with `series`.
fn series(report: &str, series: &str) -> u64 {
    report
        .lines()
        .find(|l| l.starts_with(series))
        .and_then(|l| l.rsplit(' ').next())
        .map_or(0, |v| v.parse().unwrap())
}

// RFC 0016 case 3
#[test]
fn virtual_clock_refills_the_bucket() {
    let d = Dir::new("clock");
    let cfg = d.file("c.toml", &base(1, 1));
    for (step, allowed) in [(0.0, 1), (1.0, 10)] {
        let log = d.file(
            "log",
            &lines((0..10).map(|i| (1_700_000_000.0 + i as f64 * step, "192.0.2.7".into(), "/"))),
        );
        let r = stdout(&replay(&cfg, &[log.to_str().unwrap()]));
        let ok = r#"dvarapala_requests_total{verdict="allow",protocol="http1"}"#;
        let limited = r#"dvarapala_requests_total{verdict="throttle",protocol="http1"}"#;
        assert_eq!(series(&r, ok), allowed, "{r}");
        assert_eq!(series(&r, limited), 10 - allowed, "{r}");
    }
}

// RFC 0016 case 4
#[test]
fn time_going_back_keeps_the_clock() {
    let d = Dir::new("back");
    let cfg = d.file("c.toml", &base(1, 1));
    // 10 s, then 5 s: the second line sees 10 s, an empty bucket
    let log = d.file(
        "log",
        &lines([
            (10.0, "192.0.2.7".into(), "/"),
            (5.0, "192.0.2.7".into(), "/"),
        ]),
    );
    let r = stdout(&replay(&cfg, &[log.to_str().unwrap()]));
    assert!(
        r.starts_with("lines 2, replayed 2, skipped 0, span 0.000 s"),
        "{r}"
    );
    assert_eq!(
        series(&r, r#"dvarapala_requests_total{verdict="throttle""#),
        1,
        "{r}"
    );
}

// RFC 0016 case 5
#[test]
fn route_drops_are_reported() {
    let d = Dir::new("route");
    let cfg = d.file(
        "c.toml",
        &format!(
            "{}[[routes]]\nname = \"wp\"\npath = \"/wp-admin\"\ndeny = true\n",
            base(1000, 1000)
        ),
    );
    let log = d.file(
        "log",
        &lines((0..20).map(|i| {
            (
                i as f64,
                format!("192.0.2.{i}"),
                if i % 4 == 0 { "/wp-admin/x" } else { "/" },
            )
        })),
    );
    let r = stdout(&replay(&cfg, &[log.to_str().unwrap()]));
    assert_eq!(
        series(
            &r,
            r#"dvarapala_route_requests_total{route="wp",verdict="deny"}"#
        ),
        5,
        "{r}"
    );
}

// RFC 0016 case 6
#[test]
fn detection_drops_the_flooding_prefix_only() {
    let d = Dir::new("detect");
    let cfg = d.file(
        "c.toml",
        &format!(
            "{}[detection]\nenabled = true\nmode = \"enforce\"\nprefix_v4 = 24\n\
             warmup_windows = 1\ntrigger_windows = 1\nattack_rate_factor = 0.25\n",
            base(4, 1)
        ),
    );
    let normal = (0..10).map(|i| (0.0, format!("198.51.100.{i}"), "/"));
    let flood = (0..1000).map(|i| (1.0, format!("192.0.2.{}", i % 200), "/"));
    let after = (0..10).flat_map(|i| {
        [
            (2.0 + i as f64 / 20.0, format!("192.0.2.{i}"), "/"),
            (2.0 + i as f64 / 20.0, format!("198.51.100.{}", 50 + i), "/"),
        ]
    });
    let log = d.file("log", &lines(normal.chain(flood).chain(after)));
    let out = d.0.join("out");
    let r = stdout(&replay(
        &cfg,
        &["--out", out.to_str().unwrap(), log.to_str().unwrap()],
    ));
    assert!(r.contains(r#"to="attack""#), "{r}");
    let status: Vec<String> = fs::read_to_string(&out)
        .unwrap()
        .lines()
        .map(String::from)
        .collect();
    let after = &status[1010..];
    for (i, l) in after.iter().enumerate() {
        let want = if i % 2 == 0 { 403 } else { 200 };
        assert!(l.ends_with(&format!("\"status\":{want}}}")), "{i}: {l}");
    }
}

// RFC 0016 case 7
#[test]
fn out_has_one_line_per_replayed_line() {
    let d = Dir::new("out");
    let cfg = d.file("c.toml", &base(1, 1));
    let log = d.file(
        "log",
        &lines((0..20).map(|_| (1.0, "192.0.2.7".into(), "/"))),
    );
    let out = d.0.join("out");
    stdout(&replay(
        &cfg,
        &["--out", out.to_str().unwrap(), log.to_str().unwrap()],
    ));
    let got = fs::read_to_string(&out).unwrap();
    let want: String = (1..=20)
        .map(|n| {
            format!(
                "{{\"line\":{n},\"status\":{}}}\n",
                if n == 1 { 200 } else { 429 }
            )
        })
        .collect();
    assert_eq!(got, want);
}

// RFC 0016 case 8
#[test]
fn network_keys_warn_and_bad_lines_skip() {
    let d = Dir::new("skip");
    let cfg = d.file(
        "c.toml",
        &format!("{}[store]\nbackend = \"redis\"\nurl = \"redis://<host>\"\n[xdp]\ninterface = \"eth0\"\n", base(1, 1)),
    );
    let log = d.file(
        "log",
        "{\"ts\":1,\"client\":\"192.0.2.7\"}\nnot json\n{\"ts\":2,\"client\":\"192.0.2.7\"}\n",
    );
    let o = replay(&cfg, &[log.to_str().unwrap()]);
    let r = stdout(&o);
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(err.matches("replay ignores").count(), 1, "{err}");
    assert!(err.contains("[store]") && err.contains("[xdp]"), "{err}");
    assert!(
        r.starts_with("lines 3, replayed 2, skipped 1, span 1.000 s\nskipped line 2: "),
        "{r}"
    );
}

// RFC 0016 case 9
#[test]
fn bad_inputs_exit_2() {
    let d = Dir::new("bad");
    let cfg = d.file("c.toml", &base(1, 1));
    let o = replay(&cfg, &[d.0.join("missing").to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("missing"));
    let bad = d.file("bad.toml", "[rate_limit]\nrate = \"fast\"\n");
    let log = d.file("log", "");
    let o = replay(&bad, &[log.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("rate"));
}
