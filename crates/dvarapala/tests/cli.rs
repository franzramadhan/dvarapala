//! The command line: arguments, exit codes and config errors at start.
#![cfg(unix)]

#[allow(dead_code)]
mod proc;
mod stop;

use std::process::Output;

use proc::{run, temp};

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn version_prints_the_package_version() {
    let o = run(&["--version"], &[]);
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(
        stdout(&o),
        format!("dvarapala {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn bad_usage_exits_2() {
    for args in [
        &[][..],
        &["serve", "--nope"],
        &["serve", "--config"],
        &["--version", "extra"],
        &["store"],
        &["store", "schema", "extra"],
        &["store", "schema", "--from"],
        &["store", "schema", "--from", "one"],
        &["store", "schema", "--from", "1", "extra"],
    ] {
        let o = run(args, &[]);
        assert_eq!(o.status.code(), Some(2), "{args:?}");
        assert!(stderr(&o).starts_with("usage: dvarapala serve"), "{args:?}");
        assert!(stdout(&o).is_empty(), "{args:?}");
    }
}

// RFC 0010: the schema for a hand-run migration
#[test]
fn store_schema_prints_the_migrations() {
    let o = run(&["store", "schema"], &[]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let all = stdout(&o);
    assert!(
        all.starts_with("-- dvarapala schema version 1\nBEGIN;\n"),
        "{all}"
    );
    assert!(all.contains("COMMIT;"), "{all}");
    let o = run(&["store", "schema", "--from", "0"], &[]);
    assert_eq!(stdout(&o), all);
    // past the latest version: nothing to run
    let o = run(&["store", "schema", "--from", "4294967295"], &[]);
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(stdout(&o), "");
}

/// `serve --config` with `toml`: the exit code and stderr. Every case
/// fails before it binds anything, the default metrics port included.
fn refused(name: &str, toml: &str) -> (Option<i32>, String) {
    let path = temp(&format!("cli-{name}.toml"));
    std::fs::write(&path, toml).unwrap();
    let o = run(&["serve", "--config", path.to_str().unwrap()], &[]);
    let _ = std::fs::remove_file(&path);
    (o.status.code(), stderr(&o))
}

const BASE: &str = "listen = \"127.0.0.1:1\"\nupstream = \"http://127.0.0.1:1\"\n";

#[test]
fn config_errors_exit_1_and_name_the_key() {
    let missing = temp("cli-missing.toml");
    let o = run(&["serve", "--config", missing.to_str().unwrap()], &[]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).starts_with("dvarapala: "), "{}", stderr(&o));
    let cert = temp("cli-none.pem");
    let cert = cert.to_str().unwrap();
    // a build without the tls feature refuses [tls] before reading it
    let tls = |key| {
        if cfg!(feature = "tls") {
            key
        } else {
            "[tls] needs a build with the tls feature"
        }
    };
    for (name, extra, key) in [
        ("toml", "[rate_limit\n", "rate_limit"),
        (
            "http2",
            "[http2]\nmax_concurrent_streams = 0\n",
            "http2.max_concurrent_streams",
        ),
        (
            "upgrade",
            "[upgrade]\nmax_tunnels = 0\n",
            "upgrade.max_tunnels",
        ),
        (
            "handshakes",
            &format!("[tls]\ncert = \"{cert}\"\nkey = \"{cert}\"\nmax_handshakes = 0\n"),
            tls("tls.max_handshakes"),
        ),
        (
            "tls",
            &format!("[tls]\ncert = \"{cert}\"\nkey = \"{cert}\"\n"),
            tls("tls: "),
        ),
        ("metrics", "[metrics]\nlisten = \"nope\"\n", "dvarapala: "),
        (
            "admin",
            "[admin]\nlisten = \"127.0.0.1:1\"\n",
            "admin.token",
        ),
        // a non-Linux build, or one without the xdp feature, refuses the
        // key; a Linux one with it finds no such interface
        ("xdp", "[xdp]\ninterface = \"dvx-none0\"\n", "xdp"),
    ] {
        let (code, err) = refused(name, &format!("{BASE}{extra}"));
        assert_eq!(code, Some(1), "{name}: {err}");
        assert!(
            err.starts_with("dvarapala: ") && err.contains(key),
            "{name}: {err}"
        );
    }
}

// RFC 0007: forward mode has no HTTP/3 listener
#[test]
fn forward_mode_refuses_quic_and_needs_a_destination() {
    let forward = "listen = \"127.0.0.1:1\"\nmode = \"forward\"\n";
    let (code, err) = refused(
        "fwd-quic",
        &format!("{forward}[quic]\nlisten = \"127.0.0.1:1\"\n"),
    );
    assert_eq!(code, Some(1), "{err}");
    assert!(
        err.contains("quic.listen works in reverse mode only"),
        "{err}"
    );
    let (code, err) = refused("fwd-empty", forward);
    assert_eq!(code, Some(1), "{err}");
    assert!(err.contains("[[forward.destinations]]"), "{err}");
}
