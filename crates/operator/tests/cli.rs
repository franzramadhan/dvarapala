//! The operator binary's command line, without a cluster.

use std::process::{Command, Output};

fn operator(args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_dvarapala-operator"));
    c.args(args)
        .env_remove("POD_NAMESPACE")
        .env_remove("KUBERNETES_SERVICE_HOST")
        .env_remove("KUBERNETES_SERVICE_PORT");
    for (k, v) in env {
        c.env(k, v);
    }
    c.output().unwrap()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn prints_the_crd_and_the_version() {
    let o = operator(&["crd"], &[]);
    assert!(o.status.success());
    let crd: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(crd["spec"]["names"]["kind"], "DvarapalaPolicy");
    let o = operator(&["--version"], &[]);
    assert!(o.status.success());
    assert!(String::from_utf8_lossy(&o.stdout).starts_with("dvarapala-operator "));
}

#[test]
fn usage_on_bad_arguments() {
    for args in [&[][..], &["nope"], &["run"], &["run", "--gateway-image"]] {
        let o = operator(args, &[]);
        assert_eq!(o.status.code(), Some(2), "{args:?}");
        assert!(stderr(&o).starts_with("usage: "), "{args:?}");
    }
}

#[test]
fn run_needs_a_namespace_and_a_cluster() {
    let o = operator(&["run", "--gateway-image", "x"], &[]);
    assert_eq!(o.status.code(), Some(1));
    assert!(
        stderr(&o).contains("POD_NAMESPACE is not set"),
        "{}",
        stderr(&o)
    );
    let o = operator(
        &["run", "--gateway-image", "x"],
        &[
            ("POD_NAMESPACE", "dvarapala"),
            ("KUBECONFIG", "/nonexistent/kubeconfig"),
        ],
    );
    assert_eq!(o.status.code(), Some(1));
    assert!(
        stderr(&o).contains("dvarapala-operator: "),
        "{}",
        stderr(&o)
    );
}
