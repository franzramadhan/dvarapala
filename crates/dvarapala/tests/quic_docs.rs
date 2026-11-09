//! RFC 0036 case 12: the reference and the example list every `[quic]` key
//! and metric the RFC adds.

const KEYS: [&str; 3] = ["max_per_client", "accept_rate", "accept_burst"];
const METRICS: [&str; 2] = [
    "dvarapala_quic_rejected_total{reason}",
    "dvarapala_quic_clients",
];

fn read(name: &str) -> String {
    let path = format!("{}/../../{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

#[test]
fn config_reference_and_example_list_every_key_and_metric() {
    let (config, example) = (read("CONFIG.md"), read("examples/dvarapala.toml"));
    for k in KEYS {
        assert!(config.contains(&format!("| `{k}` |")), "CONFIG.md: {k}");
        assert!(example.contains(&format!("# {k} = ")), "example: {k}");
    }
    for m in METRICS {
        assert!(config.contains(&format!("`{m}`")), "CONFIG.md: {m}");
    }
}
