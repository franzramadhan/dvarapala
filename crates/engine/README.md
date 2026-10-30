# dvarapala-engine

The verdict engine of [dvarapala](https://github.com/franzramadhan/dvarapala): token buckets, the client table,
flood detection (heavy hitters, rate baseline, source entropy), trusted
proxies and CIDR blocks, connection limits, the egress schedule, the
cluster sync model and the LLM sampling gate.

No I/O and no async runtime: callers pass the current time in, so every
decision is deterministic and testable. It has no dependencies, so it
embeds anywhere, including behind the C ABI
([`dvarapala-ffi`](https://crates.io/crates/dvarapala-ffi)).

Feature `ml` (off by default) adds an XGBoost JSON model scorer
(`TreeEnsemble`) and its only dependencies, `serde` and `serde_json`.

Part of [dvarapala](https://github.com/franzramadhan/dvarapala), an anti-DDoS gateway in Rust. Docs: <https://dvarapala.franzramadhan.dev/docs/>. License: MIT.
