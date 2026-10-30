# dvarapala-l7

HTTP protection layers for [dvarapala](https://github.com/franzramadhan/dvarapala), as `tower` layers that ask
[`dvarapala-engine`](https://crates.io/crates/dvarapala-engine) for a
verdict before the request goes on: the per-client rate limit
(`RateLimitLayer` with `RateLimitConfig`), flood detection, the
optional `Scoring` hook, the proof-of-work challenge, JA4 fingerprint
rules, per-route policy and the admin API parsing.

| Feature | Adds |
|---|---|
| `waf` | WAF client over SPOP (coraza-spoa) |
| `ui` | Console sessions and OIDC login |
| `replay` | Replay of a recorded access log on a virtual clock |
| `llm` | Request and reply format for LLM labels |

[`crates/dvarapala/src/layer.rs`](https://github.com/franzramadhan/dvarapala/blob/main/crates/dvarapala/src/layer.rs)
shows how the binary builds the layers from its configuration.

Part of [dvarapala](https://github.com/franzramadhan/dvarapala), an anti-DDoS gateway in Rust. Docs: <https://dvarapala.franzramadhan.dev/docs/>. License: MIT.
