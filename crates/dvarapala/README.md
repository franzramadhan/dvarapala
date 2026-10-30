# dvarapala

Anti-DDoS gateway in Rust: L4 to L7 protection as a reverse proxy, a
forward proxy for outbound calls, or a Kubernetes gateway run by the
operator.

```sh
cargo install dvarapala
dvarapala serve --config dvarapala.toml
```

```toml
listen = "0.0.0.0:8080"
upstream = "http://127.0.0.1:8081"
```

It limits each client with a token bucket, detects floods against a
learned baseline (`observe` first, then `enforce`), and can add
connection limits, TLS, HTTP/2 and HTTP/3 limits, a proof-of-work
challenge, JA4 fingerprints, per-route policy, upstream pools, a WAF
sidecar (OWASP CRS), shared limits across replicas, an XDP fast path, an
admin API and web console, and LLM labels for sampled traffic.

| Feature | Default | Adds |
|---|---|---|
| `tls` | yes | TLS listener and `https://` upstreams |
| `ui` | yes | Admin web console with token and OIDC login |
| `waf` | yes | WAF over an SPOP agent such as coraza-spoa |
| `replay` | yes | `dvarapala replay` over a recorded access log |
| `llm` | yes | LLM labels for sampled traffic |
| `ml` | no | XGBoost scoring |
| `redis`, `postgres` | no | Shared state backends across replicas |
| `http3` | no | HTTP/3 over QUIC, experimental |
| `xdp` | no | XDP fast path, Linux only |

Binaries, Homebrew, the install script and the container image are in
the [README](https://github.com/franzramadhan/dvarapala#install). Every key: [Configuration](https://dvarapala.franzramadhan.dev/docs/configuration.html).

Part of [dvarapala](https://github.com/franzramadhan/dvarapala), an anti-DDoS gateway in Rust. Docs: <https://dvarapala.franzramadhan.dev/docs/>. License: MIT.
