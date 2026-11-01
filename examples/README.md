# Examples

Configs for common deployments. Each file starts with its use case and why
the values differ from the defaults. Every key is described in
[CONFIG.md](../CONFIG.md).

| File | Use case |
|---|---|
| [dvarapala.toml](dvarapala.toml) | Minimal reverse proxy with every section, mostly defaults |
| [reverse-proxy-tls.toml](reverse-proxy-tls.toml) | Public HTTPS endpoint, TLS to a private-CA upstream, behind a load balancer |
| [grpc.toml](grpc.toml) | gRPC API: HTTP/2 upstream, gRPC-shaped errors, tighter stream limits |
| [websocket.toml](websocket.toml) | Chat or live updates: rate limited upgrades, tunnel limits |
| [http3.toml](http3.toml) | HTTP/3 next to HTTPS, Retry under load (build with `--features http3`) |
| [l4-limits.toml](l4-limits.toml) | Public endpoint without a load balancer: tight connection caps, accept rate, slowloris timeouts |
| [forward-proxy.toml](forward-proxy.toml) | Egress rate compliance: calls to third-party APIs held to each provider's rate and concurrency |
| [cluster.toml](cluster.toml) | Replicas behind one load balancer sharing limits and heavy hitters through Redis or PostgreSQL (build with `--features redis` or `postgres`) |
| [ml.toml](ml.toml) | Learned scoring: an XGBoost model scores every client, LLM labels collect the next training set, a new model or threshold swaps in on `config_watch` without a restart (build with `--features ml`, [RFC 0029](../rfc/0029-ml-model-reload.md)) |
| [challenge.toml](challenge.toml) | Public website: browsers solve a proof of work during an attack instead of sharing the attack limit; JA4 rules and forwarding |
| [routes.toml](routes.toml) | One site, three policies: scanner paths denied, a low login rate, an API limited per key and exempt from the challenge |
| [pool.toml](pool.toml) | Three app servers without a load balancer: least requests, health checks, ejection and budgeted retries |
| [admin-ui.toml](admin-ui.toml) | Admin web console with OIDC login, on loopback behind a TLS terminator that serves it at `public_url` |
| [waf.toml](waf.toml) | Web app behind the OWASP CRS: a `coraza-spoa` sidecar over a Unix socket, observe first; [waf/](waf/) has the agent config, a compose file and a Kubernetes manifest |
| [xdp.toml](xdp.toml) | Linux host on the open internet: SYN and packet floods dropped in the NIC driver (build with `--features xdp`) |
| [kubernetes.yaml](kubernetes.yaml) | Kubernetes: a policy, an `HTTPRoute` and an `Ingress` labeled to go through gateways the operator runs, and network policies so nothing bypasses them ([RFC 0019](../rfc/0019-operator.md)) |
| [kubernetes-console-waf.yaml](kubernetes-console-waf.yaml) | Kubernetes: an operator gateway with the console, the WAF agent as a sidecar, a CA mount for the store and a network policy for the admin port ([RFC 0025](../rfc/0025-operator-gateway-parity.md)) |

Run one with `dvarapala serve --config examples/<file>`. Paths, names and
addresses are placeholders (`app.example`, `<cert dir>`, `192.0.2.0/24`).
Detection starts in `observe` mode everywhere: watch the
`dvarapala_detection_*` metrics settle before switching to `enforce`.
