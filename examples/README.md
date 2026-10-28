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

Run one with `dvarapala serve --config examples/<file>`. Paths, names and
addresses are placeholders (`app.example`, `<cert dir>`, `192.0.2.0/24`).
Detection starts in `observe` mode everywhere: watch the
`dvarapala_detection_*` metrics settle before switching to `enforce`.
