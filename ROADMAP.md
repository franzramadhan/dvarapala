# Roadmap

Every feature starts as an RFC (`rfc/`, see `CLAUDE.md`). A release lists
the RFCs it implements. Versions stay 0.x (alpha) until a 1.0 is decided.

| RFC | Feature | Status | Target |
|---|---|---|---|
| [0001](rfc/0001-foundation.md) | Foundation: engine, L7 rate limit, reverse proxy | implemented | v0.1.0 |
| [0002](rfc/0002-adaptive-detection.md) | Adaptive detection: heavy hitters, baseline, entropy, optional tree model | implemented | v0.2.0 |
| [0003](rfc/0003-tls.md) | TLS termination with ALPN, HTTPS upstreams, bounded handshakes | implemented | v0.3.0 |
| [0004](rfc/0004-http2-grpc.md) | HTTP/2 upstreams, trailers, gRPC-shaped errors, HTTP/2 flood limits | implemented | v0.4.0 |
| [0005](rfc/0005-websocket.md) | WebSocket upgrade pass-through with tunnel limits | implemented | v0.4.0 |
| [0006](rfc/0006-http3.md) | Optional HTTP/3 over QUIC with Retry under load | implemented | v0.5.0 |
| [0007](rfc/0007-forward-proxy.md) | Forward proxy with per-destination egress rate shaping | implemented | v0.5.0 |
| [0008](rfc/0008-sdk.md) | SDKs for Go, Python and JavaScript over a C ABI | implemented | v0.5.0 |
| [0009](rfc/0009-l4-limits.md) | L4 connection limits per client and in total, accept rate, header, idle and body timeouts | implemented | v0.5.0 |
| [0010](rfc/0010-shared-state.md) | Shared state for clusters: per-client limit, egress budget and heavy hitters across replicas via Redis or PostgreSQL | implemented | v0.6.0 |
| [0011](rfc/0011-xdp.md) | XDP fast path: block list, per-source packet and SYN rates at the driver | implemented | v0.6.0 |
| [0012](rfc/0012-challenges.md) | Proof-of-work challenges with a signed pass, JA4 fingerprints with deny and challenge rules | implemented | v0.7.0 |
| [0013](rfc/0013-routes.md) | Per-route policy: deny, extra rate limits keyed by client, header or JA4, challenge exemptions, matched on host, path, method and client | implemented | v0.8.0 |
| [0014](rfc/0014-admin.md) | Admin API (status, top talkers, manual blocks, reload) and `SIGHUP` config reload of the protection keys without a restart | implemented | v0.9.0 |
| [0015](rfc/0015-upstream-pools.md) | Upstream pools: round robin or least requests, active health checks, passive ejection, budgeted retries of idempotent requests | implemented | v0.10.0 |
| [0016](rfc/0016-replay.md) | `dvarapala replay`: a config's protection layers over a recorded JSON Lines access log on a virtual clock, with the verdict counts | implemented | v0.11.0 |
| [0017](rfc/0017-waf.md) | WAF: a sidecar agent over SPOP (`coraza-spoa`: OWASP Coraza with the CRS) inspects requests that passed the limits, `observe` then `enforce`, fail closed, off until enabled | implemented | v0.12.0 |
| [0018](rfc/0018-admin-ui.md) | Admin web UI on the admin listener (`admin.ui_enabled`): live overview, top talkers, blocks, reload; login by token or OIDC | implemented | v0.12.0 |
| [0019](rfc/0019-operator.md) | Kubernetes operator: label an Ingress, HTTPRoute or GRPCRoute and a webhook routes it through a managed dvarapala gateway, policy CRD, reload on policy change | implemented | v0.13.0 |
| [0020](rfc/0020-oidc-email-trust.md) | Console OIDC login trusts the issuer's email without `email_verified` (`admin.oidc.require_email_verified = false`), for Cloudflare Access | implemented | v0.13.0 |
| [0021](rfc/0021-admin-ui-config-waf.md) | Console: the running config (secrets redacted), a WAF page with matched rules and the agent's rule files, an `observe`/`enforce` switch until the next reload (`admin.mode_switch`), health pages per layer from `GET /metrics` | implemented | v0.14.0 |
