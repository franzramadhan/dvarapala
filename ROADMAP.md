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
| [0022](rfc/0022-traffic-history.md) | Traffic history for the console: an in-memory ring (`GET /history`), optionally a per-minute history in the PostgreSQL store (`history.persist`), so the overview graph survives a reload and a restart | implemented | v0.15.0 |
| [0023](rfc/0023-llm-labels.md) | LLM labels for sampled traffic: on-demand from the console, worthwhile triggers (WAF, failed challenges, attack, uncertain `[ml]` scores, routes) sampled off the request path to a System One decision model (Clef, Jev) or an OpenAI-compatible chat model; labels for logs, metrics, the console and `[ml]` training, never verdicts | implemented | v0.16.0 |
| [0024](rfc/0024-llm-label-store.md) | LLM labels in the PostgreSQL store (`ml.llm.persist`): every replica writes its labels as rows, so training data, the console's recent labels and counts cover all replicas and survive restarts; `GET /llm/export` streams them as JSON lines | implemented | v0.17.0 |
| [0025](rfc/0025-operator-gateway-parity.md) | Operator gateways with the admin listener and console, the WAF agent as a sidecar over a Unix socket, read-only ConfigMap and Secret mounts, pod labels, and opt-in per route rule, so a policy can replace a hand-written gateway | implemented | v0.18.0 |
| [0026](rfc/0026-sdk-registries.md) | SDK packages on npm and PyPI: the Python and JavaScript SDKs with the prebuilt library inside (per-platform wheels, an npm package per platform), published by `release.yml` with trusted publishing and provenance; Linux libraries built for glibc 2.28 | implemented | v0.20.0 |
| [0027](rfc/0027-go-module.md) | Go module with prebuilt libraries: each release pushes the Go package, the header and a stripped static library per platform to `franzramadhan/dvarapala-go` and tags it, so `go get` works without Rust | implemented | v0.20.0 |
| [0028](rfc/0028-sdk-parity.md) | SDK parity: per-route policy (`dv_check_request`, routes moved to `engine`), manual blocks, egress shaping without the forward proxy, and live reload that keeps client counts, in the C ABI and the Go, Python and JavaScript packages | implemented | v0.19.0 |
| [0029](rfc/0029-ml-model-reload.md) | Reload the scoring model in place: `ml.model` and `ml.threshold` on `SIGHUP`, `POST /reload` and `config_watch`, client features kept, a bad model refused, the model in force by SHA-256 | implemented | v0.21.0 |
| [0032](rfc/0032-adaptive-concurrency.md) | Adaptive concurrency limit for the upstream (`[concurrency]`): `fixed` or latency `gradient`, sheds with `503` and `Retry-After`, challenge-passed and low-score clients admitted first, attack heavy hitters last | draft | v0.23.0 |

## Shipped without an RFC

Packaging, install channels and docs need no RFC (see `CLAUDE.md`).

| Change | Release |
|---|---|
| `install.sh` (served at `/install.sh`) and the Homebrew tap `franzramadhan/homebrew-tap` | v0.6.1 |
| Container image `ghcr.io/franzramadhan/dvarapala` for linux/amd64 and linux/arm64 | v0.6.1 |
| The Redis and PostgreSQL stores in the container image | v0.6.2 |
| Every feature (`ml`, `http3`, `xdp` too) in the container image | v0.19.1 |
| The crates on crates.io (`cargo install dvarapala`), published by `release.yml` with trusted publishing from v0.16.1 | v0.16.0 |
| A README per published crate, install steps for the Python, JavaScript and Go SDKs | v0.16.1 |
