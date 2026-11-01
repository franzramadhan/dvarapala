<p align="center">
  <img src="site/logo.svg" width="96" alt="dvarapala logo: a split temple gate">
</p>

<h1 align="center">dvarapala</h1>

<p align="center">
  <b>A guardian at the gate.</b> An anti-DDoS gateway in Rust, with protection from L4 to L7.
</p>

<p align="center">
  <a href="https://github.com/franzramadhan/dvarapala/actions/workflows/ci.yml"><img src="https://github.com/franzramadhan/dvarapala/actions/workflows/ci.yml/badge.svg" alt="ci"></a>
  <a href="https://github.com/franzramadhan/dvarapala/actions/workflows/coverage.yml"><img src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/franzramadhan/dvarapala/badges/tests.json" alt="tests"></a>
  <a href="https://github.com/franzramadhan/dvarapala/actions/workflows/coverage.yml"><img src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/franzramadhan/dvarapala/badges/coverage.json" alt="coverage"></a>
  <a href="https://github.com/franzramadhan/dvarapala/releases/latest"><img src="https://img.shields.io/github/v/release/franzramadhan/dvarapala" alt="release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="license"></a>
</p>

<p align="center">
  <a href="https://dvarapala.franzramadhan.dev"><b>Docs</b></a> ·
  <a href="#install">Install</a> ·
  <a href="CONFIG.md">Configuration</a> ·
  <a href="examples/README.md">Examples</a> ·
  <a href="ROADMAP.md">Roadmap</a> ·
  <a href="CHANGELOG.md">Changelog</a>
</p>

dvarapala sits in front of your app, bounds each client's connections and
requests, learns what normal traffic looks like, and drops floods before
they reach the upstream. It is named after the Dvarapala, the guardian
statues at Javanese temple gates.

## Ways to run it

| Mode | What it does | Start with |
|---|---|---|
| **Reverse proxy** | Protects your app from inbound floods: HTTP/1.1, HTTP/2, gRPC, WebSocket, optional HTTP/3 | [`dvarapala.toml`](examples/dvarapala.toml) |
| **Forward proxy** | Holds your outbound calls to each third-party API's agreed rate and concurrency | [`forward-proxy.toml`](examples/forward-proxy.toml) |
| **In process** | The same limits inside a Go, Python or JavaScript service, over a C ABI | [`sdk/`](sdk/README.md) |
| **Kubernetes** | Label an Ingress, HTTPRoute or GRPCRoute and the operator puts a dvarapala gateway in front of its Service | [`kubernetes.yaml`](examples/kubernetes.yaml) |

Either proxy mode scales out: replicas behind one load balancer share their
limits through Redis or PostgreSQL ([`cluster.toml`](examples/cluster.toml)).

## What it protects

Every layer is optional and configurable, and every verdict is a Prometheus
metric and a structured log line, so you can watch before you enforce.

| Layer | Protection | |
|---|---|---|
| **XDP** | Block list, per-source packet, SYN and UDP rates in the NIC driver; dynamic blocks fed by L4 and L7. Linux, feature `xdp` | [RFC 0011](rfc/0011-xdp.md) |
| **L4** | Connections per client and in total, accept rate, header, idle and slow-body timeouts, before any TLS or HTTP | [RFC 0009](rfc/0009-l4-limits.md) |
| **TLS** | rustls with ALPN, `SIGHUP` certificate reload, bounded handshakes, verified `https://` upstreams | [RFC 0003](rfc/0003-tls.md) |
| **QUIC** | HTTP/3 listener with Retry under load, connection and stream limits, no 0-RTT. Feature `http3` | [RFC 0006](rfc/0006-http3.md) |
| **HTTP/2** | Rapid reset, header list and keepalive limits; trailers and gRPC-shaped local errors | [RFC 0004](rfc/0004-http2-grpc.md) |
| **L7** | Token bucket per client with a bounded table; `X-Forwarded-For` only from trusted proxies | [RFC 0001](rfc/0001-foundation.md) |
| **Detection** | Heavy hitters, rate baseline, source entropy, optional XGBoost model; `observe` first, then `enforce` | [RFC 0002](rfc/0002-adaptive-detection.md) |
| **Challenge** | Proof-of-work page for browsers during an attack or always, stateless HMAC pass cookie; JA4 TLS fingerprints to deny, challenge or forward | [RFC 0012](rfc/0012-challenges.md) |
| **WAF** | OWASP Coraza with the Core Rule Set in a `coraza-spoa` sidecar inspects requests that passed the limits, over SPOP; `observe` first, fails closed, per-route opt-out | [RFC 0017](rfc/0017-waf.md) |
| **Operations** | Admin API with status, top talkers and manual blocks; `SIGHUP` or `POST /reload` applies the protection keys without a restart | [RFC 0014](rfc/0014-admin.md) |
| **Console** | Web console on the admin listener: live rates, top talkers, blocks and reload; login by admin token or OIDC, also through issuers that send no `email_verified` such as Cloudflare Access | [RFC 0018](rfc/0018-admin-ui.md), [RFC 0020](rfc/0020-oidc-email-trust.md) |
| **Console views** | The running config with secrets redacted, the WAF's matched rules and the agent's rule files, an `observe`/`enforce` switch until the next reload (`admin.mode_switch`), and a health page per layer from `GET /metrics` | [RFC 0021](rfc/0021-admin-ui-config-waf.md) |
| **Traffic history** | The console graph keeps the last 15 minutes in memory, so a reload or a new tab shows it at once; with `history.persist`, per-minute rows in the PostgreSQL store survive restarts and sum the replicas, up to 7 days | [RFC 0022](rfc/0022-traffic-history.md) |
| **LLM labels** | Sampled requests from worthwhile triggers (WAF matches, failed challenges, attacks, uncertain model scores, routes), redacted and sent off the request path to a System One decision model or an OpenAI-compatible chat model; the label goes to logs, metrics, the console and a training file, never to a verdict | [RFC 0023](rfc/0023-llm-labels.md) |
| **LLM label store** | With `ml.llm.persist`, every replica writes its labels as rows in the PostgreSQL store: the console's counts and recent labels cover all replicas and survive restarts, and `GET /llm/export` streams them as JSON lines for training | [RFC 0024](rfc/0024-llm-label-store.md) |
| **Replay** | `dvarapala replay` runs a config over a recorded access log on a virtual clock and reports what it would have throttled, dropped or challenged | [RFC 0016](rfc/0016-replay.md) |
| **Routes** | Per-route policy matched on host, path, method and client: deny, an extra bucket keyed by client, header or JA4, challenge exemption | [RFC 0013](rfc/0013-routes.md) |
| **Upstreams** | Pools of upstreams with round robin or least requests, active health checks, passive ejection and budgeted retries of idempotent requests | [RFC 0015](rfc/0015-upstream-pools.md) |
| **WebSocket** | Upgrades rate limited like any request; tunnel count, idle and lifetime limits | [RFC 0005](rfc/0005-websocket.md) |
| **Egress** | Per-destination rate, concurrency and bounded queue; provider `Retry-After` pauses; `CONNECT` tunnels | [RFC 0007](rfc/0007-forward-proxy.md) |
| **Embedding** | Rate limit, detection and connection limits for Go, Python and JavaScript, with HTTP middleware | [RFC 0008](rfc/0008-sdk.md) |
| **Cluster** | One per-client limit, egress budget and heavy hitter list across replicas, synced off the request path. Features `redis`, `postgres` | [RFC 0010](rfc/0010-shared-state.md) |
| **Kubernetes** | An operator: a `DvarapalaPolicy` and a label on a route; a webhook points the route at a managed gateway, `config_watch` reloads on policy edits | [RFC 0019](rfc/0019-operator.md) |
| **Operator gateways** | The gateway pods run the admin console behind their own Service, a `coraza-spoa` WAF sidecar, extra ConfigMap and Secret mounts, and pod labels; a route can opt in per rule | [RFC 0025](rfc/0025-operator-gateway-parity.md) |
| **SDK parity** | Per-route policy, manual blocks, egress shaping and live reload in the Go, Python and JavaScript packages, without the gateway | [RFC 0028](rfc/0028-sdk-parity.md) |
| **SDK packages** | `npm install dvarapala`, `pip install dvarapala` and `go get github.com/franzramadhan/dvarapala-go` with the prebuilt library inside, no Rust toolchain needed | [RFC 0026](rfc/0026-sdk-registries.md), [RFC 0027](rfc/0027-go-module.md) |
| **Model reload** | A retrained XGBoost model or a new threshold swaps in on reload or `config_watch`, without a restart; clients keep their features, a bad model is refused, the model in force shows by SHA-256 | [RFC 0029](rfc/0029-ml-model-reload.md) |

## Install

Static binaries for Linux (musl) and macOS, `x86_64` and `aarch64`:

```sh
brew install franzramadhan/tap/dvarapala
```

or

```sh
curl -fsSL https://dvarapala.franzramadhan.dev/install.sh | sh
```

The script checks the download against the release's `SHA256SUMS` and
installs to `/usr/local/bin` (when writable) or `~/.local/bin`.
`DVARAPALA_VERSION=v<version>` pins a release, `DVARAPALA_INSTALL=<dir>`
picks the directory. Tarballs are also on the
[releases](https://github.com/franzramadhan/dvarapala/releases) page.

From crates.io, built on your machine:

```sh
cargo install dvarapala                                  # default features
cargo install dvarapala --features ml,redis,postgres     # add features
cargo install dvarapala --no-default-features --features tls  # smallest build
```

| Feature | Default | Adds |
|---|---|---|
| `tls` | yes | TLS listener and `https://` upstreams (RFC 0003) |
| `ui` | yes | Admin web console with token and OIDC login (RFC 0018); turns on `tls` |
| `waf` | yes | WAF over an SPOP agent such as coraza-spoa (RFC 0017) |
| `replay` | yes | `dvarapala replay` (RFC 0016) |
| `llm` | yes | LLM labels for sampled traffic (RFC 0023); turns on `tls` |
| `ml` | no | XGBoost scoring (RFC 0002) |
| `redis` | no | Redis state backend across replicas (RFC 0010) |
| `postgres` | no | PostgreSQL state backend, persisted traffic history and LLM labels (RFC 0010, RFC 0022, RFC 0024) |
| `http3` | no | HTTP/3 listener over QUIC (RFC 0006), experimental; turns on `tls` |
| `xdp` | no | XDP fast path (RFC 0011), Linux only |

Container image (`linux/amd64`, `linux/arm64`), `FROM scratch` with the
static binary built with every feature (the stores, `ml`, `http3`, `xdp`),
running as UID 10001 on port 8080:

```sh
docker run --rm -p 8080:8080 \
  -e DVARAPALA__UPSTREAM=http://app.example:8081 \
  ghcr.io/franzramadhan/dvarapala:<version>
```

Pass a config with `-v ./dvarapala.toml:/etc/dvarapala.toml:ro` and
`serve --config /etc/dvarapala.toml`, or set every key as an environment
variable. Set `DVARAPALA__METRICS__LISTEN=0.0.0.0:9090` to scrape metrics
from outside the container. The image carries Alpine's root CAs, so
`https://` upstreams, OIDC issuers and TLS stores verify against public
roots; for a private CA set `upstream_tls.ca_file` or `store.ca_file`.

On Kubernetes, the operator (`ghcr.io/franzramadhan/dvarapala-operator`)
installs from the release's manifest:

```sh
kubectl apply --server-side -f \
  https://github.com/franzramadhan/dvarapala/releases/download/v<version>/operator.yaml
```

The SDKs install from their registries with the prebuilt library for
Linux (glibc 2.28 or newer) and macOS, `x86_64` and `aarch64` (RFC 0026,
RFC 0027):

Go:

```sh
go get github.com/franzramadhan/dvarapala-go@v<version>
```

Python:

```sh
pip install dvarapala
```

JavaScript:

```sh
npm install dvarapala
```

<details>
<summary><b>Build from source</b></summary>

The toolchain is pinned in `rust-toolchain.toml`. Optional protections are
cargo features, off by default:

```sh
cargo build --release                            # reverse and forward proxy, TLS, replay, console, WAF, LLM labels
cargo build --release --features http3           # + HTTP/3 over QUIC
cargo build --release --features ml              # + the XGBoost scorer
cargo build --release --features redis,postgres  # + shared state backends
cargo build --release --features xdp             # + the XDP fast path (Linux)
```

</details>

## Quick start

The smallest config:

```toml
listen = "0.0.0.0:8080"
upstream = "http://127.0.0.1:8081"
```

```sh
dvarapala serve --config dvarapala.toml
```

Everything else has a default: 20 requests per second per client (burst
40), detection in `observe` mode, metrics on `127.0.0.1:9090`. Environment
variables override the file (`DVARAPALA__RATE_LIMIT__RATE=5`).

- Every key and metric: [CONFIG.md](CONFIG.md)
- TLS, gRPC, WebSocket, HTTP/3, connection limits, forward proxy, clusters,
  XDP, the WAF and Kubernetes: [examples/](examples/README.md)

## How it works

```mermaid
flowchart TD
  P[packets] --> X[XDP]
  X --> L4[L4 limits]
  L4 --> T[TLS / QUIC, JA4]
  T --> B[blocks, JA4 rules, routes]
  B --> R[rate limit]
  R --> DT[detection]
  DT --> C[challenge]
  C --> W[WAF]
  W --> PL[pool]
  PL --> U[upstream]
  L4 -.->|block source| X
  DT -.->|block source| X
```

| Stage | Checks | Refuses with | |
|---|---|---|---|
| XDP | Blocked sources, packet and SYN rates per source, in the driver | drop | RFC 0011 |
| L4 limits | Connections per client and in total, accept rate, header and idle timeouts | close | RFC 0009 |
| TLS / QUIC | Bounded handshakes, the JA4 fingerprint of each ClientHello | close | RFC 0003, 0006, 0012 |
| Blocks, JA4 rules, routes | Manual blocks, `fingerprint.deny`, per-route deny and limits | `403` / `429` | RFC 0013, 0014 |
| Rate limit | A token bucket per client | `429` | RFC 0001 |
| Detection | Heavy hitters against a learned baseline | `403` | RFC 0002 |
| Challenge | During an attack, a proof of work earns a pass | proof-of-work page | RFC 0012 |
| WAF | OWASP Coraza with the CRS over SPOP | `403` | RFC 0017 |
| Pool | A healthy upstream endpoint, health checks and ejection | | RFC 0015 |

Each stage is cheaper than the next, so expensive work only happens for
traffic that survived the cheap checks. In `enforce` mode, sources refused
by L4 or dropped by detection are blocked in the XDP program for a while
(the dotted arrows). Both completed a TCP handshake, so a spoofed address
cannot get a victim blocked.

The admin API and its web console run on their own listener: manual
blocks, top talkers and reload apply to the running gateway in place. On
Kubernetes, the operator runs this same binary as a gateway in front of
each labeled route's Service.

One engine decides every verdict and does no I/O, so the binary and the
SDKs share the same logic.

<details>
<summary><b>Crates</b></summary>

| Crate | Role |
|---|---|
| `engine` | Verdicts, token buckets, detection sketches, egress schedule, route matching and keyed route limits. No I/O, no async runtime |
| `l4` | Listener wrapper: connection limits and timeouts |
| `l7` | `tower` layers: rate limit, detection, challenge, WAF client, console sessions and OIDC |
| `proxy` | Reverse and forward proxy, TLS, HTTP/2, HTTP/3, tunnels |
| `store` | Shared state backends: memory, Redis, PostgreSQL |
| `xdp` | XDP loader (`aya`) and the checked-in eBPF object |
| `xdp-common` | `no_std` packet parser and map layouts shared with the program |
| `xdp-ebpf` | The eBPF program, its own workspace on a pinned nightly |
| `ffi` | C ABI (`dvarapala.h`) for the SDKs |
| `node` | N-API addon for the JavaScript SDK |
| `dvarapala` | The binary: config, metrics, signals |
| `operator` | Kubernetes operator: policy CRD, route rewrite webhook, gateway controller |

Built on `tokio`, `hyper`, `tower`, `rustls`, `quinn`, `h3`, `redis`,
`tokio-postgres`, `aya` and `kube` (the operator); the console is SolidJS. CI fails when the idle binary goes over a
10 MB RSS budget.

</details>

## Project

> [!NOTE]
> 0.x is alpha: config keys and metrics may change between minor versions.

| | |
|---|---|
| **Changes** | [CHANGELOG.md](CHANGELOG.md) |
| **Roadmap** | Every feature lands through an RFC: [ROADMAP.md](ROADMAP.md), [rfc/](rfc/) |
| **Contributing** | Contributor and agent rules: [CLAUDE.md](CLAUDE.md) |
| **Security** | Report vulnerabilities privately: [SECURITY.md](SECURITY.md) |
| **License** | [MIT](LICENSE) |
| **Credits** | Coraza, coraza-spoa and the OWASP CRS: [CREDITS.md](CREDITS.md) |
