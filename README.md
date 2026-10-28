# dvarapala

[![ci](https://github.com/franzramadhan/dvarapala/actions/workflows/ci.yml/badge.svg)](https://github.com/franzramadhan/dvarapala/actions/workflows/ci.yml)
[![tests](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/franzramadhan/dvarapala/badges/tests.json)](https://github.com/franzramadhan/dvarapala/actions/workflows/coverage.yml)
[![coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/franzramadhan/dvarapala/badges/coverage.json)](https://github.com/franzramadhan/dvarapala/actions/workflows/coverage.yml)
[![release](https://img.shields.io/github/v/release/franzramadhan/dvarapala)](https://github.com/franzramadhan/dvarapala/releases/latest)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**An anti-DDoS gateway in Rust, with protection from L4 to L7.** It sits in
front of your app, bounds each client's connections and requests, learns
what normal traffic looks like, and drops floods before they reach the
upstream.

Named after the Dvarapala, the guardian statues at Javanese temple gates.

Docs: **[dvarapala.franzramadhan.dev](https://dvarapala.franzramadhan.dev)**

## Three ways to run it

| Mode | What it does | Start with |
|---|---|---|
| **Reverse proxy** | Protects your app from inbound floods: HTTP/1.1, HTTP/2, gRPC, WebSocket, optional HTTP/3 | [`examples/dvarapala.toml`](examples/dvarapala.toml) |
| **Forward proxy** | Holds your outbound calls to each third-party API's agreed rate and concurrency | [`examples/forward-proxy.toml`](examples/forward-proxy.toml) |
| **In process** | The same limits inside a Go, Python or JavaScript service, over a C ABI | [`sdk/`](sdk/README.md) |

## What it protects

| Layer | Protection | RFC |
|---|---|---|
| L4 | Open connections per client and in total, accept rate per client, header, idle and slow-body timeouts, before any TLS or HTTP | [RFC 0009](rfc/0009-l4-limits.md) |
| TLS | rustls with ALPN, `SIGHUP` certificate reload, bounded handshakes, verified `https://` upstreams | [RFC 0003](rfc/0003-tls.md) |
| QUIC | Optional HTTP/3 listener (feature `http3`): Retry under load, connection and stream limits, no 0-RTT, `Alt-Svc` on TCP | [RFC 0006](rfc/0006-http3.md) |
| HTTP/2 | Rapid reset, header list and keepalive limits; h2c or ALPN upstreams, trailers, gRPC-shaped local errors | [RFC 0004](rfc/0004-http2-grpc.md) |
| L7 | Token bucket per client with a bounded table, `X-Forwarded-For` only from trusted proxies | [RFC 0001](rfc/0001-foundation.md) |
| Detection | Heavy hitters, rate baseline, source entropy, optional XGBoost model; `observe` first, then `enforce` | [RFC 0002](rfc/0002-adaptive-detection.md) |
| WebSocket | Upgrades rate limited like any request; tunnel count, idle and lifetime limits | [RFC 0005](rfc/0005-websocket.md) |
| Egress | Per-destination rate, concurrency and bounded queue, provider `Retry-After` pauses, `CONNECT` tunnels | [RFC 0007](rfc/0007-forward-proxy.md) |
| Embedding | Rate limit, detection and connection limits for Go, Python and JavaScript, with HTTP middleware | [RFC 0008](rfc/0008-sdk.md) |

Every layer is optional and configurable. Every verdict is a Prometheus
metric on a separate listener and a structured log line, so you can watch
before you enforce.

## Quick start

Install the latest release (static Linux musl or macOS, `x86_64` or
`aarch64`):

```sh
brew install franzramadhan/tap/dvarapala
# or: checks SHA256SUMS, installs to /usr/local/bin or ~/.local/bin
curl -fsSL https://dvarapala.franzramadhan.dev/install.sh | sh
dvarapala serve --config dvarapala.toml
```

`DVARAPALA_VERSION=v<version>` pins a release and `DVARAPALA_INSTALL=<dir>`
picks the directory. Or download a tarball from the
[releases](https://github.com/franzramadhan/dvarapala/releases) page and
check it with `shasum -a 256 -c SHA256SUMS --ignore-missing`.

Or build from source (toolchain pinned in `rust-toolchain.toml`):

```sh
cargo build --release                    # reverse and forward proxy, TLS
cargo build --release --features http3   # plus HTTP/3 over QUIC
cargo build --release --features ml      # plus the XGBoost scorer
./target/release/dvarapala serve --config examples/dvarapala.toml
```

The smallest config:

```toml
listen = "0.0.0.0:8080"
upstream = "http://127.0.0.1:8081"
```

Everything else has a default: 20 requests per second per client (burst
40), detection in `observe` mode, metrics on `127.0.0.1:9090`. Every key
is in [CONFIG.md](CONFIG.md); environment variables override the file
(`DVARAPALA__RATE_LIMIT__RATE=5`). More deployments, from TLS and gRPC to
HTTP/3 and connection limits, are in [examples/](examples/README.md).

## Architecture

```
  connections --> L4        caps per client and in total, accept rate,   --> close
                            header, idle and body timeouts
                    |
                    v
                  listener  TCP, TLS (ALPN h2, http/1.1) or QUIC (HTTP/3)
                    |
                    v
  requests -----> L7        identity: peer, or X-Forwarded-For if trusted
                            rate limit: token bucket per client         --> 429
                            detection: heavy hitters, baseline, entropy --> 403
                    |
                    v
                  proxy     reverse: HTTP/1.1, HTTP/2, WebSocket to the upstream
                            forward: shaped per destination, or CONNECT
```

One engine, several entry points. The `engine` crate decides every verdict
and does no I/O, so the binary and the SDKs share the same logic.

| Crate | Role |
|---|---|
| `engine` | Verdicts, token buckets, detection sketches, egress schedule. No I/O, no async runtime |
| `l4` | Listener wrapper: connection limits and timeouts |
| `l7` | `tower` layers: rate limit, detection |
| `proxy` | Reverse and forward proxy, TLS, HTTP/2, HTTP/3, tunnels |
| `ffi` | C ABI (`dvarapala.h`) for the SDKs |
| `node` | N-API addon for the JavaScript SDK |
| `dvarapala` | The binary: config, metrics, signals |

Built on `tokio`, `hyper`, `tower`, `rustls`, `quinn` and `h3`. The idle
binary has a 10 MB RSS budget that CI checks on every change. Rust crates
embed as a git dependency; they are not on crates.io.

## Status

0.x is alpha: config keys and metrics may change between minor versions.
Release notes are in [CHANGELOG.md](CHANGELOG.md).

Every feature lands through an RFC: see [ROADMAP.md](ROADMAP.md) and
[rfc/](rfc/). Accepted: shared state across replicas through Redis or PostgreSQL
([RFC 0010](rfc/0010-shared-state.md)) and an XDP fast path for packet
floods ([RFC 0011](rfc/0011-xdp.md)). Request rules and challenges,
sketched in [RFC 0001](rfc/0001-foundation.md), have no RFC yet.
Contributor and agent rules are in [CLAUDE.md](CLAUDE.md).

## Security

Report vulnerabilities privately, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
