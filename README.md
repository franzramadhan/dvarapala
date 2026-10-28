# dvarapala

[![ci](https://github.com/franzramadhan/dvarapala/actions/workflows/ci.yml/badge.svg)](https://github.com/franzramadhan/dvarapala/actions/workflows/ci.yml)
[![tests](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/franzramadhan/dvarapala/badges/tests.json)](https://github.com/franzramadhan/dvarapala/actions/workflows/coverage.yml)
[![coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/franzramadhan/dvarapala/badges/coverage.json)](https://github.com/franzramadhan/dvarapala/actions/workflows/coverage.yml)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Anti-DDoS gateway with L4 to L7 protection. Named after the Dvarapala, the
guardian statues that stand at Javanese temple gates.

Runs as a standalone reverse proxy today. A forward proxy mode and
embedding (Rust crate, C ABI) are planned.

## Features

Shipped in the latest release (see [CHANGELOG.md](CHANGELOG.md)):

- Token bucket rate limit per client, bounded client table, trusted proxy
  `X-Forwarded-For` handling ([RFC 0001](rfc/0001-foundation.md))
- Adaptive detection: heavy hitters, rate baseline, source entropy, optional
  XGBoost tree model; `observe` or `enforce` ([RFC 0002](rfc/0002-adaptive-detection.md))
- TLS listener with ALPN (`h2`, `http/1.1`), `SIGHUP` certificate reload,
  bounded handshakes, `https://` upstreams ([RFC 0003](rfc/0003-tls.md))
- Cleartext HTTP/1.1 and h2c inbound, HTTP/1.1 to the upstream
- Prometheus metrics on a separate listener

Next: HTTP/2 upstreams and gRPC ([RFC 0004](rfc/0004-http2-grpc.md)),
WebSocket ([RFC 0005](rfc/0005-websocket.md)). See [ROADMAP.md](ROADMAP.md).

## Quick start

Download a binary from the
[releases](https://github.com/franzramadhan/dvarapala/releases) page (check
it against `SHA256SUMS`), or build one:

```sh
cargo build --release
./target/release/dvarapala serve --config examples/dvarapala.toml
```

Every key and default is in [CONFIG.md](CONFIG.md). Environment variables
override the file: `DVARAPALA__RATE_LIMIT__RATE=5`.

## Architecture

```
                 +-------------------------------------------------+
  packets  --->  | L3/L4 fast path (eBPF/XDP, optional)            |
                 |  SYN flood, UDP flood, per-IP pps, blocklist    |
                 +-------------------------+-----------------------+
                                           |
                 +-------------------------v-----------------------+
  conns    --->  | L4 userspace                                    |
                 |  conn limits per IP, accept rate, idle/slowloris|
                 |  timeouts, TLS handshake budget                 |
                 +-------------------------+-----------------------+
                                           |
                 +-------------------------v-----------------------+
  requests --->  | L7 pipeline (ordered middleware chain)          |
                 |  1. identity: IP, CIDR, JA3/JA4, headers        |
                 |  2. rate limit: token bucket per key            |
                 |  3. rules: path, method, size, header checks    |
                 |  4. challenge: JS / PoW / cookie on suspicion   |
                 |  5. verdict: allow | throttle | challenge | drop |
                 +-------------------------+-----------------------+
                                           |
                 +-------------------------v-----------------------+
                 | Proxy core: reverse (upstream pool) or forward  |
                 +-------------------------------------------------+

  Shared: state store (local memory, Redis for cluster), config hot-reload,
          metrics (Prometheus), structured logs.
```

### Core idea

One engine, three entry points. The protection logic lives in a single
`engine` package that decides a verdict for a connection or request. The
binary and the SDK are thin wrappers around it.

| Mode            | Entry point                                      | Status  |
|-----------------|--------------------------------------------------|---------|
| Reverse proxy   | `dvarapala serve --config <file>`                | shipped |
| Forward proxy   | HTTP CONNECT                                     | planned |
| Embedded (Rust) | `tower::Layer` and a `TcpListener` wrapper       | planned |
| Embedded (other)| C ABI (`cdylib` + generated header) for Go, Python, Node, etc. | planned |

### Stack

Rust, for a small memory footprint without a GC and memory safety at the
trust boundary.

| Concern     | Crate                         |
|-------------|-------------------------------|
| Async I/O   | `tokio`                       |
| HTTP/1, 2   | `hyper`, `hyper-util`         |
| Middleware  | `tower`                       |
| TLS         | `rustls`                      |
| eBPF/XDP    | `aya` (pure Rust, no libbpf)  |
| C bindings  | `cbindgen`                    |
| Metrics     | `metrics` + Prometheus exporter |

### Layout (cargo workspace)

```
crates/
  engine/       verdict engine, rules, limiters (no I/O, no tokio)
  l7/           tower layers: rate limit, detection
  proxy/        reverse proxy core, TLS
  dvarapala/    binary
  l4/ store/ xdp/ ffi/   planned: added with the RFC that needs them
```

`engine` stays free of I/O and async runtime so it can embed anywhere,
including through the C ABI.

## Status

0.x is alpha: config keys and metrics may change between minor versions.
Features land through RFCs: see
[ROADMAP.md](ROADMAP.md) and [rfc/](rfc/). Contributor and agent rules are
in [CLAUDE.md](CLAUDE.md).

## Security

Report vulnerabilities privately, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
