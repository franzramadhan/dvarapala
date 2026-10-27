# dvarapala

Anti-DDoS gateway with L4 to L7 protection. Named after the Dvarapala, the
guardian statues that stand at Javanese temple gates.

Runs as:

- a standalone binary (reverse proxy or forward proxy)
- an embedded library through a Go SDK

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

| Mode            | Entry point                                      |
|-----------------|--------------------------------------------------|
| Reverse proxy   | `dvarapala serve --mode reverse --upstream ...`  |
| Forward proxy   | `dvarapala serve --mode forward` (HTTP CONNECT)  |
| Embedded (Rust) | `tower::Layer` and a `TcpListener` wrapper       |
| Embedded (other)| C ABI (`cdylib` + generated header) for Go, Python, Node, etc. |

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

### Layout (planned, cargo workspace)

```
crates/
  engine/       verdict engine, rules, limiters (no I/O, no tokio)
  l4/           listener wrapper, conn limits, timeouts
  l7/           tower layers: rate limit, rules, challenges
  proxy/        reverse and forward proxy core
  store/        memory and redis backends
  xdp/          aya eBPF programs (linux only, optional)
  ffi/          C ABI for non-Rust embedders
  dvarapala/    binary
```

`engine` stays free of I/O and async runtime so it can embed anywhere,
including through the C ABI.

## Status

Design stage, 0.x is alpha. Features land through RFCs: see
[ROADMAP.md](ROADMAP.md) and [rfc/](rfc/). Contributor and agent rules are
in [CLAUDE.md](CLAUDE.md).
