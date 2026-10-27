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
| Embedded SDK    | `net.Listener` wrapper and `http.Handler` middleware |

### Layout (planned)

```
cmd/dvarapala/      binary entry point
engine/             verdict engine, rule evaluation
l4/                 listener wrapper, conn limits, timeouts
l7/                 http middleware chain, challenges
limiter/            token bucket, sliding window
store/              memory and redis backends
xdp/                eBPF programs (linux only, optional)
sdk/                public Go API for embedding
```

## Status

Design stage.
