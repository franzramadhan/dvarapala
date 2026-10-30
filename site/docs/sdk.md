---
title: SDKs
---

For services that cannot sit behind the proxy, the SDKs run the same
protection in process: the per-client rate limit, flood detection and the
connection limits of `[l4]`. Each package is a thin layer over one C ABI
(`crates/ffi`, header `dvarapala.h`), so the verdicts match the gateway's.

Settings take the [Configuration](configuration.html) names with the
gateway's defaults. A bad key or value is an error that names it.

## Keys

| Accepted in process | |
|---|---|
| `rate_limit.rate`, `rate_limit.burst`, `rate_limit.max_clients` | The per-client bucket |
| `trusted_proxies` | Peers allowed to set `X-Forwarded-For` |
| `detection.*` (every key of `[detection]`) | Flood detection, `observe` or `enforce` |
| `l4.enabled`, `l4.max_connections`, `l4.max_per_client`, `l4.accept_rate`, `l4.accept_burst`, `l4.prefix_v4`, `l4.prefix_v6`, `l4.max_clients`, `l4.exempt` | Connection limits on accept |

The gateway's own server keys are refused with `does not apply
in-process`: `mode`, `listen`, `upstream`, `upstream_protocol`, `[metrics]`,
`[ml]`, `[tls]`, `[upstream_tls]`, `[http2]`, `[upgrade]`, `[forward]` and
the `[l4]` timeouts (`header_timeout`, `idle_timeout`, `min_body_rate`).

Every other key is refused with `is not a key`, because the SDKs do not
have that layer: `rate_limit.enabled` (leave the guard out instead),
`[challenge]`, `[fingerprint]`, `[[routes]]`, `[waf]`, `[store]`,
`[admin]`, `[pool]`, `[xdp]` and `[quic]`. Run the gateway for those.

## Rust

The crates embed directly, as a git dependency (they are not on
crates.io): `dvarapala-l7` has the `tower` layers (`RateLimitLayer` with
`RateLimitConfig`, including detection and the optional `Scoring` hook),
`dvarapala-l4` the listener wrapper, `dvarapala-engine` the verdict engine
with no I/O. `crates/dvarapala/src/layer.rs` shows how the binary builds
them from the configuration.

```toml
[dependencies]
dvarapala-l7 = { git = "https://github.com/franzramadhan/dvarapala", tag = "v<version>" }
```

## Go

```go
import "github.com/franzramadhan/dvarapala/sdk/go"

g, err := dvarapala.New(dvarapala.Config{"rate_limit.rate": "20"})
if err != nil {
    log.Fatal(err)
}
l, _ := net.Listen("tcp", ":8080")
http.Serve(g.Listener(l), g.Middleware(mux))
```

`Middleware` answers `429` with `Retry-After`, or `403` with the connection closed, as the gateway does;
`Listener` applies the connection limits on accept. The package links the
static library: build it with `cargo build --release -p dvarapala-ffi`.

## Python

```python
from dvarapala import Guard, ASGIMiddleware

guard = Guard({"rate_limit.rate": 20, "detection.mode": "enforce"})
app = ASGIMiddleware(app, guard)
```

`WSGIMiddleware` does the same for WSGI apps. ASGI and WSGI expose no
accepted connections, so for the `[l4]` limits call
`guard.conn_open(ip)` on accept and `guard.conn_close(handle)` on close
from your server's hook. The library is found at `DVARAPALA_LIB`, else
next to the package.

## JavaScript and TypeScript

```js
const { Guard } = require('dvarapala');

const guard = new Guard({ 'rate_limit.rate': 20 });
const limit = guard.middleware();
guard.attach(http.createServer((req, res) => limit(req, res, () => res.end('ok'))));
```

`middleware()` fits Node's `http` and Express; `attach` applies the
connection limits to a server's sockets before any request is read. Types
ship in `index.d.ts`. The N-API addon is found at `DVARAPALA_NODE`, else
next to the package.

## Libraries

Each [release](https://github.com/franzramadhan/dvarapala/releases)
attaches `dvarapala-sdk-<tag>-<target>.tar.gz` for glibc Linux and macOS:
the static and shared library, the Node addon and the header. Packages
are not on a registry yet.

The design is in [RFC 0008](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0008-sdk.md),
and build and test commands per package in
[sdk/README.md](https://github.com/franzramadhan/dvarapala/blob/main/sdk/README.md).
