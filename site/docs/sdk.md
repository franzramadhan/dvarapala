---
title: SDKs
---

For services that cannot sit behind the proxy, the SDKs run the same
protection in process: the per-client rate limit, flood detection, the
connection limits of `[l4]`, per-route policy, manual blocks, egress
shaping and live reload. Each package is a thin layer over one C ABI
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
| `routes` | `[[routes]]` as a JSON array; `key = "ja4"`, `challenge` and `waf` are refused |
| `forward.destinations` | `[[forward.destinations]]` as a JSON array, for egress shaping; `max_concurrent` is refused (hold a semaphore of your language instead) |
| `admin.max_blocks`, `admin.max_block_ttl` | Limits of the manual block list |

Python and JavaScript take a list of dicts or objects for `routes` and
`forward.destinations` and encode it; Go takes the JSON text.

The gateway's own server keys are refused with `does not apply
in-process`: `mode`, `listen`, `upstream`, `upstream_protocol`, `[metrics]`,
`[ml]`, `[tls]`, `[upstream_tls]`, `[http2]`, `[upgrade]`, the other
`[forward]` and `[admin]` keys and the `[l4]` timeouts (`header_timeout`,
`idle_timeout`, `min_body_rate`).

Every other key is refused with `is not a key`, because the SDKs do not
have that layer: `rate_limit.enabled` (leave the guard out instead),
`[challenge]`, `[fingerprint]`, `[waf]`, `[store]`, `[pool]`, `[xdp]` and
`[quic]`. Run the gateway for those.

## Routes, blocks, egress and reload

[RFC 0028](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0028-sdk-parity.md)
brings four gateway features into every SDK:

- **Routes:** each middleware applies `routes` as the gateway does: a
  denied route drops before any bucket, a route with `rate` adds its own
  bucket per client or per header (`key = "header:x-api-key"`). Input the
  guard refuses (a field over 8 KiB, a newline in a header value, no
  method or path) gets `400` and the connection closed; the app never
  sees it.
- **Blocks:** `block(cidr, ttl)`, `unblock(cidr)` and `blocks()`. A
  blocked client is dropped by every check and refused a connection.
- **Egress:** a destination's `rate`, `burst`, `max_queue`, `max_wait`
  and `max_pause`, without the forward proxy. Go `g.Egress(ctx, dest)`
  and `g.Transport(base)` (pauses on `429` or `503` with `Retry-After`),
  Python `await guard.egress(dest)` and `guard.egress_wait(dest)`,
  JavaScript `await guard.egress(dest)`. A wait is spent once handed out,
  even when the caller gives up.
- **Reload:** `reload(config)` applies a new config in place, keeping
  client counts, the detection baseline, blocks and egress queues. A key
  that only applies at creation (`rate_limit.max_clients`, `[l4]`, the
  detector's own keys, `admin.max_blocks`) fails the reload and leaves
  the guard as it was.

Each process has its own guard. Behind several workers or replicas, a
client's limit and a provider's budget multiply by their number: divide
`rate_limit.rate`, the route rates and each destination's `rate` by it,
and block on every process.

## Rust

The crates are on crates.io: `dvarapala-l7` has the `tower` layers (`RateLimitLayer` with
`RateLimitConfig`, including detection and the optional `Scoring` hook),
`dvarapala-l4` the listener wrapper, `dvarapala-engine` the verdict engine
with no I/O. `crates/dvarapala/src/layer.rs` shows how the binary builds
them from the configuration.

```toml
[dependencies]
dvarapala-l7 = "<version>"
```

## Go

```sh
go get github.com/franzramadhan/dvarapala-go@v<version>
```

```go
import dvarapala "github.com/franzramadhan/dvarapala-go"

g, err := dvarapala.New(dvarapala.Config{"rate_limit.rate": "20"})
if err != nil {
    log.Fatal(err)
}
l, _ := net.Listen("tcp", ":8080")
http.Serve(g.Listener(l), g.Middleware(mux))
```

`Middleware` answers `429` with `Retry-After`, or `403` with the connection closed, as the gateway does;
`Listener` applies the connection limits on accept.
[RFC 0027](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0027-go-module.md):
each release generates the module from `sdk/go` with the static library
prebuilt for Linux (glibc 2.28 or later) and macOS, on amd64 and arm64.
It needs cgo and a C toolchain, no Rust. Without cgo, or on another
platform, the build stops at
`undefined: dvarapala_needs_cgo_on_linux_or_darwin_with_amd64_or_arm64`.

## Platforms

[RFC 0026](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0026-sdk-registries.md):
the PyPI and npm packages carry the native library for:

| Platform | PyPI wheel | npm package |
|---|---|---|
| Linux x86_64 (glibc 2.28 or later) | `manylinux_2_28_x86_64` | `@dvarapala/linux-x64-gnu` |
| Linux aarch64 (glibc 2.28 or later) | `manylinux_2_28_aarch64` | `@dvarapala/linux-arm64-gnu` |
| macOS Apple silicon | `macosx_11_0_arm64` | `@dvarapala/darwin-arm64` |
| macOS Intel | `macosx_11_0_x86_64` | `@dvarapala/darwin-x64` |

On another platform (Alpine with musl, Windows) `pip` finds no matching
distribution, and `require('dvarapala')` throws naming the platform.
Build the library from source there, `cargo build --release -p
dvarapala-ffi` (Python, Go) or `-p dvarapala-node` (JavaScript), and
point the package at it with `DVARAPALA_LIB` or `DVARAPALA_NODE`. Each
release also attaches the libraries as
`dvarapala-sdk-<tag>-<target>.tar.gz`.

## Python

Python 3.10 or later, no dependencies:

```sh
pip install dvarapala      # or: uv add dvarapala
```

The wheel carries the library; `DVARAPALA_LIB` overrides its path.

For an ASGI app (FastAPI, Starlette, Django ASGI), wrap it:

```python
from fastapi import FastAPI
from dvarapala import ASGIMiddleware, Guard

guard = Guard({
    "rate_limit.rate": 20,
    "rate_limit.burst": 40,
    "trusted_proxies": ["10.0.0.0/8"],  # your load balancer
    "detection.mode": "enforce",
})
app = ASGIMiddleware(FastAPI(), guard)
```

`WSGIMiddleware(app, guard)` does the same for Flask or Django WSGI. Both
answer `429` with `Retry-After`, or `403` with `Connection: close`, and
pass every other request to the app. A request the guard cannot read (no
peer address, as on a Unix socket, or bad input) gets `400`: the guard
fails closed.

Elsewhere, ask the guard directly:

```python
from dvarapala import ALLOW, THROTTLE, Guard

v = guard.check(peer_ip, request.headers.get("x-forwarded-for"))
if v.kind == THROTTLE:
    ...  # refuse; retry after v.retry_after seconds
elif v.kind != ALLOW:
    ...  # DROP: refuse and close
```

`Guard` is safe to share between threads; create one per process.
`guard.stats()` returns the counters and the detection state for your
metrics. ASGI and WSGI expose no accepted connections, so the `[l4]`
limits need your server's own accept hook: `h = guard.conn_open(ip)`
raises `Refused` over a limit, and `guard.conn_close(h)` frees the place.

## JavaScript and TypeScript

Node 20 or later:

```sh
npm install dvarapala
```

npm installs the addon of your platform from its `@dvarapala/*`
package. Install with optional dependencies (no `--omit=optional`), and
on the platform you deploy to: a lock file made on macOS still installs
the Linux package on Linux. `DVARAPALA_NODE` overrides the addon's
path. Types ship in `index.d.ts`.

With Express:

```js
const express = require('express');
const { Guard } = require('dvarapala');

const guard = new Guard({
  'rate_limit.rate': 20,
  'rate_limit.burst': 40,
  trusted_proxies: ['10.0.0.0/8'], // your load balancer
});
const app = express();
app.use(guard.middleware());
app.get('/', (req, res) => res.send('ok'));

// the [l4] connection limits, before any request is read
guard.attach(app.listen(8080));
```

`middleware()` answers `429` with `Retry-After`, or `403` with
`Connection: close`, and calls `next()` otherwise; it works with
`node:http` the same way. `attach(server)` destroys a socket over an
`l4.*` limit before the server reads it. Elsewhere, call
`guard.check(ip, xff)`: it returns `{ kind: 'allow' | 'throttle' | 'drop',
retryAfterMs }`. One guard per process.

The design is in [RFC 0008](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0008-sdk.md),
and build and test commands per package in
[sdk/README.md](https://github.com/franzramadhan/dvarapala/blob/main/sdk/README.md).
