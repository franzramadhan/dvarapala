---
title: SDKs
---

If a service cannot sit behind the proxy, the SDKs run the same
protection in process: the per-client rate limit, flood detection, the
connection limits of `[l4]`, per-route policy, manual blocks, egress
shaping (limits on outgoing calls) and live reload. In each package, a
guard (the SDK object that holds the limits) does the checks.

Each package is a thin layer over one C ABI (`crates/ffi`, header
`dvarapala.h`). A C ABI is a binary interface that other languages can
call. Thus the verdicts (allow, throttle or drop) match the verdicts of
the gateway.

The SDKs take the [Configuration](configuration.html) names with the
defaults of the gateway. If a key or a value is bad, the error names it.

Each SDK has one small program with a per-client limit, a deny route and a
manual block, and CI runs each one:
[`sdk/go/example_test.go`](https://github.com/franzramadhan/dvarapala/blob/main/sdk/go/example_test.go)
(`net/http`),
[`sdk/python/examples/server.py`](https://github.com/franzramadhan/dvarapala/blob/main/sdk/python/examples/server.py)
(WSGI) and
[`sdk/js/examples/server.js`](https://github.com/franzramadhan/dvarapala/blob/main/sdk/js/examples/server.js)
(`node:http`). Run the Python or JavaScript program with `--demo`: it
sends five requests and prints the status of each.

## Keys

| Accepted in process | |
|---|---|
| `rate_limit.rate`, `rate_limit.burst`, `rate_limit.max_clients` | The per-client bucket |
| `trusted_proxies` | Peers allowed to set `X-Forwarded-For` |
| `detection.*` (every key of `[detection]`) | Flood detection, `observe` or `enforce` |
| `l4.enabled`, `l4.max_connections`, `l4.max_per_client`, `l4.accept_rate`, `l4.accept_burst`, `l4.prefix_v4`, `l4.prefix_v6`, `l4.max_clients`, `l4.exempt` | Connection limits on accept |
| `routes` | `[[routes]]` as a JSON array. The SDKs refuse `key = "ja4"`, `challenge` and `waf` |
| `forward.destinations` | `[[forward.destinations]]` as a JSON array, for egress shaping. The SDKs refuse `max_concurrent` (hold a semaphore of your language instead) |
| `admin.max_blocks`, `admin.max_block_ttl` | Limits of the manual block list |

Python and JavaScript take a list of dicts or objects for `routes` and
`forward.destinations` and encode it. Go takes the JSON text.

The SDKs refuse the server keys of the gateway with `does not apply
in-process`: `mode`, `listen`, `upstream`, `upstream_protocol`, `[metrics]`,
`[ml]`, `[tls]`, `[upstream_tls]`, `[http2]`, `[upgrade]`, the other
`[forward]` and `[admin]` keys and the `[l4]` timeouts (`header_timeout`,
`idle_timeout`, `min_body_rate`).

The SDKs refuse every other key with `is not a key`, because they do not
have that layer: `rate_limit.enabled` (leave the guard out instead),
`[challenge]`, `[fingerprint]`, `[waf]`, `[store]`, `[pool]`, `[xdp]` and
`[quic]`. If you need those layers, run the gateway.

## Routes, blocks, egress and reload

[RFC 0028](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0028-sdk-parity.md)
brings four gateway features into every SDK:

- Routes: each middleware applies `routes` as the gateway does. A denied
  route drops the request before any bucket. A route with `rate` adds its
  own bucket per client or per header (`key = "header:x-api-key"`). If the
  guard refuses the input (a field over 8 KiB, a newline in a header
  value, no method or path), it answers `400` and closes the connection.
  The app never sees that input.
- Blocks: `block(cidr, ttl)`, `unblock(cidr)` and `blocks()`. Every check
  drops a blocked client, and the guard refuses its connections.
- Egress: the `rate`, `burst`, `max_queue`, `max_wait` and `max_pause` of
  a destination, without the forward proxy. Go has `g.Egress(ctx, dest)`
  and `g.Transport(base)`, which pauses on `429` or `503` with
  `Retry-After`. Python has `await guard.egress(dest)` and
  `guard.egress_wait(dest)`. JavaScript has `await guard.egress(dest)`.
  After the guard hands out a wait, the wait counts as spent, even if the
  caller gives up.
- Reload: `reload(config)` applies a new configuration in place. It keeps
  client counts, the detection baseline, blocks and egress queues. A key
  that applies only at creation (`rate_limit.max_clients`, `[l4]`, the
  keys of the detector itself, `admin.max_blocks`) fails the reload, and
  the guard stays as it was.

Each process has its own guard. Behind several workers or replicas, the
limit of a client and the budget of a provider multiply by their number.
Divide `rate_limit.rate`, the route rates and the `rate` of each
destination by that number, and block on every process.

## Rust

The crates are on crates.io:

- `dvarapala-l7` has the `tower` layers (`RateLimitLayer` with
  `RateLimitConfig`, including detection and the optional `Scoring` hook).
- `dvarapala-l4` has the listener wrapper.
- `dvarapala-engine` has the verdict engine, with no I/O.

`crates/dvarapala/src/layer.rs` shows how the binary builds
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

`Middleware` answers `429` with `Retry-After`, or `403` with the connection closed, as the gateway does.
`Listener` applies the connection limits on accept.
[RFC 0027](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0027-go-module.md):
each release generates the module from `sdk/go` with the static library
prebuilt for Linux (glibc 2.28 or later) and macOS, on amd64 and arm64.
The module needs cgo and a C toolchain, but no Rust. Without cgo, or on
another platform, the build stops at
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

On another platform (Alpine with musl, Windows), `pip` finds no matching
distribution, and `require('dvarapala')` throws an error that names the
platform. On such a platform, build the library from source with `cargo
build --release -p dvarapala-ffi` (Python, Go) or `-p dvarapala-node`
(JavaScript). Then point the package at it with `DVARAPALA_LIB` or
`DVARAPALA_NODE`. Each release also attaches the libraries as
`dvarapala-sdk-<tag>-<target>.tar.gz`.

## Python

Python 3.10 or later, no dependencies:

```sh
pip install dvarapala      # or: uv add dvarapala
```

The wheel carries the library. `DVARAPALA_LIB` overrides its path.

If you have an ASGI app (FastAPI, Starlette, Django ASGI), wrap it:

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
answer `429` with `Retry-After`, or `403` with `Connection: close`.
WSGI does not allow an app to set `Connection` (PEP 3333), so the WSGI
`403` and `400` leave that header to the server. They
pass every other request to the app. If the guard cannot read a request
(no peer address, as on a Unix socket, or bad input), it answers `400`.
Thus the guard fails closed.

In other code, ask the guard directly:

```python
from dvarapala import ALLOW, THROTTLE, Guard

v = guard.check(peer_ip, request.headers.get("x-forwarded-for"))
if v.kind == THROTTLE:
    ...  # refuse; retry after v.retry_after seconds
elif v.kind != ALLOW:
    ...  # DROP: refuse and close
```

You can share a `Guard` between threads. Create one per process.
`guard.stats()` returns the counters and the detection state for your
metrics. ASGI and WSGI expose no accepted connections. Thus the `[l4]`
limits need the accept hook of your server. Over a limit,
`h = guard.conn_open(ip)` raises `Refused`. `guard.conn_close(h)` frees
the place.

## JavaScript and TypeScript

Node 20 or later:

```sh
npm install dvarapala
```

npm installs the addon of your platform from its `@dvarapala/*`
package. Install with optional dependencies (no `--omit=optional`).
Install on the platform that you deploy to. A lock file made on macOS
still installs the Linux package on Linux. `DVARAPALA_NODE` overrides the
path of the addon. Types ship in `index.d.ts`.

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
`Connection: close`, and calls `next()` otherwise. It works with
`node:http` the same way. `attach(server)` destroys a socket over an
`l4.*` limit before the server reads it. In other code, call
`guard.check(ip, xff)`. It returns `{ kind: 'allow' | 'throttle' | 'drop',
retryAfterMs }`. Create one guard per process.

The design is in [RFC 0008](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0008-sdk.md).
The build and test commands for each package are in
[sdk/README.md](https://github.com/franzramadhan/dvarapala/blob/main/sdk/README.md).
