# SDKs

The dvarapala engine in process (RFC 0008): the gateway's per-client rate
limit, flood detection and connection limits for services that cannot sit
behind the proxy. Each package is a thin layer over the C ABI in
`crates/ffi` (`crates/ffi/dvarapala.h`). Settings take the `CONFIG.md`
names (`rate_limit.*`, `detection.*`, `trusted_proxies`, the connection
keys of `[l4]`) with the gateway's defaults.

| Package | Build the library | Test |
|---|---|---|
| `go` | `cargo build --release -p dvarapala-ffi` | `cd sdk/go && go test -race ./...` |
| `python` | `cargo build --release -p dvarapala-ffi` | `cd sdk/python && DVARAPALA_LIB=../../target/release/libdvarapala.so PYTHONPATH=src python -m unittest discover -s tests` |
| `js` | `cargo build --release -p dvarapala-node` | `cd sdk/js && DVARAPALA_NODE=../../target/release/libdvarapala_node.so node --test` |

On macOS the shared libraries end in `.dylib`. Releases attach prebuilt
libraries per platform as `dvarapala-sdk-<tag>-<target>.tar.gz`.

```go
g, err := dvarapala.New(dvarapala.Config{"rate_limit.rate": "20"})
http.ListenAndServe(":8080", g.Middleware(mux))
```

```python
guard = Guard({"rate_limit.rate": 20, "detection.mode": "enforce"})
app = ASGIMiddleware(app, guard)
```

```js
const guard = new Guard({ 'rate_limit.rate': 20 });
const limit = guard.middleware();
guard.attach(http.createServer((req, res) => limit(req, res, () => res.end('ok'))));
```

ASGI and WSGI expose no accepted connections, so in Python the `[l4]`
limits need the server's own hook: `guard.conn_open(ip)` on accept,
`guard.conn_close(handle)` on close.
