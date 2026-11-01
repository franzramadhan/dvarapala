# SDKs

The dvarapala engine in process (RFC 0008): the gateway's per-client rate
limit, flood detection and connection limits for services that cannot sit
behind the proxy, plus routes, manual blocks, egress shaping and reload
(RFC 0028). Each package is a thin layer over the C ABI in
`crates/ffi` (`crates/ffi/dvarapala.h`). Settings take the `CONFIG.md`
names (`rate_limit.*`, `detection.*`, `trusted_proxies`, the connection
keys of `[l4]`, `routes` and `forward.destinations` as JSON arrays,
`admin.max_blocks`, `admin.max_block_ttl`) with the gateway's defaults.
One guard per process: behind several workers, divide the rates by
their number.

| Package | Build the library | Test |
|---|---|---|
| `go` | `cargo build --release -p dvarapala-ffi` | `cd sdk/go && go test -race ./...` |
| `python` | `cargo build --release -p dvarapala-ffi` | `cd sdk/python && DVARAPALA_LIB=../../target/release/libdvarapala.so PYTHONPATH=src python -m unittest discover -s tests` |
| `js` | `cargo build --release -p dvarapala-node` | `cd sdk/js && DVARAPALA_NODE=../../target/release/libdvarapala_node.so node --test test/*.test.js` |

On macOS the shared libraries end in `.dylib`. Install from the
registries (RFC 0026, RFC 0027), with the library prebuilt for Linux
(glibc 2.28 or later) and macOS on x86_64 and arm64:

```sh
go get github.com/franzramadhan/dvarapala-go@v<version>
pip install dvarapala
npm install dvarapala
```

The Go module is generated from `sdk/go` by `scripts/go-module.sh`; the
wheels by `scripts/wheel.py`; the npm addon ships in the platform
packages under `js/npm/`. `scripts/sdk-packages-check.sh` builds and
installs all three for the host platform. Releases also attach the
libraries as `dvarapala-sdk-<tag>-<target>.tar.gz`.

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
