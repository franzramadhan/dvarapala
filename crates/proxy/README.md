# dvarapala-proxy

The proxy core of [dvarapala](https://github.com/franzramadhan/dvarapala): the server loop with graceful
shutdown, a reverse proxy to one upstream or a pool (round robin or least
requests, health checks, ejection, budgeted retries), a forward proxy to
listed destinations with `CONNECT` tunnels, WebSocket tunnels and
HTTP/2 limits.

| Feature | Adds |
|---|---|
| `tls` | rustls listener with ALPN and `https://` upstreams |
| `http3` | HTTP/3 listener over QUIC (`quinn`, `h3`), experimental |

Part of [dvarapala](https://github.com/franzramadhan/dvarapala), an anti-DDoS gateway in Rust. Docs: <https://dvarapala.franzramadhan.dev/docs/>. License: MIT.
