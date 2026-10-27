# Roadmap

Every feature starts as an RFC (`rfc/`, see `CLAUDE.md`). A release lists
the RFCs it implements. Versions stay 0.x (alpha) until a 1.0 is decided.

| RFC | Feature | Status | Target |
|---|---|---|---|
| [0001](rfc/0001-foundation.md) | Foundation: engine, L7 rate limit, reverse proxy | implemented | v0.1.0 |
| [0002](rfc/0002-adaptive-detection.md) | Adaptive detection: heavy hitters, baseline, entropy, optional tree model | implemented | v0.2.0 |
| [0003](rfc/0003-tls.md) | TLS termination with ALPN, HTTPS upstreams, bounded handshakes | accepted | v0.3.0 |
| [0004](rfc/0004-http2-grpc.md) | HTTP/2 upstreams, trailers, gRPC-shaped errors, HTTP/2 flood limits | accepted | v0.3.0 |
| [0005](rfc/0005-websocket.md) | WebSocket upgrade pass-through with tunnel limits | accepted | v0.4.0 |
| [0006](rfc/0006-http3.md) | Optional HTTP/3 over QUIC with Retry under load | accepted | unplanned |
