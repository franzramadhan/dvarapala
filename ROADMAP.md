# Roadmap

Every feature starts as an RFC (`rfc/`, see `CLAUDE.md`). A release lists
the RFCs it implements. Versions stay 0.x (alpha) until a 1.0 is decided.

| RFC | Feature | Status | Target |
|---|---|---|---|
| [0001](rfc/0001-foundation.md) | Foundation: engine, L7 rate limit, reverse proxy | implemented | v0.1.0 |
| [0002](rfc/0002-adaptive-detection.md) | Adaptive detection: heavy hitters, baseline, entropy, optional tree model | implemented | v0.2.0 |
| [0003](rfc/0003-tls.md) | TLS termination with ALPN, HTTPS upstreams, bounded handshakes | implemented | v0.3.0 |
| [0004](rfc/0004-http2-grpc.md) | HTTP/2 upstreams, trailers, gRPC-shaped errors, HTTP/2 flood limits | implemented | v0.4.0 |
| [0005](rfc/0005-websocket.md) | WebSocket upgrade pass-through with tunnel limits | implemented | v0.4.0 |
| [0006](rfc/0006-http3.md) | Optional HTTP/3 over QUIC with Retry under load | implemented | v0.5.0 |
| [0007](rfc/0007-forward-proxy.md) | Forward proxy with per-destination egress rate shaping | implemented | v0.5.0 |
| [0008](rfc/0008-sdk.md) | SDKs for Go, Python and JavaScript over a C ABI | implemented | v0.5.0 |
| [0009](rfc/0009-l4-limits.md) | L4 connection limits per client and in total, accept rate, header, idle and body timeouts | implemented | v0.5.0 |
| [0010](rfc/0010-shared-state.md) | Shared state for clusters: per-client limit, egress budget and heavy hitters across replicas via Redis or PostgreSQL | implemented | v0.6.0 |
| [0011](rfc/0011-xdp.md) | XDP fast path: block list, per-source packet and SYN rates at the driver | implemented | v0.6.0 |
| [0012](rfc/0012-challenges.md) | Proof-of-work challenges with a signed pass, JA4 fingerprints with deny and challenge rules | implemented | v0.7.0 |
| [0013](rfc/0013-routes.md) | Per-route policy: deny, extra rate limits keyed by client, header or JA4, challenge exemptions, matched on host, path, method and client | accepted | v0.8.0 |
