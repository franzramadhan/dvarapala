# 0004: HTTP/2 upstreams and gRPC

| Status | Date | PR | Release |
|---|---|---|---|
| accepted | 2026-10-27 | #19 | v0.4.0 |

> Speak HTTP/2 to the upstream, pass trailers through, and answer gRPC
> clients in gRPC, so gRPC services can sit behind dvarapala. Harden the
> HTTP/2 listener against stream floods while at it.

## Problem

The listener already accepts HTTP/2, but the proxy always downgrades the
request to HTTP/1.1 for the upstream (`reverse.rs`). gRPC cannot survive
that:

- gRPC needs HTTP/2 end to end, including streaming in both directions.
- It needs response trailers (`grpc-status`, `grpc-message`) and the
  `te: trailers` request header, which `hop.rs` strips today.
- A gRPC client that gets a plain `429` sees `UNAVAILABLE` (the gRPC HTTP
  to status mapping), which is retryable, so a throttled client retries
  straight into the limiter. The `Retry-After` header is lost on the way.

HTTP/2 also has its own floods on the listener side: rapid reset
(CVE-2023-44487), CONTINUATION floods, and many cheap streams on one
connection. The rate limit counts requests, but a single connection can
open and cancel streams faster than the limiter sees them.

## Proposal

- `upstream_protocol`:
  - `http1` (default): today's behavior.
  - `http2`: HTTP/2 to the upstream. For `http://` that is h2c with prior
    knowledge; for `https://` (RFC 0003) ALPN must select `h2`, or the
    request fails with 502.
  - `auto`: ALPN chooses for `https://`; `http://` stays HTTP/1.1.
- Trailers pass through in both directions. `te: trailers` is kept when
  the upstream is HTTP/2 (the only value HTTP/2 allows); other `te` values
  are still stripped.
- gRPC requests (`content-type: application/grpc` or `application/grpc+*`)
  get local errors in gRPC form: HTTP `200`, a trailers-only response with
  `grpc-status` and `grpc-message`.

  | Verdict or error | `grpc-status` |
  |---|---|
  | `Throttle` (rate limit, ML score) | `8` RESOURCE_EXHAUSTED, plus `retry-after` and `grpc-retry-pushback-ms` |
  | `Drop` | `7` PERMISSION_DENIED |
  | upstream unreachable | `14` UNAVAILABLE |

  `grpc-retry-pushback-ms` tells gRPC clients with retry policies to wait
  instead of retrying at once.
- Each request counts once against the rate limit, as today: one unary
  RPC or one stream. A stream that stays open is bounded by the HTTP/2
  limits below, not by the token bucket.
- HTTP/2 listener limits, on by default, through hyper's settings:
  - `http2.max_concurrent_streams` (default `100`) per connection.
  - `http2.max_pending_reset_streams` (default `20`): reset streams the
    server may have pending; over it, the connection gets `GOAWAY`
    (rapid reset).
  - `http2.max_local_error_resets` (default `1024`): streams the server
    resets for client errors before it gives up on the connection.
  - `http2.max_header_list_size` (default `16KB`): header block size,
    which also bounds CONTINUATION frames.
  - `http2.keepalive_interval` (default `30s`, `0` off) and
    `http2.keepalive_timeout` (default `10s`): close dead connections that
    hold stream slots.
- Out of scope: gRPC-Web translation (it works today as plain HTTP/1.1
  POSTs, unverified), per-method rate limits, and inspecting gRPC message
  bodies.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/proxy/src/upstream.rs` | the `upstream_protocol` choice and the client per protocol |
| `crates/proxy/src/hop.rs` | keep `te: trailers` for HTTP/2 upstreams |
| `crates/proxy/src/grpc.rs` | detect gRPC requests, build trailers-only responses |
| `crates/proxy/src/server.rs` | apply the `http2.*` settings |
| `crates/l7/src/rate_limit.rs` | local responses through one function the proxy can shape for gRPC |
| `crates/dvarapala/src/config.rs` | `upstream_protocol` and `[http2]` |

### Configuration

| Key | Default | |
|---|---|---|
| `upstream_protocol` | `http1` | `http1`, `http2` or `auto` |
| `http2.max_concurrent_streams` | `100` | Streams at once per client connection |
| `http2.max_pending_reset_streams` | `20` | Rapid reset guard; over it, `GOAWAY` |
| `http2.max_local_error_resets` | `1024` | Server-side resets before closing the connection |
| `http2.max_header_list_size` | `16384` | Bytes of headers per request |
| `http2.keepalive_interval` | `30s` | PING interval; `0` turns keepalive off |
| `http2.keepalive_timeout` | `10s` | Close when a PING is not answered in time |

### Logs and metrics

| | |
|---|---|
| `dvarapala_requests_total{protocol}` | `http1`, `http2`, by the client side |
| `dvarapala_grpc_local_responses_total{status}` | gRPC errors dvarapala answered itself |
| `dvarapala_http2_goaway_total{reason}` | connections closed for `rapid_reset`, `error_resets`, `keepalive` |
| `msg="http2 connection closed"` | sampled, with the reason and the peer |

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | `upstream_protocol = "http2"`, h2c test upstream | HTTP/1.1 client request | upstream sees HTTP/2 | integration (`proxy/tests`) |
| 2 | same | HTTP/2 client request | upstream sees HTTP/2, body intact | integration |
| 3 | `http2`, upstream only speaks HTTP/1.1 | request | 502, upstream error counted | integration |
| 4 | `http1` (default) | HTTP/2 client request | upstream sees HTTP/1.1, as in v0.2.0 | integration |
| 5 | `http2` upstream | request with `te: trailers` and `te: gzip` | upstream gets `te: trailers` only | unit (`hop`) |
| 6 | `http1` upstream | request with `te: trailers` | stripped | unit (`hop`) |
| 7 | upstream answers with trailers | request | client gets the same trailers | integration |
| 8 | test gRPC service (unary, `tonic` as a dev-dependency) | call through the proxy | reply and `grpc-status: 0` | integration |
| 9 | same, server streaming of 1000 messages | call | all 1000 arrive in order | integration |
| 10 | same, bidirectional stream | call | echo works both ways | integration |
| 11 | rate limit exhausted, gRPC request | call | HTTP 200, `grpc-status: 8`, `grpc-retry-pushback-ms` set, upstream not called | integration |
| 12 | `Drop` verdict (RFC 0002 enforce), gRPC request | call | `grpc-status: 7` | integration |
| 13 | upstream down, gRPC request | call | `grpc-status: 14` | integration |
| 14 | rate limit exhausted, plain request | GET | `429` as before | integration |
| 15 | `max_concurrent_streams = 2` | client opens 3 streams | third is refused with `REFUSED_STREAM` | integration |
| 16 | defaults | client sends HEADERS then RST_STREAM in a loop | `GOAWAY` after the pending reset limit, counter up | integration |
| 17 | `max_header_list_size = 16384` | 64 KB of headers over CONTINUATION frames | request rejected, connection stays bounded | integration |
| 18 | keepalive on, client stops answering PING | `keepalive_timeout` passes | connection closed | integration |
| 19 | arbitrary `content-type` values | gRPC detection | never panics, only `application/grpc` and `application/grpc+*` match | unit (`grpc`) |

## Implementation notes

Found while building, folded back from the PRs:

- The gRPC helpers (`is_grpc`, `grpc_response`) live in
  `crates/l7/src/grpc.rs`, not `crates/proxy`: the rate limit layer needs
  them and `l7` must not depend on `proxy`. The proxy uses the same
  function for `14` on a dead upstream.
- A trailers-only response is a HEADERS frame with `grpc-status` and an
  empty body, so local gRPC errors need no trailer support in the layer.
  `Challenge` also maps to `8`, without pushback.
- `upstream_protocol = "auto"` keeps `te: trailers` too, since ALPN may
  pick HTTP/2 after the headers are built.
- The gRPC tests (cases 8 to 10) frame messages by hand (5-byte prefix)
  instead of using `tonic`: same wire behavior, no codegen and no new
  dev-dependencies.
- Cases 15 to 18 write raw HTTP/2 frames: a compliant client never breaks
  the limits. Cases 16 and 17 already held on hyper's defaults, so they ran
  from the first commit as guards for those defaults.
- `dvarapala_http2_goaway_total{reason}` has `flood` (h2 sent `GOAWAY`
  with `ENHANCE_YOUR_CALM`: rapid reset, error resets, CONTINUATION or
  header floods) and `protocol` (any other error h2 detected). h2 does not
  expose which limit fired, so `rapid_reset` and `error_resets` are one
  label. A keepalive timeout closes the connection without an error, so it
  is not counted; the `http2 connection closed` log line covers the
  counted cases only.
- `dvarapala_requests_total` gained the `protocol` label next to
  `verdict`, instead of a second counter.
- `ReverseProxy::with_config(upstream, &UpstreamConfig)` replaces
  `with_tls`; `serve` and `serve_tls` take `Http2Limits`.
  `http2.max_concurrent_streams = 0` is a config error.
- `keepalive_interval = "0s"` turns keepalive off (durations keep their
  unit).
- Also tested beyond the table: `http2` and `auto` over TLS, against an
  upstream that offers ALPN `h2` and one that does not.
- The `footprint` job runs a gRPC request over h2c against a dead
  upstream and checks `grpc-status: 14` and the counter.

## Alternatives

| Option | Why not |
|---|---|
| Plain `429` for gRPC clients | maps to `UNAVAILABLE`, which clients retry at once: the throttle amplifies the load |
| Choose the upstream protocol from the client's version | an HTTP/1.1 client cannot reach a gRPC upstream then, and the upstream's capability is static |
| h2c upgrade (`Upgrade: h2c`) to the upstream | deprecated by RFC 9113; prior knowledge is simpler and what gRPC uses |
| Rate limit per gRPC message | needs body parsing on the hot path; per stream plus HTTP/2 limits bounds the cost |
| Leave the HTTP/2 limits at hyper's defaults | they exist, but are not visible or tunable; a gateway should expose its flood knobs |

## Security and resource limits

- The attacker controls stream counts, resets, header sizes and timing on
  the HTTP/2 connection. Each is bounded by an `http2.*` setting, enforced
  by hyper and h2 before the request reaches the rate limiter.
- Worst case per connection: `max_concurrent_streams` open streams, each
  with at most `max_header_list_size` of headers and one HTTP/2 flow
  control window of buffered body.
- Long streams: a stream holds a slot, not tokens. Stream count and
  keepalive bound how many slots one client holds; connection limits per
  IP come with the L4 RFC.
- Trailers pass through unchanged and are not parsed by dvarapala.
- Local gRPC errors carry fixed messages, never upstream details.

## Rollout

- **Rollout:** v0.4.0. `upstream_protocol` defaults to `http1`, so upgrades
  change nothing upstream. The `http2.*` limits apply to the existing
  HTTP/2 listener at once; their defaults sit above normal browser and
  gRPC usage.
- **Off switch:** `upstream_protocol = "http1"`. Each `http2.*` limit can be
  raised; `keepalive_interval = 0` turns keepalive off.
