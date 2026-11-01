# 0030: PROXY protocol and the client address behind an L4 load balancer

| Status | Date | PR | Release |
|---|---|---|---|
| draft | 2026-11-01 | #268 | |

> Read a PROXY protocol v1 or v2 header from trusted load balancers on the
> TCP listener, before TLS, and use the address it carries as the client
> for every layer: `[l4]` limits, the rate limiter, detection, routes,
> challenges, blocks, logs and `[ml]` features.

## Problem

Behind an L4 load balancer that does not terminate TLS (AWS NLB with
TLS passthrough, a GCP passthrough load balancer, HAProxy in `mode tcp`,
Cloudflare Spectrum, an ingress controller's TCP passthrough), the TCP
peer of every connection is the load balancer. The real client is only
known to the balancer, which can send it in a PROXY protocol header.

- `trusted_proxies` covers only `X-Forwarded-For`, which needs a
  balancer that speaks HTTP. A TCP balancer cannot add it, and with TLS
  passthrough it cannot see the request at all.
- `[l4]` limits never use `X-Forwarded-For` (CONFIG.md): the docs tell
  operators to put the balancer in `exempt`, which turns the per-client
  connection cap and accept rate off for all traffic.
- The rate limiter, heavy hitters, entropy, JA4 rules, manual blocks and
  `[ml]` features key on the balancer's address (or a handful of them),
  so one abusive client throttles everyone behind the same balancer node,
  and detection sees a few sources with enormous rates.
- A block (manual or dynamic) of the balancer's address takes the whole
  site down.

HTTP/3 is not affected: QUIC reaches dvarapala as UDP from the client,
and UDP balancers that preserve the source address are the norm.

## Proposal

- `l4.proxy_protocol = "off" | "v1" | "v2" | "any"`, default `"off"`.
  `"any"` accepts either version, detected by the first bytes.
- `l4.proxy_protocol_from`: the CIDRs allowed to send a header. Required
  (non-empty) when `proxy_protocol` is not `"off"`; a start-up and reload
  error otherwise.
- A connection from an address in `proxy_protocol_from` must start with
  a valid header. A missing, malformed or truncated header closes the
  connection with nothing written (fail closed).
- A connection from any other address is handled as today, keyed by its
  own peer: a header sent by it is not parsed, so it fails as garbage at
  the TLS or HTTP layer. This lets health checkers and direct clients
  share the port.
- The header is read before the TLS handshake and before JA4 reads the
  ClientHello, under `l4.proxy_protocol_timeout` (default `"5s"`) and a
  cap of 107 bytes for v1 and 16 + 216 bytes for v2 (address block plus
  TLVs, TLVs ignored).
- Order of the `[l4]` checks on a connection from a trusted balancer:
  `max_connections` at accept (the total does not depend on the client),
  then the header, then `max_per_client` and the accept bucket keyed on
  the carried address, then TLS and HTTP as today.
- The carried address replaces the TCP peer in `PeerAddr`, so every
  layer that reads the client today reads the real one without changes.
  `trusted_proxies` still applies on top: a carried address in
  `trusted_proxies` may set `X-Forwarded-For`.
- `PROXY UNKNOWN` (v1) and the v2 `LOCAL` command (balancer health
  checks) keep the balancer's own address as the client.
- XDP (RFC 0011) sees packets from the balancer, so a carried address is
  never sent to the XDP block list: dynamic blocks of carried clients
  stay in the engine's block list only. The balancer's own address is
  never blocked by a carried client's verdict.
- Forward mode accepts the header too, for a forward proxy behind a TCP
  balancer.
- Operator (RFC 0019): the policy CRD exposes `l4.proxy_protocol` and
  `l4.proxy_protocol_from` through the existing config passthrough; no
  new field.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/l4/src/proxy_protocol.rs` | v1 and v2 parser over a byte slice: no I/O, bounded, returns the source address or `Local` |
| `crates/l4/src/listener.rs` | reads the header from trusted peers under the timeout, then applies the per-client limits to the carried address |
| `crates/l4/src/conn.rs` | carries the client address next to the TCP peer |
| `crates/proxy/src/server.rs` | sets `PeerAddr` from the connection's client address |
| `crates/dvarapala/src/config.rs` | the new keys and their validation |
| `fuzz/fuzz_targets/proxy_protocol.rs` | fuzz target over the parser, row in `fuzz/select.sh` |
| `examples/proxy-protocol.toml`, `CONFIG.md` | a config behind an NLB-style balancer |

### Configuration

| Key | Default | |
|---|---|---|
| `l4.proxy_protocol` | `"off"` | `"v1"`, `"v2"` or `"any"`; `"off"` keeps today's behavior |
| `l4.proxy_protocol_from` | `[]` | Peers that must send a header; required when on |
| `l4.proxy_protocol_timeout` | `"5s"` | Time to receive the whole header; above 0 |

All three need a restart, as the other `[l4]` connection keys.

### Logs and metrics

| | |
|---|---|
| `dvarapala_proxy_protocol_total{result}` | `ok`, `local`, `invalid`, `timeout` per header read |
| `msg="proxy protocol header refused" peer=<addr> reason=<r>` | at most once a second, with the count since the last line |

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | v1 lines for TCP4, TCP6 and UNKNOWN | parsed | source `192.0.2.10:4000`, `[2001:db8::1]:4000`, `Local` | unit |
| 2 | v2 headers for TCP over IPv4 and IPv6, with TLVs, and `LOCAL` | parsed | the source address, TLVs skipped, `Local` | unit |
| 3 | a v2 header with a length over the cap, a bad signature, a v1 line without `\r\n` in 107 bytes | parsed | an error, no allocation over the cap | unit |
| 4 | the parser | `cargo fuzz` for 60 s | no panic, no read past the input | fuzz |
| 5 | `proxy_protocol = "v2"`, a trusted peer | it sends a header for `192.0.2.10`, then an HTTP request | the upstream's `X-Forwarded-For` and the access log name `192.0.2.10` | integration |
| 6 | the same | it sends a header, then a TLS ClientHello | the handshake completes; the JA4 and the client key are the carried client's | integration |
| 7 | a trusted peer | it sends HTTP without a header | the connection is closed, nothing written, `result="invalid"` | integration |
| 8 | a trusted peer | it sends half a header and stalls | closed after `proxy_protocol_timeout`, `result="timeout"` | integration |
| 9 | an untrusted peer | it sends a valid header for `192.0.2.10` | the header is not honored: the client stays the peer, the request fails as a bad request | integration |
| 10 | `max_per_client = 2`, one trusted peer | three carried clients open two connections each, then one opens a third | the third connection of that client is refused, the others are open | integration |
| 11 | `rate_limit.rate = 1`, one trusted peer | client A floods, client B sends one request | A is throttled, B is allowed | integration |
| 12 | `[xdp]` enforce, a carried client over the accept rate | the dynamic block fires | the engine blocks the carried client; the XDP block list is unchanged | integration |
| 13 | `proxy_protocol = "v1"` and `proxy_protocol_from = []` | start or reload | refused naming `l4.proxy_protocol_from` | unit |
| 14 | `examples/proxy-protocol.toml` | `example_configs_load` | loads | integration |

## Alternatives

| Option | Why not |
|---|---|
| Only `X-Forwarded-For` | needs an HTTP balancer, does not reach `[l4]` or TLS passthrough |
| Auto-detect a header from any peer | lets any client spoof its address; the header is trusted only from listed peers |
| Accept a missing header from trusted peers (`optional`) | a balancer misconfigured to drop the header turns every client into the balancer, silently; failing closed makes it visible at once |
| Parse TLVs (ALPN, authority, AWS VPC endpoint id) | no layer needs them today; a later RFC can add the ones a rule wants |
| Push carried clients into XDP | the packets come from the balancer: a block on the client never matches, a block on the balancer drops everyone |

## Security and resource limits

- An attacker controls the header only from a trusted peer, so the
  security of the feature is the correctness of `proxy_protocol_from`.
  An empty list is refused.
- From a trusted peer, the worst case is a slow or garbage header: one
  read buffer of at most 232 bytes per connection, closed after
  `proxy_protocol_timeout`. `max_connections` applies before the read,
  so a stalled balancer cannot open unbounded connections.
- The per-client table now keys on carried addresses, which an attacker
  behind the balancer can vary freely only over the addresses the
  balancer actually sees (it completed a handshake with the client), so
  the bound stays `max_clients`.
- The parser reads attacker-influenced bytes and gets a fuzz target.

## Rollout

- **Rollout:** a minor release. Default `"off"`: nothing changes on
  upgrade. A trusted peer must send the header, so the balancer and
  dvarapala switch together: restart dvarapala with the header on, then
  turn the header on at the balancer (most balancers apply it to new
  connections only). Connections refused in between show up as
  `result="invalid"`. `site/docs/` gets the order for an NLB and for
  HAProxy.
- **Off switch:** `l4.proxy_protocol = "off"` and a restart, then turn
  the header off at the balancer.
