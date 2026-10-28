# 0007: Forward proxy with egress rate shaping

| Status | Date | PR | Release |
|---|---|---|---|
| implemented | 2026-10-28 | #41 | v0.5.0 |

> A forward proxy mode for outbound traffic: requests to each named
> destination are shaped to an agreed rate, delayed in a bounded queue when
> they come too fast, and refused locally before the provider would block
> us.

## Problem

Services that call third-party providers (payment networks, banks, data
vendors, messaging gateways) usually work under an agreed request rate and
concurrency. A surge on our side (a batch job, a retry storm, a traffic
spike) that goes past the agreement gets throttled by the provider at best
and blocks all of our traffic at worst, for every service that shares the
credentials or the source address.

Each caller enforcing its own limit does not hold: many services and
replicas share one agreement, and retries multiply the rate exactly when
the provider is already slow. The limit has to sit at the one place all
outbound calls to that provider pass: an egress gateway.

Dvarapala today is a reverse proxy only. RFC 0001 lists the forward proxy
as a later milestone.

## Proposal

- `mode = "forward"` runs dvarapala as an HTTP forward proxy. Clients point
  `HTTP_PROXY` (or their HTTP client's proxy setting) at it. `mode =
  "reverse"` stays the default; `upstream` is required only there.
- Destinations are an allow list. Each `[[forward.destinations]]` names an
  origin (`https://api.provider.example`, scheme, host and port) and its
  limits. A request to any other origin gets `403` and never leaves, so the
  proxy cannot be used as an open relay or to reach internal addresses.
- Two ways in:
  - **Absolute-form HTTP** (`GET http://api.provider.example/v1/x`):
    the proxy sees every request, shapes each one, and opens TLS itself
    when the destination is `https://` (TLS origination, with the upstream
    verification of RFC 0003). This is the mode that can enforce a request
    rate.
  - **`CONNECT host:443`**: TLS stays end to end, so the proxy sees
    tunnels, not requests. Each new tunnel takes a token and the open
    tunnels count against `max_concurrent`; the tunnel limits of RFC 0005
    apply. Good enough for providers that limit connections, not for a
    per-request agreement: the docs say so.
- Shaping is per destination and global (one budget for all clients), not
  per client. A generic cell rate algorithm in the engine (no I/O, time as
  input) gives each request a send time:
  - a token is free now: send.
  - the next free slot is within `max_wait` and fewer than `max_queue`
    requests wait: sleep until the slot, then send. Order is first come,
    first served.
  - otherwise: refuse locally with `429` and `Retry-After` (the time to the
    next free slot). Fail closed: the proxy never sends above the rate, it
    makes our side wait or fail instead.
- `max_concurrent` bounds requests in flight per destination (most
  agreements cap both rate and concurrency). A request waits for a free
  place within the same `max_wait`.
- When the provider answers `429` or `503` with `Retry-After`, the
  destination pauses for that long (capped by `max_pause`): requests queue
  or are refused as above instead of piling more retries on the provider.
- Clients are an allow list too: only `forward.clients` (default loopback)
  may use the proxy; others get `403`.
- Out of scope, later RFCs if needed: a budget shared between dvarapala
  replicas (needs the `store` crate and Redis), priorities between callers
  of the same destination, TLS interception of `CONNECT` tunnels, path or
  method level budgets inside one destination, SOCKS.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/engine/src/schedule.rs` | cell rate scheduling: send time, wait or refuse, for a rate, burst, queue bound and pause, time as input |
| `crates/proxy/src/forward/route.rs` | match a request (absolute URI or `CONNECT` authority) to a destination |
| `crates/proxy/src/forward/shaper.rs` | per destination: the schedule, the wait, the concurrency places, provider pauses |
| `crates/proxy/src/forward/mod.rs` | the forward proxy service: absolute form, `CONNECT` (reusing `upgrade.rs` tunnels) |
| `crates/dvarapala/src/config.rs` | `mode`, `[forward]` and `[[forward.destinations]]` |

The reverse path, `l7` and the per-client rate limit are untouched. In
forward mode the per-client limiter and detection are not in the chain:
the callers are our own services.

### Configuration

| Key | Default | |
|---|---|---|
| `mode` | `"reverse"` | `"forward"` turns on this RFC; `upstream` is ignored there |
| `forward.clients` | `["127.0.0.0/8", "::1/128"]` | CIDRs allowed to use the proxy |
| `forward.connect` | `true` | Allow `CONNECT` to listed destinations; `false` accepts absolute-form only |
| `forward.destinations[].origin` | required | `https://host[:port]` or `http://host[:port]` |
| `forward.destinations[].name` | the host | Label in logs and metrics |
| `forward.destinations[].rate` | required | Requests (or new tunnels) per second |
| `forward.destinations[].burst` | `1` | Requests that may go at once after an idle period |
| `forward.destinations[].max_concurrent` | `0` (off) | Requests or tunnels in flight at once |
| `forward.destinations[].max_queue` | `100` | Requests waiting at once; `0` refuses instead of waiting |
| `forward.destinations[].max_wait` | `"2s"` | Longest wait for a slot or a place; over it, `429` |
| `forward.destinations[].max_pause` | `"60s"` | Cap on a provider's `Retry-After`; `"0s"` ignores it |

TLS to `https://` destinations uses `[upstream_tls]` (RFC 0003).

Example:

```toml
mode = "forward"
listen = "127.0.0.1:3128"

[forward]
clients = ["10.0.0.0/8"]

[[forward.destinations]]
name = "provider-a"
origin = "https://api.provider-a.example"
rate = 50
burst = 10
max_concurrent = 20
max_queue = 500
max_wait = "3s"
```

### Logs and metrics

| | |
|---|---|
| `dvarapala_egress_requests_total{destination,result}` | `sent`, `delayed` (sent after a wait), `refused` (local `429`), `denied` (not listed, or client not allowed) |
| `dvarapala_egress_wait_seconds{destination}` | histogram of the time spent waiting |
| `dvarapala_egress_queue{destination}` | requests waiting now; compare with `max_queue` |
| `dvarapala_egress_in_flight{destination}` | requests or tunnels in flight; compare with `max_concurrent` |
| `dvarapala_egress_provider_pauses_total{destination}` | provider `429` or `503` with `Retry-After` that paused the destination |
| `msg="egress refused"` | sampled per destination, at most once per second, with the reason |

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | rate 10, burst 1, fake clock | 10 requests at t=0 | send times 0, 100 ms, ..., 900 ms | unit (`engine`) |
| 2 | rate 10, burst 5 | 5 requests at t=0 | all send at once | unit |
| 3 | rate 10, `max_wait` 300 ms | 10 requests at t=0 | 4 scheduled, 6 refused with the `Retry-After` of the next slot | unit |
| 4 | `max_queue` 2 | 5 requests at t=0, burst 1 | 1 sent, 2 wait, 2 refused | unit |
| 5 | provider pause 2 s, `max_pause` 1 s | next request | waits or is refused per a 1 s pause | unit |
| 6 | the schedule | arbitrary request times and configs (proptest) | never more than `burst + rate * t` sends in any window `t` | unit |
| 7 | absolute-form `GET http://` to a listed origin | proxy | upstream gets the request with origin-form path, hop headers stripped | integration (`proxy/tests`) |
| 8 | listed `https://` origin, test CA | absolute-form request | proxy opens verified TLS, response comes back | integration |
| 9 | origin not listed | absolute-form and `CONNECT` | `403`, nothing sent, `denied` counted | integration |
| 10 | client outside `forward.clients` | any request | `403` | integration |
| 11 | rate 20 | 100 concurrent requests from 10 clients | upstream sees at most `burst + 20/s`, every request either sent or `429` | integration |
| 12 | `max_concurrent` 2, slow upstream | 3 requests | third waits for a place, then sends | integration |
| 13 | upstream answers `429` with `Retry-After: 1` | next requests | none sent for 1 s, `provider_pauses_total` up | integration |
| 14 | `CONNECT` to a listed origin, rate 1 | 2 tunnels at once | first opens, second waits or is refused | integration |
| 15 | request target from the client | arbitrary bytes | route never panics, only listed origins match | fuzz (`forward_route`) |
| 16 | 1000 waiting requests | memory | per-waiter cost reported, within the budget below | bench |

## Implementation notes

Found while building, folded back from the PRs:

- The schedule is a GCRA: `interval = 1 / rate`, a send may go up to
  `interval * (burst - 1)` ahead of the theoretical arrival time. A pause
  pushes every send to its end, where a full burst may go again.
- Case 6 uses a seeded xorshift generator over 200 configs instead of
  `proptest`: no new dependency for one test.
- A request that got a rate slot but no `max_concurrent` place within
  what is left of `max_wait` is refused with `Retry-After: 1`; its rate
  slot is spent, so the proxy errs on sending less.
- `Retry-After` from the provider is read as delay-seconds only; an
  HTTP-date is ignored.
- `denied` for an unlisted origin is counted with `destination="none"`;
  a listed destination refused because of the client or
  `forward.connect = false` keeps its own name.
- The proxy replaces `Host` with the target authority, strips hop-by-hop
  headers (`Proxy-Authorization` included) and adds no
  `X-Forwarded-For`.
- `CONNECT` tunnels reuse the RFC 0005 copy loop and `[upgrade]` limits
  (`max_tunnels`, `idle_timeout`, `max_lifetime`), with
  `protocol="connect"` in the tunnel metrics.
- Case 16 is the `forward_wait` bench, not run in CI: about 5.5 KB per
  waiting request on macOS at 1000 and 3000 waiters (the request head,
  its connection and the timer), over the 2 KB estimate above. Its budget
  is 8 KB, so the default `max_queue` of 100 is under 1 MB per
  destination.
- `upstream` is optional in the file; reverse mode fails at start without
  it. Forward mode needs at least one destination. `rate` is a number
  (`0.5` is one request every 2 s).
- `examples/forward-proxy.toml` is the egress rate compliance use case.

## Alternatives

| Option | Why not |
|---|---|
| Limit in each calling service | many services and replicas share one agreement; nobody sees the total |
| Reject over the rate instead of waiting | a short burst becomes errors the callers retry, which is the surge we want to avoid; a bounded wait absorbs it |
| Unbounded queue | memory grows with the surge and requests wait past every client timeout; `max_queue` and `max_wait` bound both |
| Per-client budgets | the agreement is with the provider, for all our traffic: one budget per destination |
| Shape `CONNECT` tunnels only | cannot enforce a request rate inside TLS; absolute-form with TLS origination can |
| TLS interception (bump) of `CONNECT` | needs a local CA trusted by every client and handles their secrets; out of scope |
| Allow any destination by default | an open relay and an SSRF path; the allow list is the safe default |
| Shared budget across replicas now | needs Redis and the `store` crate; one egress instance per agreement, or the rate split by replica count, covers the first users |

## Security and resource limits

- The callers are trusted services, but a bug or a compromised one controls
  how many requests arrive and where they go. `forward.clients` limits who
  can use the proxy, the destination allow list limits where requests go,
  and private or loopback addresses are reachable only when listed.
- Destinations are matched on the parsed origin (scheme, host, port), never
  on a prefix of the raw target, so `api.provider.example.attacker.example`
  or a userinfo trick does not match. The route parser reads client input
  and gets a fuzz target.
- Waiting requests hold their client connection and a timer, no body is
  read until the slot comes: about 2 KB each plus headers, so the default
  `max_queue` of 100 per destination is a few hundred KB. Bodies stream
  once sent, as in the reverse proxy.
- The schedule state per destination is a few words; the number of
  destinations is fixed by config.
- Fail closed: a missing slot is a local `429`, never a send above the rate.
  Provider pauses are capped by `max_pause`, so a hostile `Retry-After`
  cannot stop a destination for longer.

## Rollout

- **Rollout:** v0.5.0. A new mode; reverse proxy deployments are unchanged
  (`mode` defaults to `"reverse"`). Target version decided on acceptance.
- **Off switch:** `mode = "reverse"`, or remove a destination to deny it.
