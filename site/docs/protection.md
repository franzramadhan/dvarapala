---
title: Protection layers
---

Each layer is optional. [Configuration](configuration.html) lists every
key.

## XDP fast path

An optional eBPF program (builds with the `xdp` feature, Linux only) runs
on the network interface, before the kernel builds a socket buffer. It
acts on packets to the TCP `listen` port and the UDP `quic.listen` port.
First, `allow` passes a packet and `block` drops it. Then per-source rates
apply to all packets (`pps`), to TCP SYNs (`syn_pps`) and to UDP
(`udp_pps`). Every other packet passes untouched.

With `mode = "enforce"`, two kinds of clients get a dynamic block (a
block that dvarapala adds at run time) for `block_ttl`. These are clients
that the `[l4]` accept rate refuses, and heavy hitters (sources that send
far more than the rest) that detection drops. Both completed a TCP
handshake, so a spoofed source cannot get a victim blocked. Keep kernel
SYN cookies on for the backlog. In `observe` mode, XDP counts
`would_drop` and passes everything. If `l4.proxy_protocol` is on,
dvarapala sends no dynamic blocks (see below).

Keys: [`[xdp]`](configuration.html#xdp).

## Connection limits

dvarapala checks every accepted connection before it reads TLS or any
HTTP. It caps open connections in total (`max_connections`) and per
client (`max_per_client`). It also applies a token bucket (a counter that
refills at a fixed rate) to new connections per client (`accept_rate`,
`accept_burst`). dvarapala closes a refused connection at once, with no
response.

Timeouts close connections that hold a slot but send nothing useful:

- `header_timeout` for each request head.
- `idle_timeout` between requests.
- `min_body_rate` for bodies that trickle in (`408`).

Here, a client is the peer address, grouped by `prefix_v4` /
`prefix_v6`. `X-Forwarded-For` does not apply. If an HTTP load balancer
is in front, list it in `exempt`.

### Behind a TCP load balancer

A balancer that passes TLS through (an AWS NLB, a GCP passthrough load
balancer, HAProxy in `mode tcp`) cannot add `X-Forwarded-For`. Every
client then looks like the balancer. Make the balancer send a PROXY
protocol header (`proxy_protocol_v2.enabled` on an NLB target group,
`send-proxy-v2` in HAProxy). Then set `proxy_protocol` and
`proxy_protocol_from` ([RFC
0030](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0030-proxy-protocol.md)).

dvarapala reads the header before TLS. The client in the header is the
client for every layer on this page. dvarapala closes a connection from
the balancer that has no valid header. Restart dvarapala first. Then turn
on the header at the balancer at once. Watch
`dvarapala_proxy_protocol_total`.

Behind such a balancer, XDP sees the packets of the balancer, not of the
client. While `proxy_protocol` is on, no dynamic blocks reach the XDP
block list. The reason: XDP cannot tell which addresses come through
the balancer. L4 and L7 still refuse the client. Put the
balancers in `xdp.allow` so that a static block or a per-source rate
never drops them.

Keys: [`[l4]`](configuration.html#l4),
[example](examples.html#proxy-protocoltoml).

## Rate limit

Each client gets a token bucket: `rate` tokens per second, up to `burst`.
If the bucket is empty, dvarapala answers `429` with `Retry-After` and
does not contact the upstream. The client table holds `max_clients`
entries and evicts the least recently seen one. As a result, a flood from
spoofed sources cannot grow memory.

If a load balancer is in front, list it in `trusted_proxies`. Only those
peers can set `X-Forwarded-For`. dvarapala keys every other client by its
own address.

Keys: [`[rate_limit]`](configuration.html#rate_limit), `trusted_proxies`.

## Adaptive detection

Counts per time window catch what a fixed rate misses: many clients that
each stay under the limit.

- Heavy hitters: a count-min sketch (a small table of approximate counts)
  with a top-k list finds the prefixes that send more than the per-client
  limit.
- Baseline: an EWMA (a moving average that favors recent values) of the
  request rate. After `warmup_windows`, a window that is `z_threshold`
  standard deviations above it is anomalous.
- Entropy: a sharp drop in how spread out the sources are
  (`entropy_drop`) is also anomalous.

After `trigger_windows` anomalous windows in a row, the state changes to
`Attack`. After `cooldown_windows` normal windows, it changes back.
Prefixes (`prefix_v4`, `prefix_v6`) group a subnet into one key.

In `observe` mode, none of this changes a verdict. It shows in logs
("would drop") and in the `dvarapala_detection_*` metrics. In `enforce`
mode, a heavy hitter gets `403` and dvarapala closes the connection.
During `Attack`, the bucket of every client refills at
`attack_rate_factor` of its rate.

Keys: [`[detection]`](configuration.html#detection).

## Scoring model

An optional XGBoost model of your own scores each client on every request
that the bucket of the client allows. If the score is above
`ml.threshold`, the client gets `429` with `Retry-After`. The model
catches what the fixed limits miss, such as a slow scraper that stays
under the rate. LLM labels collect the training data. [Learned
scoring](ml.html) describes the full loop: features, sample input and
output, training, and rollout.

Keys: [`[ml]`](configuration.html#ml).

## Challenge

During an attack, every client without a pass shares the attack limit
(`attack_rate_factor`). With `challenge.mode = "attack"`, a browser gets a
`403` page instead. The script on the page finds a SHA-256 proof of work
(a puzzle that costs the client CPU time) with `difficulty` leading zero
bits. At the default of 16, this takes under a second. The browser then
gets a pass cookie and the normal limit back. With `"always"`, dvarapala
challenges every request without a pass.

The pass is an HMAC bound to the client key, so the server keeps no
state. Set `challenge.secret` so that passes survive a restart and work
on every replica. The bucket of the client still comes first. In
`enforce` mode, dvarapala drops heavy hitters with or without a pass.
Clients that do not accept `text/html`, and gRPC clients, get `429`
instead of the page.

The page sends its answer to `/.well-known/dvarapala/verify`. If an
ingress or gateway sends only some paths to dvarapala, add that prefix to
those paths. Otherwise the upstream answers it and the browser loops on
the challenge.

Keys: [`[challenge]`](configuration.html#challenge).

## JA4 fingerprints

With `[fingerprint]` set, the TLS listener computes the JA4 fingerprint
of each ClientHello. `deny` drops matching clients. `challenge` makes
them solve the challenge, whatever the detector says. `header` forwards
the JA4 to the upstream. Each entry is a full JA4 or a prefix that ends
in `*`.

Keys: [`[fingerprint]`](configuration.html#fingerprint).

## Routes

`[[routes]]` entries apply a policy to the requests that they match. The
first match wins. A route matches on `host`, `path` (a prefix, `=` for
exact), `methods` and `clients` (CIDRs). Every condition that is set must
hold. A route can:

- `deny` the request: `403` and the connection closed, before any bucket.
- Add its own bucket (`rate`, `burst`), keyed by the client, a request
  header or the JA4.
- Turn the challenge off with `challenge = false`, for clients that
  cannot run a script.
- Skip the WAF with `waf = false`.

Routes only tighten. The global bucket, detection and `fingerprint.deny`
still apply to every request. The table of each route holds at most
`max_keys` keys.

A route can also match on where a client comes from: `country` and `asn`
from the GeoIP database, and `feeds` from the reputation feeds below.

Keys: [`[[routes]]`](configuration.html#routes).

## Reputation feeds and GeoIP

`[[intel.feed]]` loads a list of networks from a file or an `https://`
URL. Examples are Spamhaus DROP, FireHOL level 1, the Tor exit list or a
list of the operator ([RFC 0031](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0031-network-intel.md)).
Each feed has one action:

- `deny`: `403` and the connection closed, before any bucket.
- `challenge`: the proof of work until the client holds a pass, during an
  attack or not.
- `tag`: routes match it with `feeds`.

Feeds start in `observe`. In this mode, a feed lets the request through and
counts the action it skipped in `dvarapala_intel_hits_total`.

dvarapala fetches a `url` feed again every `refresh`. If a fetch fails or
gives an invalid list, dvarapala keeps the last good list. As a result,
an outage of a third-party list blocks no new addresses. dvarapala reads
a `path` feed again on reload and through `config_watch`. A cron job that
rewrites the file is enough. dvarapala parses lists with the caps of
attacker input (body size, entries, line length). It refuses a prefix
wider than `/8` (IPv6 `/16`), so a broken list cannot deny everyone.

`intel.geoip` points at the MaxMind DB files that the operator supplies
(one path, or a list of up to 4). The files use the MaxMind schema:
GeoLite2 or GeoIP2, or DB-IP Lite. dvarapala downloads none. A file with
another schema (IPinfo) loads but matches nothing. Routes then match on
`country` and `asn`, for example an admin path open to one country.

Each file sets what it holds: a Country or City file gives `country`,
an ASN file gives `asn`. The list combines them, so the free
GeoLite2-Country and GeoLite2-ASN files together serve both. GeoIP needs
the `geoip` feature, which the container image has.

To keep the files current, run the MaxMind `geoipupdate` on a schedule,
because the databases change weekly. A reload or `config_watch` then
picks up the new bytes. If a file does not change, dvarapala does not swap it.
The log line `geoip loaded path=<path> sha256=<hex>` names each swap.

On Kubernetes, the files do not fit a ConfigMap or Secret (1 MiB at most,
and GeoLite2-Country is several MiB). Operator gateways mount them from a
PersistentVolumeClaim that a `geoipupdate` CronJob fills (RFC 0033,
[example](https://github.com/franzramadhan/dvarapala/blob/main/examples/kubernetes-geoip.yaml)).
dvarapala reads each file whole, so every gateway pod holds its size in
memory.

Feeds act at L7 only: dvarapala does not push them to the XDP block list.
If a list must drop in the driver, put it in `xdp.block`.

Keys: [`[intel]`](configuration.html#intel),
[example](examples.html#inteltoml).

## WAF

With `[waf]`, each request that passed the limits goes over SPOP to a
`coraza-spoa` sidecar (a separate process next to dvarapala). The sidecar
runs OWASP Coraza with the Core Rule Set. The sidecar verdict blocks the
request (`403`) or forwards it ([RFC 0017](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0017-waf.md)).
Start in `observe`, add exclusions in the sidecar configuration, then
enforce. The protection path fails closed (it refuses the request if a check
cannot run). In enforce mode, the request gets `503` if the sidecar
does not answer in `timeout`. To pass the request instead, set
`on_error = "pass"`. See
[WAF](waf.html).

Keys: [`[waf]`](configuration.html#waf).

## Upstream concurrency

Rate limits per client do not protect a backend from a flood that spreads
over many clients, each under its rate. `[concurrency]` caps the requests
in flight to the upstream ([RFC 0032](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0032-adaptive-concurrency.md)).

`fixed` is a hard cap. `gradient` finds the cap from the latency of the
backend. Every `window`, it compares the median latency with the lowest
latency seen. While latency stays flat, it grows the limit by about the
square root of the limit. When latency rises, it cuts the limit, by at
most half. A connect error or timeout counts as a slow answer, so a
backend that stops answering shrinks the limit.

Over the limit, dvarapala sheds the request (answers at once, never
queues it) with `503` and `Retry-After: 1` (gRPC: `RESOURCE_EXHAUSTED`).
The last `reserve` of the limit stays for trusted clients (a valid
challenge pass, or a low `[ml]` score). During an attack, dvarapala sheds
heavy hitters first. Only the wait for the response head counts:
streaming bodies and WebSocket tunnels do not hold a slot.

Routes can bypass the limit (`concurrency = false`) or weigh more
(`concurrency_weight`). A shed request never ejects a `[pool]` endpoint
or spends a retry.

Keys: [`[concurrency]`](configuration.html#concurrency),
[example](examples.html#concurrencytoml).

## LLM labels

If `[ml.llm]` has at least one trigger, dvarapala samples requests. It
sends them to an LLM, off the request path ([RFC 0023](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0023-llm-labels.md)).
The triggers are requests that hit a WAF rule, fail a challenge, arrive
during an attack, score in an uncertain `[ml]` band or match a route.
Sampling takes one request per client and trigger in `per_client`. The
LLM is a System One decision model (`protocol = "systemone"`) or an
OpenAI-compatible chat model (`"chat"`).

The answer is one of `labels`, a confidence and a short pattern. Labels
go to the logs, the `dvarapala_llm_*` metrics, the LLM labels page of the
console and the `export` file. They never change a verdict.

Sampling runs while the console switch is on (`admin.mode_switch`, at
most `max_duration`) or with `enabled = true`. dvarapala never sends
`Cookie` and `Authorization`. Query values become `_`. dvarapala sends
the body only with `body_bytes`. Use the labels to decide when the WAF
can leave `observe`, or to train the [scoring model](#scoring-model).

With `persist = true` and the PostgreSQL store, each replica writes
labels as rows ([RFC 0024](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0024-llm-label-store.md)).
The counts and recent labels in the console then cover all replicas and
survive restarts. dvarapala deletes rows older than `retention` (30
days). `GET /llm/export` streams the rows as JSON lines. If the store is
lost, dvarapala logs it once and keeps labels in memory.

Keys: [`[ml.llm]`](configuration.html#mlllm).

## Manual blocks

`POST /blocks?cidr=<net>&ttl=<duration>` on the admin API blocks a
network until the `ttl` ends. The network gets `403` and the connection
closed before any other check. If `[xdp]` is on, XDP also drops it. At
most `admin.max_blocks` blocks exist at a time, each at most
`admin.max_block_ttl` long. See [Operations](operations.html).

Keys: [`[admin]`](configuration.html#admin).

## Across replicas

A `[store]` is Redis or PostgreSQL (features `redis` and `postgres`).
With a store, replicas behind one load balancer share one limit per
client, instead of one limit each. In `enforce` mode, they drop the heavy hitters that any
replica finds. In forward mode, they split the budget of each
destination. The request path never waits for the store. If the store is
lost, dvarapala falls back to local limits and logs it. See
[Clusters](clusters.html).

Keys: [`[store]`](configuration.html#store).

## TLS

dvarapala terminates TLS with rustls and negotiates `h2` or `http/1.1` by
ALPN. It reloads the certificate on `SIGHUP`. It also limits how many
handshakes run at once and how long each one can take. As a result, a
handshake flood costs bounded CPU.

Keys: [`[tls]`](configuration.html#tls),
[`[upstream_tls]`](configuration.html#upstream_tls).

## HTTP/3 over QUIC

An optional UDP listener (builds with the `http3` feature, off by default)
serves HTTP/3 into the same rate limit, detection and upstream. A flood of
QUIC Initials from spoofed sources must not cost handshakes. Thus, once
`retry_threshold` handshakes are in progress, new clients must first echo
a Retry token. This costs one extra round trip and keeps no state on the
server. `retry = "always"` asks every new client.

Over `max_connections`, dvarapala refuses new connections before any
crypto. One client address holds at most `max_per_client` connections, and
`accept_rate` can limit its new connections, counted on the validated
address only. Each connection gets `max_streams` concurrent requests. 0-RTT is
off, so dvarapala processes no request before the handshake ends. TCP
responses advertise the listener with `Alt-Svc`.

Volumetric UDP floods still need filtering at the network edge.

Keys: [`[quic]`](configuration.html#quic).

## HTTP/2

These limits stop the cheap HTTP/2 attacks:

- Rapid reset (streams opened and cancelled).
- Oversized header lists.
- Idle connections (keepalive).

Over a limit, the connection gets `GOAWAY`.

Keys: [`[http2]`](configuration.html#http2), `upstream_protocol`.

## WebSocket

The upgrade request goes through the rate limit and detection like any
request, so dvarapala throttles a reconnect storm. After the `101`, the
tunnel limits apply: `max_tunnels` in total (`503` above it),
`idle_timeout`, and `max_lifetime`. `max_lifetime` makes long-lived
clients reconnect through the current limits once an attack starts.

Keys: [`[upgrade]`](configuration.html#upgrade).

## Metrics

Every layer reports on the metrics listener. The list is at the end of
[Configuration](configuration.html#metrics-1).
