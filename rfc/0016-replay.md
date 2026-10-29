# 0016: Replay of access logs

| Status | Date | PR | Release |
|---|---|---|---|
| accepted | 2026-10-29 | | |

> `dvarapala replay` runs a config's protection layers over a recorded
> access log on a virtual clock and reports what they would have done, so
> a limit, a route or a detection threshold can be tried on yesterday's
> traffic before it reaches clients.

## Problem

Every protection change is a guess until it runs on real traffic:

- A new `rate` or `burst` can throttle a NAT full of customers, or let a
  slow scraper through. Detection has `observe` mode, but the limits and
  routes do not, and observing takes a day of traffic per try.
- A `[[routes]]` deny or a low login rate looks right in review and only
  shows its false positives in production.
- After an attack, there is no way to check whether a tighter config
  would have stopped it: the traffic is gone, only the log is left.

## Proposal

- `dvarapala replay --config <file> [--out <file>] <log>` reads a JSON
  Lines access log (`-` for stdin) and sends each line, as a request,
  through the same `RateLimitLayer` that `serve` builds from the config:
  manual blocks, fingerprint rules, routes, the rate limit, detection,
  scoring and the challenge. The inner service answers `200` without any
  I/O; no listener, upstream, store or XDP program is started.
- Virtual clock: the layer's clock is the `ts` of the line being
  replayed, so a day of traffic replays in seconds and buckets refill and
  detection windows close as they did. A `ts` earlier than the previous
  one keeps the clock where it is.
- Input, one JSON object per line, unknown fields ignored:

  | Field | | |
  |---|---|---|
  | `ts` | required | Unix time in seconds, fractions allowed |
  | `client` | required | The peer address, IPv4 or IPv6 |
  | `method` | `"GET"` | |
  | `host` | `""` | The `Host` header |
  | `path` | `"/"` | Path and query |
  | `xff` | none | `X-Forwarded-For`, used only from `trusted_proxies` as in `serve` |
  | `ja4` | none | The client's JA4, for fingerprint rules and JA4 routes |
  | `headers` | `{}` | Other request headers, name to value |

  Logs in another format are converted first, for example with `jq`.
- Report on stdout when the log ends: lines read, lines skipped (with the
  first ten reasons and line numbers), the virtual time span, then the
  `dvarapala_requests_total`, `dvarapala_challenges_total`,
  `dvarapala_fingerprint_matches_total`, `dvarapala_route_requests_total`
  and `dvarapala_detection_*` series in the
  Prometheus text format, the same names and labels as `/metrics`.
- `--out <file>`: one JSON line per replayed line, `{"line":N,"status":S}`,
  to diff two configs over the same log.
- Keys that need a network (`[store]`, `[xdp]`, `[admin]`, `listen`,
  `upstream`, `[pool]`, `[tls]`, `[quic]`, `[l4]`) are ignored and named
  in one warning: the log has no connections to apply `[l4]` to.
- A config that does not load or validate exits with status 2, as
  `serve` does.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/l7/src/replay/line.rs` | `Line`: parse one log line, build the request with its `PeerAddr` and `Ja4` (feature `replay`) |
| `crates/dvarapala/src/replay.rs` | the subcommand: read lines, the virtual clock, drive the layer, the report and `--out` |

### Configuration

No new keys. The subcommand reads the same file as `serve`.

### Logs and metrics

| | |
|---|---|
| `msg="replay ignores"` | the network keys set in the config that replay skips |
| `msg="line skipped"` | a line that did not parse, with its number and the reason (the first ten) |
| the report | the protection metrics after the last line, as `/metrics` would show them |

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | a line with every field | parse | the request has the method, host, path, headers, `X-Forwarded-For`, `PeerAddr` and `Ja4` | unit (`l7::replay`) |
| 2 | not JSON; no `ts`; no `client`; a bad address; a line over 64 KiB; over 64 headers; a bad header name | parse | an error naming the reason, no panic | unit (`l7::replay`) |
| 3 | `rate = 1`, `burst = 1`, 10 lines of one client | the same second / one second apart | 1 allowed, 9 limited / all 10 allowed | integration (`dvarapala/tests`) |
| 4 | `ts` going back | replay | the clock stays, counts as if the line had the previous `ts` | integration (`dvarapala/tests`) |
| 5 | a route denying `/wp-admin`, 5 lines on it among 20 | replay | the report shows 5 drops for the route | integration (`dvarapala/tests`) |
| 6 | detection in `enforce`, 1 s of a flood from one `/24` among normal traffic | replay | the report shows the attack and drops from the `/24` only | integration (`dvarapala/tests`) |
| 7 | `--out` | replay of 20 lines | 20 JSON lines with the line number and status | integration (`dvarapala/tests`) |
| 8 | `[store]` and `[xdp]` set; a bad line among good ones | replay | one `replay ignores` warning naming both; the bad line skipped and counted, the rest replayed | integration (`dvarapala/tests`) |
| 9 | a missing log file; a bad config | replay | exit status 2 and the reason | integration (`dvarapala/tests`) |
| 10 | 1 million lines, 10000 clients | replay, release build | under 10 s | bench (`dvarapala/benches/replay.rs`) |
| 11 | arbitrary bytes | `Line::parse` | no panic | fuzz (`fuzz_targets/replay_line.rs`) |

## Alternatives

| Option | Why not |
|---|---|
| Shadow mode in `serve` (decide, log, always pass) | needs a day of live traffic per try and cannot test an attack that already happened; replay can come first and a shadow mode later |
| Send the log to a running gateway | runs on the wall clock, so a day takes a day, and needs a listener and an upstream |
| Parse nginx, Envoy and ALB log formats | every format and version differs; JSON Lines plus `jq` covers them without a parser per format |
| A separate tool or crate | would rebuild the layer from the config and drift from `serve`; the subcommand uses the same code path |

## Security and resource limits

- The log is operator input, but its fields came from clients: lines are
  parsed with `serde_json`, at most 64 KiB per line and 64 headers, and a
  bad line is skipped, never fatal. The parser has a fuzz target.
- Memory is bounded by the config, as in `serve`: lines are streamed and
  every table keeps its `max_*` bound. `--out` writes as it goes.
- No network: nothing listens and nothing is sent; challenge pages and
  `Set-Cookie` headers are only counted.
- Replay has no admin API, so manual blocks are empty; a challenge pass
  in a replayed `cookie` header is checked against the wall clock, so
  recorded passes have usually expired and those clients count as
  without a pass (the worst case).

## Rollout

- **Rollout:** v0.11.0, in the release binaries. The `replay` feature of
  `dvarapala-l7` adds `serde_json`; the binary enables it by default
  unless it grows the release binary by more than 150 KB, in which case
  it stays opt-in and the implementation notes say so.
- **Off switch:** a subcommand, nothing runs unless it is called.
