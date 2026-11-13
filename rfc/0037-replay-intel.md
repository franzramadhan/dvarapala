# 0037: Replay with intel feeds and GeoIP

| Status | Date | PR | Release |
|---|---|---|---|
| draft | 2026-11-13 | #366 | |

> `dvarapala replay` puts the `[intel]` feeds and the GeoIP database in force from local files, so deny, challenge and tag feeds and the route `feeds`, `country` and `asn` matchers give the same verdicts as `serve`. A `url` feed is never fetched: `--feed <name>=<file>` supplies a saved copy.

## Problem

RFC 0016 made replay the way to try a config on recorded traffic before it reaches clients. RFC 0031 added reputation feeds and GeoIP route matchers, asks operators to start every feed in `observe`, and left replay out: its Implementation notes say replay ignores `[intel]`, but the `replay ignores` warning does not name it today (`crates/dvarapala/src/replay.rs`). #365 fixes that on its own and lands first, adding `[intel]` and `[concurrency]` to the warning; this RFC builds on it:

- The replay layer is built by `layer::config` (`crates/dvarapala/src/layer.rs`) without intel. In `serve`, feeds reach the layer only through `intel::Running::commit`, which the reloader calls (`crates/dvarapala/src/intel/running.rs`).
- So in replay a `deny` feed in `enforce` denies nothing, a `challenge` feed challenges nobody, and a route with `feeds`, `country` or `asn` never matches. The report shows `200` where `serve` answers `403` or the challenge page.
- The report has no `dvarapala_intel_hits_total`, so an operator cannot see how many recorded clients a feed would have hit before moving it from `observe` to `enforce`.

A feed of 100 000 prefixes from a third party can deny a large share of real users. Replay over yesterday's log is the cheapest way to see that before enforcing it.

## Proposal

- Replay reads every `[[intel.feed]]` with a `path`, and `intel.geoip`, at start, with the checks and caps `serve` uses (`intel.max_bytes`, `max_entries`, the line and prefix rules of RFC 0031). Then it puts them in force on the replay layer with their `action` and `mode`. No refresh task, no `config_watch`.
- A feed that does not load exits with status 2, naming the feed and the file, as a bad `path` feed refuses a start or a reload in `serve`.
- A `url` feed is never fetched: replay sends nothing (RFC 0016). `--feed <name>=<file>` reads a saved copy of the named feed instead, for a `url` or a `path` feed (for example the list as it was on the day of the log). It may be given more than once. An unknown name exits with status 2.
- A `url` feed without `--feed` stays empty. An `enforce` `deny` `url` feed without a copy exits with status 2 naming the feed and `--feed`, because replay would report allows where `serve` denies. Any other `url` feed without a copy is shown as `not loaded` in the report and named in the `replay ignores` warning as `intel.feed "<name>" (url)`.
- Reproducibility: the report has one line per feed (name, source `path`, `url` or `--feed`, entries, sha256 of the file) and one for the GeoIP database (path and the sha256 `intel/geoip.rs` already computes), so two runs that differ show why. `--geoip <file>` is out of scope: the database is the configured `intel.geoip`.
- `intel.geoip` set on a build without the `geoip` feature exits with status 2, as `serve` does (`intel/geoip.rs`).
- The report adds the `dvarapala_intel_hits_total` series. `observe` feeds are counted and never change a verdict, as in `serve`.
- Lookups use the line's `client` after `trusted_proxies` and `xff`, the address `serve` uses: a listed client behind an unlisted trusted peer is matched.
- `[concurrency]` limit and shedding stay out of replay (RFC 0032 case 15 needs a latency model). Priority classes are already on in replay whenever `mode != off`. The warning naming `[concurrency]` is #365, not this RFC.
- Out of scope: GeoIP or feed fields in `--out`, and a feed list that changes over the log's time span.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/dvarapala/src/intel/running.rs` | a load without refresh tasks: `prepare` with per-feed file overrides, then put the feeds and the database in force on a layer without spawning `url` fetches |
| `crates/dvarapala/src/replay.rs` | the `--feed` flag, loading intel before the first line, naming unfetched `url` feeds, the report prefix |
| `crates/dvarapala/tests/replay.rs` | the integration cases |
| `examples/replay.toml`, `examples/replay/` | a `path` feed and a log with listed clients |

### Configuration

No new config key. One new replay argument:

| Key | Default | |
|---|---|---|
| `--feed <name>=<file>` | none | Replay only: read the named feed from `file` instead of its `path` or `url`; repeatable. Without it a `url` feed is empty in replay |

### Logs and metrics

| | |
|---|---|
| `msg="replay ignores"` | also names each `url` feed without `--feed` (`[intel]` and `[concurrency]` come with #365) |
| report intel lines | per feed: name, source, entries, sha256 or `not loaded`; for the database: path, sha256 |
| `dvarapala_intel_hits_total{feed,action,mode}` | now in the replay report, from the existing RFC 0031 counter |

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | a `deny` feed in `enforce` from a `path` listing `192.0.2.0/24`, 10 lines, 4 from `192.0.2.7` | replay | 4 lines `403` in `--out`, `dvarapala_intel_hits_total{action="deny",mode="enforce"}` 4 in the report | integration (`dvarapala/tests`) |
| 2 | the same feed in `observe` | replay | every line `200`, hits with `mode="observe"` 4 | integration |
| 3 | a `challenge` feed in `enforce`, `[challenge]` on | a browser line from a listed client | the challenge status, `dvarapala_challenges_total` counts it | integration |
| 4 | a `tag` feed and a route with `feeds = ["tor"]`, `rate = 1` | two lines in one second from a listed client, two from an unlisted one | the listed client's second line throttled, the unlisted client's not | integration |
| 5 | a test database mapping `198.51.100.0/24` to `ZZ`, a route with `country = ["ZZ"]` denying | lines from `198.51.100.1` and `203.0.113.1` | the first `403`, the second `200` | integration (feature `geoip`) |
| 6 | an `observe` `url` feed, no `--feed` | replay | the report shows the feed `not loaded`, one `replay ignores` warning naming `intel.feed "<name>" (url)`, no network connection attempted, its lines allowed | integration |
| 7 | the same `url` feed, `--feed <name>=<file>` listing `192.0.2.0/24`, `enforce`, `deny` | replay | the listed lines `403` | integration |
| 8 | `--feed nope=<file>`; a `path` feed with a malformed line; a feed file over `max_bytes` | replay | exit status 2 naming the flag, or the feed, the file and the reason | integration |
| 9 | a `deny` `url` feed in `enforce`, no `--feed` | replay | exit status 2 naming the feed and `--feed` | integration |
| 13 | a `path` feed and `--feed <name>=<other file>` | replay | the other file's entries are in force, the report line shows its sha256 | integration |
| 14 | a feed and a database | replay | the report has one line per feed (name, source, entries, sha256) and one for the database with its sha256 | integration (feature `geoip`) |
| 15 | `intel.geoip` set, build without feature `geoip` | replay | exit status 2, as `serve` | integration |
| 16 | `trusted_proxies` lists the peer `203.0.113.9`, a `deny` feed in `enforce` lists `192.0.2.7`, a line from peer `203.0.113.9` with `X-Forwarded-For: 192.0.2.7` | replay | `403`; the same line from an unlisted client behind the peer is `200` | integration |
| 10 | `--feed` arguments: missing `=`, empty name, empty path, repeated name | argument parsing | refused with the usage line | unit (`replay`) |
| 11 | `examples/replay.toml` with a `path` feed | `example_configs_load` and the replay of `examples/replay/` | loads, report shows the intel hits | integration |
| 12 | 1 million lines, 10000 clients, a 100 000 prefix feed | replay, release build | within 10 percent of the RFC 0016 bench without a feed | bench (`dvarapala/benches/replay.rs`) |

## Alternatives

| Option | Why not |
|---|---|
| Fetch `url` feeds in replay | replay sends nothing (RFC 0016); the list today is not the list on the day of the log, and a run would depend on a third-party service |
| Keep ignoring `[intel]`, only warn | the warning is needed in any case, but the feeds are the protection RFC 0031 asks operators to try in `observe` first; replay is the cheapest place to try them |
| A new `[replay]` config section mapping feeds to files | replay inputs belong on the command line with `--config`, `--out` and the log; a config section would be loaded by `serve` too |
| Apply only `path` feeds, no `--feed` | most public lists are `url` feeds; without a saved copy they could never be tried |

## Security and resource limits

- Replay reads files named by the operator on the command line or in the config, never attacker input over the network. Feed files and saved copies go through the RFC 0031 parser with the same caps as `serve` (`intel.max_bytes`, `max_entries`, 128 bytes per line, no prefix shorter than `/8` or IPv6 `/16`). That parser already has its fuzz target.
- Memory is that of `serve` with the same feeds: about 8 bytes per IPv4 range and 32 per IPv6 range (RFC 0031), plus the mapped database.
- Lookups are one binary search per feed and one database lookup per line, as in `serve`, bounded by the 64 feed limit.
- Replay still opens no socket: a `url` feed without `--feed` is empty, never fetched.

## Rollout

- **Rollout:** the next release. Replays of configs without `[intel]` do not change. Configs with feeds or GeoIP routes now give the verdicts `serve` would. The `replay ignores` warning names what is still skipped (after #365). `CONFIG.md` (Replay), `site/docs/operations.md` and `examples/replay.toml` are updated in the implementation.
- **Off switch:** replay a copy of the config without `[intel]`; replay is an offline command and changes nothing in a running gateway.
