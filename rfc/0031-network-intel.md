# 0031: Network intelligence: reputation feeds and GeoIP / ASN rules

| Status | Date | PR | Release |
|---|---|---|---|
| draft | 2026-11-01 | #N | |

> Load lists of networks from files or URLs (reputation feeds such as
> Spamhaus DROP, Tor exits or an operator's own list), refresh them in
> the background, and deny, challenge or tag their clients. Match routes
> on country and ASN from an operator-supplied MaxMind-format database.

## Problem

Every verdict today comes from traffic dvarapala has already seen
(rates, detection, `[ml]`, challenges) or from CIDRs written by hand
(`[xdp] block`, `[[routes]] clients`, manual blocks through the admin
API). Two common needs have no place:

- **Known-bad networks.** Lists such as Spamhaus DROP/EDROP (hijacked
  netblocks, about 1 000 prefixes), FireHOL level 1, Tor exit nodes
  (about 1 500 addresses) or a provider's abuse list change daily.
  Copying them into the config by hand goes stale, and a reload per
  update is a chore every operator repeats.
- **Where a client comes from.** An API used from one country, or an
  admin path that should never be called from a hosting ASN, is a rule
  most WAFs and CDNs offer. Today it needs a CIDR list per country,
  which is thousands of prefixes and changes monthly.

Both are inputs to policy, not policy: the operator chooses the action
per list, and nothing is fetched unless configured.

## Proposal

- `[[intel.feed]]`: a named list of networks from `path` (a local file)
  or `url` (`https://` only), one CIDR or address per line, `#` and `;`
  comments, blank lines ignored (the Spamhaus, FireHOL and Tor bulk exit
  list formats all reduce to this).
- Each feed has an `action`:
  - `"deny"`: `403` and the connection closed, as a route `deny`, before
    any bucket. With `[xdp]` on, deny entries also go into the XDP block
    list as static entries, within `xdp.max_blocks`.
  - `"challenge"`: the client gets the proof-of-work challenge (RFC
    0012) until it holds a pass, attack or not.
  - `"tag"`: no verdict; the feed's name is added to logs, LLM samples
    (RFC 0023) and a `[ml]` feature, and routes can match it.
- `mode = "observe" | "enforce"` per feed, default `"observe"`: observe
  counts what the action would do and lets the request through, as the
  WAF and XDP do.
- A feed loads at start; a start with a `path` that does not parse is an
  error, a `url` that fails to fetch is logged and the feed starts empty
  (there is no last good copy yet). Every `refresh` (default `"1h"`) a
  `url` feed is fetched again; a failed or invalid fetch keeps the last
  good list (fail open to the previous list, logged and counted). A
  `path` feed is reread on reload and by `config_watch`.
- `intel.geoip`: the path of a MaxMind DB file (GeoLite2-Country,
  GeoLite2-ASN, a combined City file, or an IPinfo or DB-IP file in the
  same format). Nothing is downloaded: the operator brings the file and
  its license. Reread on reload and by `config_watch` when its bytes
  change, as the model in RFC 0029.
- `[[routes]]` gains `country` (ISO 3166-1 alpha-2 codes), `asn`
  (numbers) and `feeds` (feed names); each is a list, any element
  matches, and an empty list matches anything, as `clients`. `country`
  and `asn` without `intel.geoip` are a config error.
- A client whose address is not in the database has no country and no
  ASN: it never matches a `country` or `asn` condition.
- Lookups use the client key (after `trusted_proxies` and RFC 0030),
  once per request in the rate limiter, never on the connection path.
- The console (RFC 0018) shows each feed's size, last refresh and hit
  counts, and the country and ASN of top talkers.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/engine/src/intel/set.rs` | an immutable prefix set (sorted ranges, binary search) per feed, built off the request path |
| `crates/engine/src/intel/parse.rs` | the line format parser, bounded per line and per list |
| `crates/engine/src/routes/matcher.rs` | the `country`, `asn` and `feeds` conditions |
| `crates/l7/src/intel.rs` | the feed verdicts and tags in the rate limiter, from the policy |
| `crates/dvarapala/src/intel/fetch.rs` | the refresh task: `https://` fetch with the existing `hyper-util` client and rustls, size and time caps |
| `crates/dvarapala/src/intel/geoip.rs` | the MaxMind DB reader, behind a new `geoip` feature (`maxminddb`, `default-features = false`) |
| `crates/dvarapala/src/reload.rs` | swaps feeds and the database in the policy |
| `fuzz/fuzz_targets/intel_feed.rs`, `fuzz/fuzz_targets/geoip.rs` | the feed parser and the database reader over arbitrary bytes |
| `examples/intel.toml`, `site/docs/protection.md`, `CONFIG.md` | a config with a Spamhaus DROP deny feed, a Tor tag feed and a country route |

### Configuration

| Key | Default | |
|---|---|---|
| `intel.feed[].name` | required | Label in metrics, logs and `routes.feeds`; unique |
| `intel.feed[].path` / `url` | one required | Local file, or an `https://` URL |
| `intel.feed[].action` | required | `"deny"`, `"challenge"` or `"tag"` |
| `intel.feed[].mode` | `"observe"` | `"enforce"` applies the action |
| `intel.feed[].refresh` | `"1h"` | Fetch interval for `url`, at least `"5m"` |
| `intel.feed[].max_entries` | `200000` | A list over it is refused (the previous one kept) |
| `intel.max_bytes` | `"16MiB"` | Largest feed body or file read |
| `intel.geoip` | unset | MaxMind DB file; unset turns `country` and `asn` off |
| `routes[].country` / `asn` / `feeds` | `[]` | Route conditions, any element matches |

Feeds and `intel.geoip` reload; adding or removing a `url` feed also
starts or stops its refresh task.

### Logs and metrics

| | |
|---|---|
| `dvarapala_intel_feed_entries{feed}` | prefixes in the list in force |
| `dvarapala_intel_feed_refresh_total{feed,result}` | `ok`, `fetch_error`, `invalid`, `too_large`, `unchanged` |
| `dvarapala_intel_feed_last_success_timestamp_seconds{feed}` | alert when a feed goes stale |
| `dvarapala_intel_hits_total{feed,action,mode}` | requests matched per feed |
| `msg="intel feed refresh failed" feed=<n> error=<e>` | each failure, the previous list stays |
| `msg="geoip loaded" sha256=<hex> type=<db type>` | at start and on each swap |
| access log `intel=<feed,...> country=<cc> asn=<n>` | when present |

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | a feed body with CIDRs, bare addresses, comments, `; SBL123` suffixes and blank lines | parsed | the expected prefix set; a malformed line is an error naming its line number | unit |
| 2 | a set of 100 000 IPv4 and IPv6 prefixes | lookups of members and non-members | correct, and under 200 ns each | unit, bench |
| 3 | the feed parser and the database reader | `cargo fuzz` for 60 s | no panic, no allocation over the caps | fuzz |
| 4 | a `deny` feed in `enforce` listing `192.0.2.0/24` | a request from `192.0.2.7` | `403`, connection closed, `hits{action="deny",mode="enforce"}` 1 | integration |
| 5 | the same feed in `observe` | the same request | allowed, `hits{mode="observe"}` 1 | integration |
| 6 | a `challenge` feed, no attack | a browser request from a listed address | the challenge page; with a valid pass, allowed | integration |
| 7 | a `tag` feed and a route with `feeds = ["tor"]`, `rate = 1` | two requests from a listed address | the second is throttled; a non-listed client is not | integration |
| 8 | a `url` feed served by a test server | the server returns 500, then a list over `max_entries` | both refused, the previous list in force, `refresh_total` counts each | integration |
| 9 | a `path` feed | the file changes and `config_watch` runs | the new list applies without a restart | integration |
| 10 | a test database mapping `198.51.100.0/24` to `ZZ` and AS64500 | a route with `country = ["ZZ"]` and one with `asn = [64500]` | a request from `198.51.100.1` matches; one from `203.0.113.1` matches neither | integration |
| 11 | a route with `country` and no `intel.geoip` | start or reload | refused naming `routes[].country` | unit |
| 12 | `[xdp]` enforce and a `deny` feed in `enforce` | the feed loads, then refreshes without one prefix | the prefixes are in the XDP block list, the removed one is gone | integration |
| 13 | an idle binary with a 100 000 prefix feed | `footprint` | RSS within the RFC 0001 budget plus the documented per-prefix cost | bench |
| 14 | `examples/intel.toml` | `example_configs_load` | loads | integration |

The test database is generated in the test from RFC 5737 ranges and a
private-use ASN; no third-party database is checked in.

## Alternatives

| Option | Why not |
|---|---|
| Download GeoLite2 automatically | needs a MaxMind account and license key, and the license is the operator's to accept; bringing the file keeps defaults generic |
| Ship built-in feed URLs | defaults would depend on third-party services and their terms; `examples/` names them instead |
| Fail closed when a feed fails to refresh | an outage of a third-party list would block or challenge real users; the previous list is the safest state |
| Put feeds in the store (RFC 0010) for clusters | each replica fetching the same public list is simpler and has no single point of failure; a later RFC can share private lists |
| A radix trie per feed | sorted ranges with binary search are smaller, immutable and fast enough at these sizes |
| Feeds as route `clients` lists | a route matches one list per field and cannot deny before buckets with its own observe mode; feeds also reach XDP |

## Security and resource limits

- A feed URL is configured by the operator, but its content comes from
  a third party: it is parsed with the same caps as attacker input
  (`intel.max_bytes`, `max_entries`, line length 128 bytes), fetched
  over `https://` only, with a 30 s total timeout, and never on the
  request path.
- A hostile or broken feed can at worst deny, challenge or tag the
  networks it lists, under the action and mode the operator chose. A
  feed that lists `0.0.0.0/0` or `::/0` is refused (prefixes shorter
  than `/8` and `/16` IPv6 are a parse error) so a broken list cannot
  deny everyone.
- Memory: about 40 bytes per prefix (two 16-byte bounds plus padding),
  so 8 MB at the default `max_entries`; a refresh holds two copies of a
  feed at most. A GeoLite2-Country file is about 10 MB, mapped once.
- Lookups are a binary search per feed and one database lookup per
  request, bounded by the number of feeds configured.

## Rollout

- **Rollout:** a minor release. No feed and no database by default:
  nothing changes on upgrade. The `geoip` feature joins the release
  binaries and the image (the `maxminddb` crate is pure Rust, ISC; `cargo deny check` before
  the implementation PR).
  New feeds start in `observe`.
- **Off switch:** remove the feed (or set `mode = "observe"`) and
  reload. Removing `intel.geoip` needs the `country` and `asn`
  conditions removed in the same reload.
