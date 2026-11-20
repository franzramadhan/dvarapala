# 0038: Intel deny feeds in the XDP block list

| Status | Date | PR | Release |
|---|---|---|---|
| draft | 2026-11-20 | | |

> An enforced `deny` feed (RFC 0031) can opt in to the XDP block list (RFC 0011). Its networks are dropped in the driver, and each refresh adds and removes them, so a reputation list costs no handshake, no socket and no rate limiter lookup.

## Problem

RFC 0031 planned this as its test case 12 and dropped it at implementation. The XDP block list had only the dynamic entries of heavy hitters, which expire and are never removed, and the static `xdp.block` entries, which are written once at load (`crates/xdp/src/loader.rs:75-81`). Nothing could follow a feed that changes.

Today a `deny` feed acts in the rate limiter. A listed source still gets:

- a SYN, a SYN-ACK and a full TCP handshake, then an `[l4]` table entry, a TLS handshake (the most expensive step) and an HTTP request parse, all before the `403`;
- the same for every new connection, since the `403` closes the connection and the client opens another.

A DROP-style list exists to name networks that send nothing but attacks. A botnet on those networks makes dvarapala pay the full TLS cost per connection while XDP, already attached, could drop the packets for a few nanoseconds each. The documented workaround (`site/docs/protection.md:228-229`) is copying the list into `xdp.block`. That copy is fixed at start, needs a restart to change, and goes stale as the feed changes.

## Proposal

- `intel.feed[].xdp` (default `false`): when `true`, the feed's networks also go to the XDP block list, as entries that never expire. The key is allowed only on a feed with `action = "deny"` and `mode = "enforce"`, and needs `[xdp]` with `mode = "enforce"`. Anything else is a start-up and reload error naming `intel.feed[].xdp`.
- On the first good list and on each refresh or reload that changes the list, dvarapala computes the networks to add and to remove, and applies them to the trie under the loader's lock. A refresh that fails keeps the entries in force, as the L7 list does. A feed removed from the config, or switched to `xdp = false`, `observe` or another action, has its entries removed.
- The feed's ranges (`PrefixSet` merges adjacent networks) are turned back into the fewest CIDRs that cover them exactly. IPv4-mapped ranges go in as IPv4.
- Feed entries share `xdp.max_blocks` with the static and dynamic ones, as a third kind next to `statics` and `dynamic` in `crates/xdp/src/maps.rs`. Before writing anything, dvarapala checks that the feed fits in the room left by the static entries and the other feeds. If it does not fit, nothing of that feed is pushed and its previous entries stay. This is logged and counted, and the L7 deny still applies. Dynamic blocks get the room that is left, so a big feed shrinks the room for heavy hitters, and the docs say so.
- An entry with the same network as a static `xdp.block` entry, another feed's entry or a dynamic entry is shared, with a reference count. Removing it for one owner never removes it for another. When a feed takes a dynamic entry's network, the entry becomes permanent. When that feed lets it go, the entry stays until its own expiry.
- `xdp.allow` still wins over every block, so a balancer listed by a feed is never dropped.
- With `l4.proxy_protocol` on, `intel.feed[].xdp = true` is a config error. The packets of carried clients come from the balancer (RFC 0030), so the entries would only reach direct peers. For those, the static `xdp.block` remains.
- `intel.feed[].xdp` reloads with the feed. `[xdp]` keys still need a restart.
- Out of scope: pushing `challenge` or `tag` feeds, pushing GeoIP countries or ASNs, and changes to the eBPF program (value 0 already means a permanent entry).

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/engine/src/intel/set.rs` | `PrefixSet::cidrs`: the exact CIDR cover of the ranges, and the diff of two sets as CIDRs to add and to remove |
| `crates/xdp/src/maps.rs` | feed entries per feed name in `Blocks`: reference counts shared with static and dynamic entries, room checks, diff application |
| `crates/xdp/src/loader.rs` | `Xdp::set_feed(name, cidrs)` and `Xdp::remove_feed(name)`: all or nothing per feed, the trie writes under the state lock |
| `crates/dvarapala/src/xdp.rs` | hands the loaded `Xdp` to the intel code next to the dynamic `BlockSink` |
| `crates/dvarapala/src/intel/running.rs`, `feeds.rs` | pushes a feed's list on commit and on each refresh that changes it, removes it when the feed goes |
| `crates/dvarapala/src/config/intel.rs` | the `xdp` key and its checks against `[xdp]`, `action`, `mode` and `l4.proxy_protocol` |
| `CONFIG.md`, `examples/intel.toml`, `site/docs/protection.md` | the key, the metrics, the shared `max_blocks` budget |

### Configuration

| Key | Default | |
|---|---|---|
| `intel.feed[].xdp` | `false` | Also drop the feed's networks in the XDP block list. Needs `action = "deny"`, `mode = "enforce"`, `xdp.mode = "enforce"` and `l4.proxy_protocol = "off"`. `false` removes the entries on reload |

The feed entries count against `xdp.max_blocks` (default `65536`).

### Logs and metrics

| | |
|---|---|
| `dvarapala_xdp_feed_entries{feed}` | CIDRs of the feed in the XDP block list |
| `dvarapala_xdp_feed_sync_total{feed,result}` | `ok`, `unchanged`, `too_large` (does not fit in `xdp.max_blocks`), `error` (a trie write failed, the previous entries restored) |
| `dvarapala_xdp_blocks` | unchanged: every entry, the feed ones included |
| `msg="xdp feed refused" feed=<n> entries=<n> room=<n>` | each `too_large` or `error`, the previous entries kept |

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | ranges `192.0.2.0` to `192.0.2.130` and `2001:db8::/48` | `PrefixSet::cidrs` | `192.0.2.0/25`, `192.0.2.128/31`, `192.0.2.130/32`, `2001:db8::/48`, exactly covering the ranges | unit (engine) |
| 2 | two sets | the diff | the CIDRs to add and to remove, and applying them to the first set gives the second | unit (engine) |
| 3 | `Blocks` with a static `192.0.2.0/24` and a feed listing it | the feed drops it | the static entry stays in the trie | unit (`xdp/maps`) |
| 4 | a dynamic block of `198.51.100.7/32` | a feed adds `198.51.100.7/32`, then removes it | permanent while the feed holds it, then expires at its own time | unit |
| 5 | `max_blocks = 4`, one static entry | a feed of 4 CIDRs | refused whole, nothing written, `result="too_large"`, the previous entries kept | unit |
| 6 | a feed in the trie | a dynamic block when the room is used up | the dynamic entry that expires first is replaced, never a feed entry | unit |
| 7 | `[xdp]` enforce, a `deny` feed in `enforce` with `xdp = true` listing `192.0.2.0/24` | a SYN from `192.0.2.7` through `BPF_PROG_TEST_RUN` | `XDP_DROP`, `dvarapala_xdp_packets_total{action="drop",reason="block"}` 1 | integration (`xdp/tests`, Linux, root) |
| 8 | the same feed | it refreshes without `192.0.2.0/24` and with `203.0.113.0/24` | `192.0.2.7` passes, `203.0.113.1` is dropped, `dvarapala_xdp_feed_entries` is 1 | integration |
| 9 | the same feed | the refresh fails (`500`) | the entries stay, `result` of the feed refresh is `fetch_error` | integration |
| 10 | the same feed | a reload sets `xdp = false`, or removes the feed | its entries are removed, static and dynamic entries stay | integration |
| 11 | `xdp = true` on a `tag` feed, an `observe` feed, without `[xdp]`, with `xdp.mode = "observe"`, or with `l4.proxy_protocol = "v2"` | start or reload | refused naming `intel.feed[].xdp` | unit (config) |
| 12 | `xdp.allow = ["192.0.2.10/32"]` and a feed listing `192.0.2.0/24` | a packet from `192.0.2.10` | passes | integration |
| 13 | a feed of 50 000 ranges | the first push, then a refresh changing 1% | the first push within 1 s, the refresh writes only the diff | bench (`xdp_feed`) |
| 14 | `[intel]` with `xdp = true` | `CONFIG.md` and `examples/intel.toml` | the key and both metrics listed | unit (docs check) |

## Alternatives

| Option | Why not |
|---|---|
| Keep copying feeds into `xdp.block` | fixed at start, needs a restart to change, goes stale with the feed |
| Push every enforced `deny` feed without a key | changes behavior on upgrade, and a large feed would use up the room of heavy hitter blocks without the operator choosing it |
| A separate LPM map for feeds in the eBPF program | needs a program change, a second lookup per packet and a rebuilt object. The current trie already has permanent entries |
| Truncate a feed that does not fit | a partial list drops some listed networks and not others with no rule the operator can see. All or nothing is easier to reason about, and L7 still denies the whole list |
| Push `challenge` feeds | XDP cannot answer with a challenge, only drop |

## Security and resource limits

- The content of a `url` feed comes from a third party. It is already bounded by `intel.max_bytes`, `max_entries` and the prefix floor (no IPv4 prefix shorter than /8, no IPv6 prefix shorter than /16, RFC 0031). With this key, that third party can also have the listed networks dropped in the driver, so the key is opt-in per feed and `xdp.allow` still wins. Spoofing is not a concern: the entries come from the feed, not from traffic.
- Kernel memory: the trie is already sized by `xdp.max_blocks` at load, so feeds add no kernel memory. Process memory: one reference-counted entry per CIDR in `Blocks`, about 48 bytes, so 3 MB at the default `max_blocks`.
- CPU: the diff is computed off the request path, in the refresh task or the reload. Trie writes are one syscall per changed CIDR, under the loader's lock, and never on a packet path. A feed whose diff exceeds `max_blocks` is refused before any write.
- A failed write in the middle of a diff rolls back the CIDRs already written for that feed, so the trie never holds half a refresh.
- Fail closed: a feed that is not pushed still denies at L7, and the refusal is logged and counted.

## Rollout

- **Rollout:** v0.25.0. `intel.feed[].xdp` defaults to `false`, so nothing changes on upgrade. The docs recommend keeping a feed in L7 `enforce` first, then turning on `xdp` once `dvarapala_intel_hits_total` shows the list is right.
- **Off switch:** `intel.feed[].xdp = false` and a reload removes the entries. `ip link set dev <iface> xdp off` detaches the program at once.
