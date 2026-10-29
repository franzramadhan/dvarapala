# 0012: Challenges and JA4 fingerprints

| Status | Date | PR | Release |
|---|---|---|---|
| implemented | 2026-10-29 | #102 | v0.7.0 |

> A stateless proof-of-work challenge that browsers solve once for a signed
> pass cookie, issued during an attack (or always), and the JA4 fingerprint
> of every TLS client, so operators can deny or challenge a TLS stack that
> rotates its addresses.

## Problem

In `Attack` with detection in `enforce` (RFC 0002), dvarapala has two
answers: drop the heavy hitters and cut every other client's rate to
`attack_rate_factor`. A botnet spread over many addresses is not a heavy
hitter, so the real users pay the same 4x cut as the bots. The engine has
had a `Verdict::Challenge` since RFC 0001, but nothing issues it: a request
that gets it today is a `429` without `Retry-After`.

The address is also the only thing a client is known by. Bots that rotate
addresses (residential proxies, a /16 of cloud instances) but share one TLS
library look the same at the TLS layer: the ClientHello of `curl`, Go's
`net/http` or a Python script differs from a browser's. JA4 (FoxIO, BSD
3-Clause spec) is the de facto format for that fingerprint, and RFC 0003
deferred it to this RFC.

## Proposal

- **Challenge verdict.** `[challenge] mode`:
  - `"off"` (default): no challenge, as today.
  - `"attack"`: while detection is in `Attack` and `enforce`, a request
    without a valid pass gets `Challenge` instead of the attack-limited
    bucket. A request with a pass keeps the normal (not reduced) limit.
    Heavy hitters are still dropped, pass or not.
  - `"always"`: every request without a valid pass gets `Challenge` (an
    operator's "under attack" switch). Needs no detection.
  - The client's bucket is taken first: a client over its limit gets
    `429` as before, so challenge pages are bounded by the same rate.
- **The challenge.** For a request that accepts `text/html`, a `403` page
  with a small inline script (SHA-256 in plain JavaScript, so it works
  without a secure context) that finds a nonce `n` such that
  `SHA-256(seed ":" n)` starts with `difficulty` zero bits, then loads
  `/.well-known/dvarapala/verify?t=<issued>&s=<seed>&n=<nonce>&r=<path>`.
  The page is the same for every request apart from the numbers; nothing
  from the request is written into it.
  - `seed` is `HMAC-SHA256(secret, "seed" | client key | issued)`, cut to
    128 bits: no server state, bound to the client key, valid for
    `challenge.timeout`.
  - The verify endpoint checks the seed, its age and the work, then sets
    the pass cookie and answers `303` to `r`. `r` must be a path (one `/`,
    then not `/` or `\`, printable ASCII, at most 2048 bytes), otherwise
    `/`: no open redirect.
  - Other requests (no `text/html` in `Accept`) keep today's answer:
    `429` without `Retry-After`, or gRPC `RESOURCE_EXHAUSTED` (RFC 0004).
- **The pass.** Cookie `dvarapala_pass=<expires>.<mac>`,
  `mac = HMAC-SHA256(secret, "pass" | client key | expires)` cut to 128
  bits, `Path=/; Max-Age=<pass_ttl>; HttpOnly; SameSite=Lax`, plus
  `Secure` unless `cookie_secure = false`. Checked in constant time. It is
  bound to the client key (the IPv4 address or IPv6 /64), so a pass solved
  once cannot be handed to a botnet. A client whose address changes solves
  again.
- **JA4.** On the TLS listener, dvarapala reads the ClientHello records
  itself (at most 16 KiB, inside the handshake timeout and slot), computes
  JA4, then hands the same bytes to rustls. Every request on the
  connection gets a `Ja4` extension. A hello that does not parse gets no
  fingerprint; the handshake goes on and rustls decides.
- **Fingerprint rules.** `[fingerprint]`:
  - `deny`: matching requests get `Drop` (`403`, connection closed).
  - `challenge`: matching requests need a pass, whatever `challenge.mode`
    says (needs `challenge.mode` other than `"off"` to be served a page).
  - `header`: the fingerprint is sent to the upstream in this header;
    the client's own copy of it is removed first.
  - Entries are a full JA4 or a prefix ending in `*`
    (`"t13d1516h2_*"`).
  - JA4 is computed only when one of these is set.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/engine/src/guard.rs` | `ChallengeMode`; `Guard::check_passed` issues `Challenge` from the mode, the detector state and whether the request has a pass |
| `crates/l7/src/challenge/pass.rs` | seeds and pass cookies: HMAC, expiry, constant-time check |
| `crates/l7/src/challenge/page.rs` | the challenge page, the proof-of-work check, the verify endpoint and its redirect rule |
| `crates/l7/src/challenge/config.rs` | `ChallengeConfig`, the pass cookie lookup, metrics |
| `crates/l7/src/challenge/body.rs` | `PageBody`: the response body types a page can be written into |
| `crates/l7/src/fingerprint.rs` | the `Ja4` request extension, `deny` and `challenge` rules, the upstream header |
| `crates/proxy/src/tls/hello.rs` | read the ClientHello records off the socket, bounded |
| `crates/proxy/src/tls/ja4.rs` | parse a ClientHello and compute JA4 |
| `crates/proxy/src/tls/prefixed.rs` | a stream that replays the read bytes before the socket |
| `crates/dvarapala/src/config/challenge.rs` | `[challenge]` and `[fingerprint]` |

### Configuration

| Key | Default | |
|---|---|---|
| `challenge.mode` | `"off"` | `"off"`, `"attack"` or `"always"` |
| `challenge.difficulty` | `16` | leading zero bits of work, 8 to 24 (16 is about 65 000 hashes, under a second in a browser) |
| `challenge.timeout` | `"60s"` | how long a seed can be solved |
| `challenge.pass_ttl` | `"1h"` | how long a pass is valid |
| `challenge.secret` | `""` | HMAC key, at least 32 bytes. Empty: a random key per process (passes do not survive a restart or cross replicas; a warning when `store.backend` is not `"memory"`) |
| `challenge.cookie_secure` | `true` | `Secure` on the pass cookie; `false` for plain-HTTP labs |
| `fingerprint.deny` | `[]` | JA4 values or prefixes to drop |
| `fingerprint.challenge` | `[]` | JA4 values or prefixes that always need a pass |
| `fingerprint.header` | `""` | upstream header for the JA4, for example `"x-ja4"`; empty sends none |

### Logs and metrics

| | |
|---|---|
| `dvarapala_requests_total{verdict="challenge"}` | challenge pages and `429`s for clients without a pass (existing metric) |
| `dvarapala_challenges_total{result}` | `issued`, `passed`, `failed` (bad seed, stale seed, wrong work), `invalid_pass` (a cookie that is present but does not verify) |
| `dvarapala_fingerprint_matches_total{rule}` | `deny` or `challenge` matches |
| `dvarapala_tls_ja4_total{result}` | `ok`, `unparsed` (no fingerprint for that connection) |
| `msg="challenge_passed"` | debug, with the client key |

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | `mode = "always"`, no pass | check | `Challenge`; with a pass, `Allow` | unit (`engine::guard`) |
| 2 | `mode = "attack"`, detector in `Attack`, `enforce` | check, no pass | `Challenge`; with a pass, the normal limit (not `attack_rate_factor`) | unit (`engine::guard`) |
| 3 | `mode = "attack"`, `Attack` in `observe`, or `Normal` | check, no pass | no `Challenge` | unit (`engine::guard`) |
| 4 | heavy hitter in `Attack`, `enforce`, with a pass | check | `Drop` | unit (`engine::guard`) |
| 5 | a client over its bucket, no pass, `mode = "always"` | check | `Throttle`, not `Challenge` | unit (`engine::guard`) |
| 6 | a pass for one key | verified for another key, after `pass_ttl`, with one byte changed | rejected each time | unit (`l7::challenge::pass`) |
| 7 | a seed | verified after `timeout`, for another key, with too little work | `failed`; with the right work in time, a cookie and `303` | unit (`l7::challenge::page`) |
| 8 | `r` = `//evil.example`, `/\evil`, `https://x`, CRLF, 3000 bytes | verify | redirect to `/` | unit (`l7::challenge::page`) |
| 9 | `mode = "always"`, `Accept: text/html` | request through the layer | `403`, `text/html`, `Cache-Control: no-store`, the inner service not called | integration (`l7/tests`) |
| 10 | the same, no `text/html`, or gRPC | request | `429` without `Retry-After`, or `grpc-status: 8` | integration (`l7/tests`) |
| 11 | the page's seed solved in the test | verify, then a request with the cookie | `303` with `Set-Cookie`, then the inner service answers | integration (`l7/tests`) |
| 12 | a synthetic ClientHello with GREASE, SNI, ALPN `h2` and the spec's Chrome ciphers, extensions and signature algorithms | JA4 | `t13d1516h2_8daaf6152771_e5627efa2ab1` | unit (`proxy::tls::ja4`) |
| 13 | no SNI, no ALPN, TLS 1.2 only, no extensions | JA4 | `t12i0000...` parts as the spec says (`00` ALPN, `000000000000` hashes) | unit (`proxy::tls::ja4`) |
| 14 | arbitrary bytes | parse a ClientHello | no panic, `None` or a 36-byte JA4 | fuzz (`ja4`) |
| 15 | arbitrary query strings and cookie headers | verify and pass parsing | no panic | fuzz (`challenge`) |
| 16 | a rustls client against the TLS listener, `fingerprint.header = "x-ja4"`, client sends its own `x-ja4` | request | the upstream sees one `x-ja4`, the computed one | integration (`proxy/tests`) |
| 17 | `fingerprint.deny` matching the rustls client | request | `403`, connection closed, `rule="deny"` counted | integration (`proxy/tests`) |
| 18 | a ClientHello split over two records, and one over 16 KiB | handshake | the first fingerprinted and served, the second served without a fingerprint | integration (`proxy/tests`) |
| 19 | `challenge.secret` of 10 bytes, `difficulty = 30`, `mode = "attack"` without detection | start | error naming the key | unit (`config`) |
| 20 | the fingerprinting path | bench | JA4 per handshake under 5 µs | bench (`proxy/benches/ja4.rs`) |

## Implementation notes

Found while building:

- `Guard::check_passed(key, now, pass)` takes a `Pass`: `Missing`,
  `Valid`, or `Required` (a `fingerprint.challenge` match). `check` is
  `check_passed` with `Missing`, so the C ABI is unchanged.
- A failed verify answers `303` to the return path without a cookie, so
  the client gets a fresh page instead of an error. A verify request is
  counted as `verdict="allow"`.
- `PageBody` is implemented for `Full<Bytes>`, `BoxBody` and
  `UnsyncBoxBody`; the `l7` tests moved from `Empty` to `Full` bodies.
- The page lives in `crates/l7/src/challenge/page.html`; its SHA-256 was
  checked against Node's `crypto` for 3000 inputs of one to three blocks.
- Case 18 is covered by unit tests on the reader (`proxy::tls::hello`):
  rustls clients never split their hello, so an integration test could
  not produce one. Case 16 covers the replay on every fingerprinted
  handshake.
- `fingerprint.challenge` with `challenge.mode = "off"` is a start-up
  error instead of a silent no-op.
- Case 20: about 1.2 µs per JA4 on an Apple M-series core.
- `[tls]` moved to `crates/dvarapala/src/config/tls.rs` to keep
  `config.rs` under 500 lines.

## Alternatives

| Option | Why not |
|---|---|
| A CAPTCHA (image or third-party) | third-party calls and privacy cost; proof-of-work needs no service and no user action |
| Server-side challenge state | memory an attacker can fill; HMAC seeds and passes keep it stateless |
| Bind the pass to the JA4 too | browsers move to HTTP/3 after `Alt-Svc`, where there is no TLS ClientHello to fingerprint, so the pass would fail on the switch |
| A per-JA4 rate limit | every user of one browser version shares a JA4; a limit on it throttles them together. Rules per route (a later RFC) can key on it where it makes sense |
| JA4 for HTTP/3 (`q` prefix) | the hello is inside QUIC CRYPTO frames that quinn does not expose; later if needed |
| `crypto.subtle.digest` in the page | needs a secure context, so it fails on plain HTTP; a 40-line SHA-256 works everywhere |
| JA3 | sorted extensions in JA4 make it stable against Chrome's extension shuffling; JA3 is not |

## Security and resource limits

- The attacker controls the ClientHello bytes, the query string of the
  verify endpoint and the `Cookie` header. The hello read is capped at
  16 KiB and runs inside the existing handshake slot and timeout; the
  parser is bounds-checked and fuzzed. The verify endpoint costs two
  HMACs and one SHA-256, less than proxying the request, and is behind
  the client's bucket like any request.
- Nothing from the request is written into the challenge page; the
  script reads its own location for the return path. The page sets
  `Content-Security-Policy: default-src 'none'; script-src
  'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'`.
- A solved seed works only for its client key and only within
  `timeout`; a pass only for its key and `pass_ttl`. Reusing either from
  the same key gives that key nothing it did not earn.
- The work is a speed bump, not a wall: a bot with a JavaScript engine
  can solve it, paying `2^difficulty` hashes per address per `pass_ttl`.
  That is the trade, and why `deny` and `challenge` by fingerprint exist.
- Fail closed: a `Challenge` verdict never reaches the upstream.

## Rollout

- **Rollout:** v0.7.0. `challenge.mode = "off"` and empty
  `[fingerprint]` by default, so nothing changes on upgrade. The
  `--no-default-features` build gains `ring` (already in the default
  build through rustls) for the HMAC.
- **Off switch:** `challenge.mode = "off"`, empty `[fingerprint]`.
