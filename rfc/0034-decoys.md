# 0034: Decoys and honeytokens

| Status | Date | PR | Release |
|---|---|---|---|
| draft | 2026-11-06 | #N | |

> Trap paths that dvarapala answers itself and never proxies, fake
> credentials in those answers that identify the client when they come
> back, and an optional lure that only an agent which reads and acts on
> responses follows. A hit marks the client for a TTL, across replicas,
> with the RFC 0031 actions and `observe` first.

## Problem

Agentic attack tools (open-source pentest frameworks that drive an LLM)
enumerate a site breadth first, read every response, act on what they
read, and harvest any credential they find to try it later. They run at
machine speed but not at flood rates: a few requests per second, rarely
the same path twice.

What dvarapala has today scores this traffic but never decides on it:

- The rate limit (RFC 0001), heavy hitters and the attack state (RFC
  0002) catch volume. An agent at 2 requests per second is far under any
  limit a real site can set.
- Online features 2 and 3 (inter-arrival mean and variance), 6
  (distinct paths) and 7 (4xx share) describe this client well, but they
  feed a `[ml]` score, and a curious crawler or a QA script looks the
  same.
- JA4 rules (RFC 0012) catch a TLS stack, not a behavior: agents use
  common HTTP libraries or a real browser.
- LLM labels (RFC 0023) are never verdicts, by design.
- A route `deny` (RFC 0013) can refuse `/.env`, but the refusal ends
  with the request: the same client goes on to the next path.

One request that no legitimate client sends is a near-certain signal. A
browser never asks for `/.git/config`. A real user never sends an API
key that the site only ever printed inside a fake `.env`. That signal is
free to collect at the gateway and today it is thrown away.

## Proposal

- **Trap paths.** `[[decoy.trap]]` entries name a path (prefix, or
  exact with a leading `=`, matched on the raw path as routes are) and a
  response: status, content type and a body template from a file. In
  `enforce` dvarapala answers the request itself. The upstream never
  sees it. A hit marks the client (class `scanner`).
- **Honeytokens.** A body template can hold `{token}`. Each answer puts
  a fresh token there: the trap's index, the client key and the issue
  time, sealed with ChaCha20-Poly1305 under a key derived from
  `decoy.secret`. No server state, as the challenge pass (RFC 0012). A
  later request that carries a valid token in a configured header (or,
  opt-in, the query string) marks its client at the highest class
  (`token`), and the log links it to the original hit: the client key
  and the time inside the token.
- **Agent lure (optional, off by default).** A template can hold
  `{lure}`: the path of a second trap, derived from the secret. The
  operator's template puts it where a reader finds it (a comment in a
  fake `.env`, a `Location` in a fake config). Wordlist scanners do not
  parse bodies and do not request it. A client that does read the body
  and act on it hits the lure, and its mark becomes class `agent`. A
  human pentester reading the body also gets `agent`: the class means
  "read the decoy and acted on it", which is what separates an agent
  from a scanner.
- **Marks.** A mark is (client key, class, expiry). Classes rank
  `scanner` < `agent` < `token`. A new hit keeps the higher class and the
  later expiry (`decoy.mark_ttl`, default `1h`). The table is bounded
  (`decoy.max_marks`).
- **Actions on a marked client** use the RFC 0031 vocabulary, one
  `decoy.action` for every class:
  - `"deny"`: `403` and the connection closed, before any bucket.
  - `"challenge"`: the proof-of-work challenge until the client holds a
    pass (needs `challenge.mode` other than `"off"`, as
    `fingerprint.challenge`).
  - `"tag"`: no verdict. The class goes to the access log, the LLM
    sample (RFC 0023) and, when `decoy.header` is set, to the upstream
    in that header (the client's own copy removed first), so the
    application can choose its own answer.
- **`observe` first.** `decoy.mode = "observe"` (default) matches traps
  and tokens, records marks and counts what the action will do, but
  proxies every request as today. No token is issued in `observe`,
  because no trap is answered. The upstream's status on a trap path is
  recorded: anything other than `404`, `410` or `403` logs
  `msg="decoy shadows upstream"` and counts
  `dvarapala_decoy_shadowed_total{trap}`. That is the check that a trap
  does not hide a real route, before `enforce`.
- **Order in the rate limiter.** Mark and token checks run with the
  manual block and intel checks, before the buckets. A trap path is
  matched (and the client marked) before the buckets too, but answered
  only if the client's bucket allows the request: a flood of trap hits
  gets `429` like any other flood, and costs a mark update each.
- **Shared marks.** With `[store]` set (RFC 0010), marks go out and come
  back in the sync round as a new mark kind, `decoy`, keyed by class and
  client key, with their expiry. Redis gets a `decoy` sorted set next to
  `heavy` and `pauses`. PostgreSQL uses the existing `marks` table with
  `kind = 'decoy'`, so there is no migration. The per kind cap of
  `store.max_list` applies. A lost store falls back to local marks, as
  for heavy hitters.
- **XDP, opt-in.** `decoy.xdp = true`, with `action = "deny"` and
  `mode = "enforce"`, pushes marked clients into the XDP block list for
  `xdp.block_ttl`, through the same sink heavy hitters use. Only the peer
  address of a completed TCP handshake or QUIC validation goes there.
  An address carried by the PROXY protocol (RFC 0030) never does.
- **LLM labels and replay.** `decoy` becomes an RFC 0023 trigger
  (`[[ml.llm.triggers]] on = "decoy"`), sampled with the class.
  `dvarapala replay` answers traps, verifies tokens in the recorded
  `headers` (with the same `decoy.secret`, a production token verifies)
  and reports the decoy series.
- **SDKs (RFC 0028).** Trap matching, token scanning and verification,
  template rendering and the mark table live in `engine`, so
  `dv_check_request` gets them: a trap returns a new verdict, `decoy`,
  and `dv_decoy_response` writes the status, headers and body for the
  application to send. Marked clients get the existing `drop` and
  `challenge` verdicts. The Go, Python and JavaScript middleware serve
  the decoy response.

### Not fingerprintable from the repo

The repository is public, so nothing a scanner can learn from it can
identify a dvarapala decoy:

- No default trap paths. `[decoy]` without traps is a config error, and
  the section is absent by default. A starter list is in
  `examples/decoy.toml`, with paths that scanners already probe on any
  site, so the list itself tells a reader nothing.
- Every per-deployment value comes from `decoy.secret` (at least 32
  bytes, required, redacted in `GET /config` and the console as
  `challenge.secret` is, RFC 0021) through HKDF-SHA256 with a label per
  use:
  - the token sealing key.
  - the token prefix when `decoy.token.prefix` is empty: six lowercase
    letters and `_`, in the style of `ghp_`.
  - the lure path when `decoy.lure.path` is empty.
  - `{fake:<name>}` values in templates (a database password, a host
    name, an account id), stable per deployment, trap and name, so two
    fetches of the same trap agree and two deployments that copied the
    same example template do not.
- The token is sealed, not only signed. A signed token with a readable
  payload will show the agent its own address once decoded, which is a
  fingerprint.
- A trap answer carries only the template's body, `content-type`,
  `content-length`, `date` and the headers in `decoy.headers` (for
  example the upstream's `server`). dvarapala adds no header of its own.
- The examples' templates are starting points and say so. Their
  `{fake:...}` fields already differ per secret.

### Guarding real routes

A trap that matches a real upstream path answers real users with a fake
body and marks them. Four guards, in the order an operator meets them:

1. Exact paths by default in the examples (`=/.env`), prefixes only where
   the whole subtree is never real (`/.git/`).
2. At start and on reload, a trap whose path overlaps a `[[routes]]`
   `path` condition (the operator described that path as real) is a
   warning naming both: `msg="decoy overlaps route" trap=<n> route=<r>`.
3. `observe` proxies trap paths and records the upstream's answer, so a
   week in `observe` with `dvarapala_decoy_shadowed_total` at zero shows
   the upstream has nothing there.
4. `decoy.exempt` (CIDRs) never hits a trap or a mark: internal
   scanners, uptime checks, the operator's own pentest range.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/engine/src/decoy/trap.rs` | the trap set: exact paths in a hash set, prefixes sorted longest first, and `exempt` |
| `crates/engine/src/decoy/token.rs` | token seal and open (ring ChaCha20-Poly1305, nonce from an HMAC of the plaintext so the engine needs no random source), the base64url body |
| `crates/engine/src/decoy/scan.rs` | find token candidates by prefix in the configured header values and the query, bounded in bytes and candidates |
| `crates/engine/src/decoy/template.rs` | parse a body template once into literal parts and `{token}`, `{lure}`, `{fake:<name>}` slots. Render with the per-hit token |
| `crates/engine/src/decoy/marks.rs` | `Marks`: the bounded mark table over `Table`, class order, expiry, the batch for the store |
| `crates/engine/src/decoy/keys.rs` | HKDF subkeys, the derived prefix, lure path and fake values |
| `crates/engine/src/cluster.rs` | `Batch.decoys` and `Reply.decoys` |
| `crates/store/src/{redis,postgres,memory}.rs` | the `decoy` mark kind |
| `crates/l7/src/decoy.rs` | in the rate limiter: mark and token checks, the trap answer, the shadow check on upstream responses in `observe`, `decoy.header`, metrics |
| `crates/l7/src/llm/` | the `decoy` trigger |
| `crates/ffi/src/decoy.rs` | the `decoy` verdict of `dv_check_request`, `dv_decoy_response` |
| `sdk/go`, `sdk/python`, `sdk/js` | the middleware serves decoy responses |
| `crates/dvarapala/src/config/decoy.rs` | `[decoy]`, the secret through `view::redact` |
| `fuzz/fuzz_targets/decoy_token.rs`, `fuzz/fuzz_targets/decoy_template.rs` | token scan and open over arbitrary headers and queries. The template parser over arbitrary bytes. Rows in `fuzz/select.sh` (`engine`) |
| `examples/decoy.toml`, `examples/decoy/` | a starter config and templates. `CONFIG.md` and `site/docs/protection.md` in the implementation |

`engine` gains `ring` (`default-features = false`), already in every
build through rustls and in `l7` for the challenge pass. The challenge
pass stays where it is.

### Configuration

| Key | Default | |
|---|---|---|
| `decoy` | absent | The section turns the layer on. Absent, nothing is matched |
| `decoy.mode` | `"observe"` | `"enforce"` answers traps and applies the action |
| `decoy.secret` | required | At least 32 bytes. Redacted in `GET /config`. Changing it voids every issued token and moves derived paths |
| `decoy.action` | `"challenge"` | `"deny"`, `"challenge"` or `"tag"`, for marked clients |
| `decoy.mark_ttl` | `"1h"` | How long a mark lasts after its last hit, `1m` to `7d` |
| `decoy.max_marks` | `65536` | Marks held at most. When full, the lowest class expiring first is evicted |
| `decoy.exempt` | `[]` | CIDRs never marked or trapped |
| `decoy.headers` | `{}` | Extra response headers on trap answers, name to value |
| `decoy.header` | `""` | Upstream header with the class for `tag`. Empty sends none |
| `decoy.xdp` | `false` | Push `deny` marks to the XDP block list |
| `decoy.trap[].name` | required | Label in metrics and logs, unique |
| `decoy.trap[].path` | required | Prefix, or exact with a leading `=` |
| `decoy.trap[].methods` | `["GET", "HEAD"]` | Methods that hit the trap |
| `decoy.trap[].status` | `200` | Status of the answer |
| `decoy.trap[].content_type` | `"text/plain"` | |
| `decoy.trap[].body` | required | Template file, at most 64 KiB |
| `decoy.token.prefix` | `""` | Prefix before the token body. Empty derives one from the secret |
| `decoy.token.ttl` | `"90d"` | A token older than this is counted `expired` and does not mark |
| `decoy.token.headers` | `["authorization", "x-api-key"]` | Request headers scanned for tokens |
| `decoy.token.query` | `false` | Also scan the query string (see Security) |
| `decoy.lure.enabled` | `false` | Serve the lure trap and fill `{lure}` |
| `decoy.lure.path` | `""` | The lure path. Empty derives one from the secret |
| `decoy.lure.body` | required with `enabled` | Template of the lure answer |

Every key reloads (`SIGHUP`, `POST /reload`, `config_watch`). Marks
survive a reload. A reload that changes `decoy.secret` keeps the marks
but voids the tokens.

### Logs and metrics

| | |
|---|---|
| `dvarapala_decoy_hits_total{trap,class,mode}` | trap and lure hits, `trap="token"` for token uses |
| `dvarapala_decoy_tokens_total{result}` | `issued`, `valid`, `linked` (a valid token from a key other than the one it was issued to), `expired`, `invalid` (prefix matched, did not open) |
| `dvarapala_decoy_marks{class}` | marks in force |
| `dvarapala_decoy_marks_evicted_total` | marks evicted by `max_marks` |
| `dvarapala_decoy_actions_total{action,mode}` | requests from marked clients, what was done or will be |
| `dvarapala_decoy_shadowed_total{trap}` | upstream answered a trap path with other than `404`, `410` or `403` in `observe` |
| `dvarapala_requests_total{verdict,scope="decoy"}` | existing metric, the decoy verdicts |
| `msg="decoy hit" client=<k> trap=<n> class=<c> mode=<m>` | each hit, at info |
| `msg="decoy token used" client=<k> origin=<k> trap=<n> issued=<t>` | each valid token, at warn. `origin` is the key the token was issued to |
| `msg="decoy shadows upstream" trap=<n> status=<s>` | at warn, once per trap per minute |
| `msg="decoy overlaps route" trap=<n> route=<r>` | at warn, on start and reload |
| access log `decoy=<class>` | for marked clients |

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | traps `=/.env` and `/.git/` | match `/.env`, `/.env.bak`, `/.git/config`, `/.GIT/config`, `/%2egit/config` | the first and third match, the rest do not | unit (`engine::decoy::trap`) |
| 2 | a trap and `exempt = ["192.0.2.0/24"]` | a hit from `192.0.2.7` | no match, no mark | unit (`engine::decoy::trap`) |
| 3 | a token sealed for one key at `t` | opened with the same secret, with another secret, with one byte changed, truncated | the trap, key and `t` back. Then `invalid` three times | unit (`engine::decoy::token`) |
| 4 | a token issued `ttl` plus one second ago | opened | `expired`, no mark | unit (`engine::decoy::token`) |
| 5 | two secrets | derive the prefix, the lure path and `{fake:db_password}` | stable per secret, different between them. The prefix is six lowercase letters and `_` | unit (`engine::decoy::keys`) |
| 6 | a token body base64url-decoded | inspected | no byte sequence equal to the client address or the issue time | unit (`engine::decoy::token`) |
| 7 | a template with `{token}`, `{lure}`, `{fake:host}` and a lone `{` | parse and render twice for two clients | literals kept, `{` kept as text, the fake value equal in both, the tokens different | unit (`engine::decoy::template`) |
| 8 | a template over 64 KiB, or with an unknown `{slot}` | load | refused naming the trap and the slot | unit (`config`) |
| 9 | a header with 100 prefix matches | scan | at most 4 candidates opened, `invalid` counted once per candidate | unit (`engine::decoy::scan`) |
| 10 | marks `scanner` then `token` then `scanner` for one key | read | class `token`, the latest expiry | unit (`engine::decoy::marks`) |
| 11 | `max_marks = 2` holding a `token` and a `scanner` mark | a third key is marked `scanner` | the old `scanner` mark evicted, `marks_evicted_total` 1 | unit (`engine::decoy::marks`) |
| 12 | arbitrary header values and query strings | scan and open | no panic, no allocation over the caps | fuzz (`decoy_token`) |
| 13 | arbitrary template bytes | parse | no panic, an error or a template | fuzz (`decoy_template`) |
| 14 | `enforce`, trap `=/.env` with `{token}` | `GET /.env` | the template with a token, the inner service not called, no header beyond the listed ones, `hits{class="scanner"}` 1 | integration (`l7/tests`) |
| 15 | the same, `observe` | `GET /.env`, the inner service answers `404` | the inner service's `404`, no token, a mark, `shadowed_total` 0 | integration (`l7/tests`) |
| 16 | `observe`, the inner service answers `200` on `/.env` | `GET /.env` | the `200` passes through, `shadowed_total{trap}` 1, one warn log | integration (`l7/tests`) |
| 17 | `enforce`, `action = "deny"`, a marked client | `GET /` | `403`, connection closed, `actions{action="deny",mode="enforce"}` 1 | integration (`l7/tests`) |
| 18 | `action = "challenge"`, a marked client with `Accept: text/html` | `GET /`, then with a valid pass | the challenge page, then the inner service | integration (`l7/tests`) |
| 19 | `action = "tag"`, `header = "x-decoy"`, a marked client sending its own `x-decoy` | `GET /` | the inner service sees one `x-decoy: scanner` | integration (`l7/tests`) |
| 20 | a token issued to `192.0.2.7` | `GET /api` from `198.51.100.9` with `Authorization: Bearer <token>` | `198.51.100.9` marked `token`, `tokens{result="linked"}` 1, the log has `origin` | integration (`l7/tests`) |
| 21 | the same token in the query, `token.query = false`, then `true` | `GET /api?key=<token>` | not marked, then marked | integration (`l7/tests`) |
| 22 | lure on, a trap answered with `{lure}` | the client requests the lure path | mark class `agent`, `hits{class="agent"}` 1 | integration (`l7/tests`) |
| 23 | a client over its bucket | `GET /.env` in `enforce` | `429`, marked, no token issued | integration (`l7/tests`) |
| 24 | a trap overlapping a `[[routes]]` path | start | warn log naming both, starts | unit (`config`) |
| 25 | `[decoy]` without traps, a secret under 32 bytes, or `challenge` with `challenge.mode = "off"` | start or reload | refused naming the key | unit (`config`) |
| 26 | `decoy.secret` set | `GET /config` | `"<redacted>"`, the value absent from the body. The redaction list test names the field | integration (`dvarapala/tests`) |
| 27 | two replicas on one store, Redis then PostgreSQL | a trap hit on the first | the second applies the action within two sync rounds | integration (`store/tests`) |
| 28 | the store goes away | a trap hit | the local mark applies, the rest as RFC 0010 | integration (`store/tests`) |
| 29 | `xdp = true`, `deny`, `enforce`, a hit from a PROXY protocol address | hit | the block sink gets nothing. A direct peer is pushed | unit (`l7`) |
| 30 | a trigger `on = "decoy"` with rate 1 | a trap hit | one LLM sample with the class | integration (`l7/tests`) |
| 31 | a replay log with a trap hit and a later line carrying the token | `dvarapala replay` with the issuing secret | `decoy_hits_total` and `tokens{result="valid"}` in the report | integration (`dvarapala/tests`) |
| 32 | `dv_check_request` on a trap path, then `dv_decoy_response` | the C ABI, and each SDK's middleware | the `decoy` verdict, the rendered answer served | integration (`ffi`, SDK jobs) |
| 33 | `examples/decoy.toml` | `example_configs_load` | loads | integration |
| 34 | a request with no trap, no mark and two scanned headers | criterion | the decoy checks add under 1 µs. A trap answer with a token under 5 µs | bench (`engine/benches/decoy.rs`) |

## Alternatives

| Option | Why not |
|---|---|
| A separate honeypot service | it sees only traffic sent to it, not the agents probing the real site, and its findings reach the gateway only through an integration that does not exist. The trap has to be on the path the agent already walks |
| WAF (Coraza) rules for trap paths | the WAF is an optional sidecar that inspects after the limits, one SPOP round trip per request. A rule can deny one request but cannot mark a client for a TTL across replicas, issue a token or follow a lure. Rules in the repo will also be a fingerprint |
| Only features 6 and 7 plus LLM labels | they score and label, and RFC 0023 keeps labels out of verdicts on purpose. A low-rate agent's distinct paths and 4xx share overlap a crawler's, so no threshold is near-certain |
| A route `deny` on the same paths | refuses one request and forgets the client. Kept as the zero-cost option for operators who want no state |
| `deceive`: plausible fake answers to every request of a marked client | to fool an agent the fakes must be convincing for any path, which only the application can produce. A NATed real user who shares a marked address will get a broken site without an error, which is worse than a `403` or a challenge. `tag` with `decoy.header` gives the application the class so it can deceive where it knows how. Trap answers already are the deception for the paths dvarapala owns |
| Tokens with server-side state (a random id per hit) | a table an attacker fills by hitting traps. Sealed tokens need none |
| HMAC-signed token with a readable payload | decoding it shows the agent its own address and the issue time, which identifies the decoy |
| Built-in default trap paths | defaults are a fingerprint, and a default can shadow a real route on someone's site |
| A random secret per process, as `challenge.secret` allows | tokens will not verify after a restart or on another replica, and derived paths will move on each restart. A required secret avoids a silent half-working mode |
| One action per class | more keys for a signal that is near-certain in every class. Can come later if `scanner` marks prove noisy |

## Security and resource limits

- **Attacker input.** The token scan reads attacker-controlled header
  values and the query: at most the first 8 KiB of each scanned header
  and of the query, at most 4 candidates opened per request (each one
  ChaCha20-Poly1305 open of 42 bytes, about 1 µs). The parser is
  bounds-checked and fuzzed (case 12). Templates come from the operator
  but are parsed once at load with a 64 KiB cap and fuzzed (case 13).
- **Mark table.** `max_marks` entries of about 48 bytes (key, class,
  expiry, table links): 3 MB at the default. Eviction takes the lowest
  class expiring soonest, so a scanner flood cannot push out `token`
  marks. In the store, the per kind `max_list` cap and the longest-lived
  rule (#337) bound what each replica reads back.
- **Spoofed addresses.** A trap hit is an HTTP request, so the address
  completed a TCP handshake or a QUIC validation, or was carried by a
  trusted proxy (`trusted_proxies`, RFC 0030). A spoofed source cannot
  mark a victim. XDP gets only direct peers, as heavy hitters.
- **Shared addresses.** A mark is per client key: an IPv4 address or an
  IPv6 /64. Behind a CGNAT or a corporate proxy, one infected device
  marks everyone behind it. That is why `challenge` is the default
  action (real users pass it), `mark_ttl` is short, and `exempt` exists.
- **Marking someone else with a token.** Anyone holding a token can mark
  the addresses they send it from, which they can do by hitting a trap
  anyway. The risk is a third party making a victim's browser send it:
  a link or an `<img>` with the token in the query string. Browsers do
  not send `Authorization` or custom headers cross-site without a CORS
  preflight that the site does not grant, so the default scans headers
  only, and `token.query` is opt-in. Tokens are never set as cookies.
- **Cost during a flood.** Trap matching is a hash lookup and a short
  prefix scan. A trap answer is a template copy plus one seal, cheaper
  than proxying, and it is served only within the client's bucket, after
  heavy hitter drops. Bytes out per client are bounded by the bucket
  rate times 64 KiB.
- **Residual fingerprints.** A trap answer comes from the gateway, so
  its timing differs from the upstream's, and the token body has a fixed
  length (56 base64url characters). The operator's templates and
  `decoy.headers` control everything else. An agent that suspects a
  decoy can at best avoid one path. It still cannot tell which of the
  other paths are traps.
- **The lure** points to a path on the same host and asks nothing else
  of the reader. dvarapala never writes text that tells an agent to act
  outside the site.
- **Fail closed** on the protection path: a template that fails to load
  refuses the start or the reload, and the config in force stays. A
  token that does not open never marks. A lost store fails open to
  local marks, as RFC 0010 says.

## Rollout

- **Rollout:** the next minor after acceptance. The `[decoy]` section is
  absent by default, so nothing changes on upgrade. Turned on, it starts
  in `observe`: run it until `dvarapala_decoy_shadowed_total` stays at
  zero, then `enforce`. Start with `action = "tag"` or `"challenge"`.
- **Off switch:** `mode = "observe"` and reload stops all answers and
  actions while counting continues. Removing the section and reloading
  turns it off. Marks expire on their own within `mark_ttl`. A restart
  without a store clears them.

## Out of scope

For later RFCs:

- Header consistency: a browser `User-Agent` without `sec-fetch-*`
  headers, or a JA4 that disagrees with the `User-Agent`.
- `DvarapalaPolicy` CRD fields for the operator (RFC 0019).
- A console page for traps, marks and token links (RFC 0018).
- Per-class actions, and a route matcher on the mark class.
- Lures in HTML responses of the real upstream (injecting into proxied
  bodies).
