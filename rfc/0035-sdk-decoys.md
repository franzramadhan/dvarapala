# 0035: SDK parity: decoys and honeytokens

| Status | Date | PR | Release |
|---|---|---|---|
| accepted | 2026-11-06 | #340 | |

> Bring the RFC 0034 decoys into the C ABI and the Go, Python and
> JavaScript SDKs: trap paths answered by the middleware, honeytokens
> found in request headers, marks per process. The ABI only gains
> functions and one verdict value. Existing calls keep their behavior.

## Problem

RFC 0034 puts trap matching, token sealing and scanning, template
rendering and the mark table in `engine`, with no I/O, so the C ABI can
reach them. It leaves the ABI out: a service that embeds the SDK instead
of running the gateway gets no traps and no tokens, and `dv_config_set`
refuses every `decoy.*` key as unknown.

An embedding application is where agents land when there is no gateway
in front: an API on a serverless platform, a Python service behind a
managed load balancer. It is also the one place that knows its real
routes, which is the main risk of a trap.

Three parts of the ABI do not fit RFC 0034 as it stands:

- `DvRequestVerdict` and `DvStats` are allocated by the caller, so a new
  field can let the library write past an old caller's struct (RFC
  0028 kept `DvStats` unchanged for this reason).
- `DvRequest` carries the path without the query, so the query string
  cannot be scanned for tokens.
- There is no challenge in process (RFC 0028 refuses route `challenge`),
  so the RFC 0034 default action, `challenge`, has nothing to run.

## Proposal

- **Config.** `dv_config_set` accepts the RFC 0034 keys, with these
  differences:
  - `decoy.traps` is a JSON array, as `routes` (RFC 0028), with the
    `CONFIG.md` field names. `body` is the template text itself, not a
    file: the library reads no files. At most 64 KiB, UTF-8, no NUL.
    `decoy.lure.body` is text the same way.
  - `decoy.headers` is a JSON object, name to value.
  - `challenge.secret` becomes a key of the ABI. It is used only for the
    decoy keys (HKDF label `decoy`, as RFC 0034), so an app that shares
    the gateway's secret gets tokens that verify on both.
  - `decoy.action` defaults to `"tag"` in process, not `"challenge"`:
    no challenge runs in the app, and `tag` changes no answer, so the
    app sees its marks before it chooses `"deny"`. An explicit
    `"challenge"` is refused with a hint, never mapped to another action.
  - `decoy.token.query` is refused: `DvRequest` has no query.
  - `decoy.header` is refused: there is no upstream. `dv_decoy_mark`
    gives the class to the app instead.
- **Trap answers.** In `enforce`, `dv_check_request` on a trap path,
  within the client's bucket, returns a new verdict kind, `DV_DECOY`
  (3). `dv_decoy_response` then renders the answer for that request,
  with a fresh token, into a `DvDecoy` the caller passes. The middleware
  sends it and never calls the handler.
  `DV_DECOY` is returned only when `decoy.traps` is set, so an
  application built against an older header never sees it.
- **Marked clients.** `deny` gives `DV_DROP` from `dv_check_request`
  and `dv_check`, before any bucket, as a manual block does. `tag` gives
  `DV_ALLOW`. `dv_decoy_mark(ip, xff)` returns the mark as JSON (class,
  expiry, and for a linked token the origin key and issue time) or
  `NULL`, so the app can log it, label its metrics or answer as it
  likes.
- **Tokens.** `dv_route_headers` also lists `decoy.token.headers`, so
  the middleware passes them, and `dv_check_request` scans them as RFC
  0034 does. With no decoy keys the list is as before.
- **Observe.** In `observe`, trap paths reach the handler as today. The
  middleware reports the handler's status with `dv_decoy_observed`, which
  counts `shadowed` as RFC 0034 does when the status is not `404`, `410`
  or `403`. It is a no-op for a path that is not a trap.
  `dv_decoy_mode` tells the middleware whether to call it: `0` off, `1`
  observe, `2` enforce.
- **Counters.** `dv_decoy_stats` returns the RFC 0034 counters as JSON.
  The SDKs have no metrics exporter (RFC 0028). The app exports them.
- **Reload.** `dv_guard_reload` keeps the marks, as the gateway does. A
  new `challenge.secret` voids the tokens and moves the derived prefix
  and lure path.
- **One guard per process.** Marks live in the guard, not in a store:
  a client marked by one worker is not marked by the next. The SDK docs
  say so next to the middleware, as for the buckets in RFC 0028. Sharing
  marks waits for the SDK store RFC.
- **Middleware.** Go `Middleware`, Python `ASGIMiddleware` and
  `WSGIMiddleware`, and JavaScript `middleware()` handle `DV_DECOY` and
  `dv_decoy_observed` with no code change in the app. Each language also
  gets `decoyMark(ip, xff)` and `decoyStats()` in its own naming.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/ffi/src/decoy.rs` | `dv_decoy_response`, `dv_decoy_mark`, `dv_decoy_observed`, `dv_decoy_mode`, `dv_decoy_stats` |
| `crates/ffi/src/request.rs` | the `DV_DECOY` verdict, the token scan, the decoy headers in `dv_route_headers` |
| `crates/ffi/src/guard.rs` | `deny` marks in `dv_check` |
| `crates/ffi/src/config.rs`, `crates/ffi/src/lists.rs` | the `decoy.*` keys, `decoy.traps` as JSON, `challenge.secret` |
| `crates/ffi/src/state.rs` | the marks in the guard's one lock, kept on reload |
| `crates/ffi/include/dvarapala.h` | regenerated by `cbindgen` |
| `crates/node` | the N-API side of the new calls |
| `sdk/go`, `sdk/python`, `sdk/js` | config for the new keys, the middleware, `decoyMark` and `decoyStats` |
| `fuzz/fuzz_targets/ffi_check_request.rs` | extended with decoy keys set, so token headers reach the scan through the ABI |

### C ABI additions

```c
#define DV_DECOY 3          /* dv_check_request only: answer with dv_decoy_response */

typedef struct DvDecoy {
  int32_t status;
  const char *content_type; /* valid while the guard lives */
  const char *headers;      /* "name: value\n" lines, valid while the guard lives */
  char *body;               /* free with dv_string_free */
  size_t body_len;
} DvDecoy;

int32_t dv_decoy_response(const DvGuard *g, const DvRequest *r, DvDecoy *out); /* DV_E_NOT_FOUND: not a trap */
char *dv_decoy_mark(const DvGuard *g, const char *ip, const char *xff);       /* JSON or NULL, free with dv_string_free */
int32_t dv_decoy_observed(const DvGuard *g, const DvRequest *r, int32_t status);
int32_t dv_decoy_mode(const DvGuard *g);                                     /* 0 off, 1 observe, 2 enforce */
char *dv_decoy_stats(const DvGuard *g);                                      /* JSON, free with dv_string_free */
```

`dv_decoy_response` matches the trap again. A reload between
`dv_check_request` and it can remove the trap: it then returns
`DV_E_NOT_FOUND`, and the middleware answers `404`. `headers`
and `content_type` point into the guard's config and stay valid until
the guard is freed, as `DvRequestVerdict.route` does: a reload keeps the
old strings alive until `dv_guard_free`.

`dv_decoy_mark` JSON:
`{"class":"token","expires_ms":3600000,"origin":"192.0.2.7","issued":1793923200}`.
`origin` and `issued` are present only for a linked token.

### Configuration

No new keys beyond RFC 0034. In process:

| Key | Default | In process |
|---|---|---|
| `challenge.secret` | `""` | Required with any `decoy.*` key, at least 32 bytes. Used for decoys only |
| `decoy.mode` | `"observe"` | as RFC 0034 |
| `decoy.action` | `"tag"` | `"deny"` or `"tag"`. `"challenge"` refused |
| `decoy.traps` | `[]` | JSON array of `[[decoy.trap]]` tables. `body` is the template text |
| `decoy.headers` | `{}` | JSON object |
| `decoy.lure.body` | required with `enabled` | the template text |
| `decoy.token.query`, `decoy.header` | refused | no query in `DvRequest`, no upstream |
| other `decoy.*` keys | as RFC 0034 | |

### Logs and metrics

None new in the library: it has no logger or exporter.
`dv_decoy_stats` gives the RFC 0034 counters with the same names, minus
the `dvarapala_` prefix, so an app exporting them can keep the
gateway's dashboards:

```json
{"hits":[{"trap":"env","class":"scanner","mode":"enforce","count":3}],
 "tokens":{"issued":3,"valid":1,"linked":1,"expired":0,"invalid":0},
 "marks":{"scanner":2,"agent":0,"token":1},"marks_evicted":0,
 "actions":[{"action":"deny","mode":"enforce","count":7}],
 "shadowed":[]}
```

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | `decoy.traps` with `body` text, `decoy.action = "deny"`, `challenge.secret` set | `dv_config_set`, `dv_guard_new` | the guard starts, `dv_decoy_mode` is `1` | unit (`ffi`) |
| 2 | `decoy.action = "challenge"`, `decoy.token.query = true`, `decoy.header`, a decoy key without `challenge.secret`, a `body` with NUL or over 64 KiB | `dv_guard_new` | refused naming the key, `DV_E_INVALID` | unit (`ffi`) |
| 3 | no decoy keys | `dv_route_headers`, `dv_check_request` on `/.env` | the route headers only, `DV_ALLOW` (unchanged) | unit (`ffi`) |
| 4 | `enforce`, trap `=/.env` with `{token}` | `dv_check_request` on `GET /.env`, then `dv_decoy_response` | `DV_DECOY`, then the status, content type, listed headers and a body with a token, `tokens.issued` 1 | unit (`ffi`) |
| 5 | the same, a client over its bucket | `dv_check_request` | `DV_THROTTLE`, marked, no token | unit (`ffi`) |
| 6 | a request that is not a trap, or a trap removed by `dv_guard_reload` in between | `dv_decoy_response` | `DV_E_NOT_FOUND` | unit (`ffi`) |
| 7 | `deny`, a marked client | `dv_check` and `dv_check_request` | `DV_DROP` from both | unit (`ffi`) |
| 8 | no `decoy.action` (default `tag`), a marked client | `dv_check_request`, `dv_decoy_mark` | `DV_ALLOW`, the JSON with its class | unit (`ffi`) |
| 9 | a token issued to `192.0.2.7` | `dv_check_request` from `198.51.100.9` with it in `authorization` | marked `token`, `dv_decoy_mark` has `origin` `192.0.2.7`, `tokens.linked` 1 | unit (`ffi`) |
| 10 | a token issued by the gateway with the same `challenge.secret` | `dv_check_request` with it | `tokens.valid` 1 | integration (`ffi`, engine helper) |
| 11 | `observe`, trap `=/.env` | `dv_check_request`, then `dv_decoy_observed` with `200`, then with `404` | `DV_ALLOW`, marked, `shadowed` 1 after the first, unchanged after the second | unit (`ffi`) |
| 12 | marks for two clients | `dv_guard_reload` with the same keys, then with a new `challenge.secret` | marks kept both times. The old token is `invalid` after the second | unit (`ffi`) |
| 13 | arbitrary bytes in method, path and headers with decoy keys set | `ffi_check_request` | no panic, no allocation over the caps | fuzz (`ffi_check_request`) |
| 14 | each SDK's middleware, `enforce`, a test app with a handler that records calls | `GET /.env` | the decoy answer, the handler not called | integration (`go`, `python`, `js` jobs) |
| 15 | each SDK's middleware, `observe`, the handler answering `200` on `/.env` | `GET /.env` | the handler's `200`, `decoyStats().shadowed` 1 | integration (SDK jobs) |
| 16 | each SDK, `deny`, a marked client | `GET /` | `403` with the connection closed, as for `DV_DROP` today | integration (SDK jobs) |
| 17 | the header from `cbindgen` | the stale header check | matches | CI (`cbindgen`) |

## Alternatives

| Option | Why not |
|---|---|
| Put the decoy in `DvRequestVerdict` | the caller allocates it: a new field breaks every binding built against the old header |
| A `query` field in `DvRequest` | the same struct problem. A later `dv_check_request` version can add the query for all features at once when a second need appears |
| Map `challenge` to `deny` or `tag` in process | a silent change of the operator's action. Refusing names the gap |
| A challenge in process | needs the page, the verify endpoint and the pass in every middleware, for a feature RFC 0028 left out on purpose. A separate RFC if the SDKs need challenges |
| Templates as file paths | the library reads no files today, and each language reads a file in one line |
| Render the answer inside `dv_check_request` | every allowed request would pay for an output buffer, and the body would need a lifetime tied to the verdict |
| Keep SDKs without decoys | the embedding app is where an agent lands when there is no gateway, and the engine code is already reachable |

## Security and resource limits

- Attacker input reaches the token scan through the headers that
  `dv_route_headers` lists, each already capped at 8 KiB by the ABI, and
  the RFC 0034 caps on candidates apply. Fuzzed through the ABI (case
  13) and in `engine` (RFC 0034).
- `dv_decoy_response` allocates the rendered body, at most the 64 KiB
  template plus the token per slot. The middleware frees it after the
  write. A caller that never frees it leaks per call, as for
  `dv_blocks`.
- Marks are bounded by `decoy.max_marks` per guard, so per process.
- `challenge.secret` set through `dv_config_set` is held in the guard
  and never returned by any call. `dv_decoy_stats` and `dv_decoy_mark`
  carry no secret.
- `dv_decoy_observed` is called by the app with its own status, so a
  buggy app can only miscount `shadowed`.

## Rollout

- **Rollout:** with or after the RFC 0034 release. No decoy keys, no
  change: `dv_route_headers`, `dv_check` and `dv_check_request` behave
  as before, and `DV_DECOY` is never returned. The SDK packages (RFC
  0026, 0027) ship the new calls with the release.
- **Off switch:** remove the `decoy.*` keys and `dv_guard_reload`, or
  set `decoy.mode = "observe"`.

## Out of scope

- Sharing marks between processes (the SDK store RFC).
- A challenge in process.
- The query string in `DvRequest`.
