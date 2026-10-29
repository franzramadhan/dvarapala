# 0018: Admin web UI with OIDC login

| Status | Date | PR | Release |
|---|---|---|---|
| accepted | 2026-10-29 | #139 | |

> An optional web console on the admin listener (`admin.ui_enabled`, off
> by default) that shows the gateway's state live and drives the admin
> API (top talkers, blocks, reload), with a login by admin token or by
> OIDC single sign-on, so an operator under attack works from a browser
> instead of composing `curl` calls.

## Problem

The admin API (RFC 0014) gives the levers, but only to someone at a shell:

- Answering "who is attacking and is it working" means polling `GET /top`
  and `GET /status` by hand and diffing JSON in a terminal. There is no
  view of the trend: rates, drops and detection state over the last
  minutes need a Prometheus and a dashboard someone has to build first.
- Blocking a network takes a `curl` with the bearer token, a CIDR
  percent-encoded by hand and a TTL. Under pressure this is where typos
  block the wrong `/16`.
- The bearer token is the only credential. Every operator shares it,
  it sits in shell history, and the log cannot say who blocked or
  reloaded. Teams that already run an identity provider (Keycloak, Dex,
  Okta, Entra ID, Google) cannot use it, nor revoke one person's access
  without rotating the token for all.

## Proposal

- `admin.ui_enabled = true` serves a single page console at `/ui/` on the
  admin listener. Off by default; it needs `admin.listen`. With it off,
  `/ui/` and the session calls answer `404` as today, and nothing below
  changes the admin API for `curl` users.
- The console is a static bundle built once and embedded in the binary:
  no Node at runtime, no CDN, no external font or script. Pages:
  - **Overview**: detection state (`normal`, `attack`, with the time in
    state), clients in the table, blocks in force, and live charts of
    requests per second by verdict over the last
    15 minutes, drawn from `/status` polled every 2 s. The history lives
    in the browser; the gateway keeps no new state for it.
  - **Top talkers**: the heavy hitters of the last window as a sortable
    table with each one's share of traffic; one action blocks a row with
    a TTL picked from presets (10m, 1h, 24h) or typed.
  - **Blocks**: the manual blocks with a live countdown, add (the CIDR is
    validated and its size shown before submit, "this blocks 65 536
    addresses"), remove.
  - **Reload**: runs `POST /reload` and shows the result as two lists,
    applied keys and keys waiting for a restart, or the refusal error.
  - Every destructive action asks for confirmation that names its target.
    Light and dark themes follow the system and can be switched;
    keyboard shortcuts for the frequent paths (`g o`, `g t`, `g b`, `/`
    to filter).
- Two login methods on the login page, either or both:
  - **Admin token**: the operator pastes `admin.token`; the page sends it
    once as `Authorization: Bearer` to `POST /session` and gets a session
    cookie back. The token is never kept in browser storage.
  - **OIDC** (`[admin.oidc]`): "Sign in with <name>" runs the
    authorization code flow with PKCE (`S256`), `state` and `nonce`
    against the configured issuer. The gateway is a confidential client:
    it exchanges the code at the token endpoint over TLS and checks the
    ID token's `iss`, `aud`, `exp`, `iat` and `nonce`, then the access
    rule: the `email` (with `email_verified`) in `allow_emails`, or a
    value of the `groups_claim` in `allow_groups`. No match is a
    `403` page naming the subject, and a log line.
- Sessions: a random 256 bit id in an `HttpOnly`, `SameSite=Lax` cookie
  (`Secure` when `public_url` is `https`), kept in memory, bounded,
  expiring after `session_ttl` and gone on restart. A session carries the
  login method and the subject (the email, the OIDC `sub`, or `token`).
- The existing endpoints accept either the bearer header (unchanged) or a
  session cookie. A call made with the cookie that changes state
  (`POST`, `DELETE`) must also carry `X-Dvarapala-Csrf` with the session's
  CSRF value, which only the console can read (`GET /session`).
- `GET /status` gains `requests`: the totals behind
  `dvarapala_requests_total` summed per `verdict` value (protocol and
  scope folded in), so the console can chart rates from differences. Additive;
  existing fields are unchanged.
- Audit: every state changing call logs who made it (`actor=`), for the
  bearer header too (`actor=token`).

New admin calls:

| Call | Answer |
|---|---|
| `GET /ui/`, `GET /ui/assets/*` | the console; any other path under `/ui/` returns `index.html` so deep links work |
| `POST /session` | with a valid bearer header: sets the session cookie, `204` |
| `GET /session` | the session's `subject`, `method`, `expires_in`, `csrf`; `401` without one |
| `DELETE /session` | logs out: the session is removed, the cookie cleared |
| `GET /session/oidc` | `302` to the issuer's authorization endpoint |
| `GET /session/oidc/callback` | the issuer's redirect: on success sets the cookie and `302` to `/ui/` |
| `GET /session/methods` | unauthenticated: which login methods are on and the OIDC button label, nothing else |

### Frontend

- `ui/` at the repo root: Vite, SolidJS, `@tanstack/solid-router`
  (code based routes, four pages) and `@tanstack/solid-query` (polling,
  caching, retries and mutations with optimistic updates for blocks),
  Tailwind CSS v4. Charts are hand-written SVG (a sparkline and a
  stacked area), no chart library.
- Budget: the gzip compressed bundle (HTML, JS, CSS, icons) at most
  120 KiB; the binary grows by that much at most. CI fails above it.
- Design direction: a dense operations console. One accent colour for
  the detection state (calm in `normal`, an unmistakable change in
  `attack`), tabular numerals, motion only to show change (a counter
  ticking, a row entering the top list), reduced motion respected.
  System font stack, WCAG AA contrast in both themes, every action
  reachable by keyboard.
- The built `ui/dist/` is checked in, like the XDP object, so
  `cargo build` needs no Node. A CI job rebuilds it with the pinned Node
  and fails when the result differs from the checked in copy, then runs
  the UI tests.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/l7/src/session.rs` | `Sessions`: id and CSRF generation, expiry, bound, constant time lookup; no I/O |
| `crates/l7/src/oidc.rs` | authorization URL with PKCE, `state` and `nonce`; callback query parsing; ID token claim checks and the access rule; no I/O, fuzzed |
| `crates/l7/src/admin.rs` | the cookie and the CSRF header as a second credential next to the bearer check |
| `crates/dvarapala/src/admin/ui.rs` | the embedded bundle: path to asset, `Content-Encoding: gzip`, cache and security headers |
| `crates/dvarapala/src/admin/oidc.rs` | discovery and the token exchange over `hyper-rustls`, both bounded |
| `crates/dvarapala/src/admin.rs` | becomes `admin/mod.rs` plus `admin/serve.rs`; routes the new calls |
| `ui/` | the console sources, tests and the built `dist/` |

### Configuration

| Key | Default | |
|---|---|---|
| `admin.ui_enabled` | `false` | serves the console at `/ui/`; needs `admin.listen` |
| `admin.session_ttl` | `"8h"` | lifetime of a console session, at most `"24h"` |
| `admin.max_sessions` | `64` | sessions at most; the oldest is dropped for a new one |
| `admin.public_url` | `""` | the console's origin as the browser sees it, for example `"https://<host>:9091"`; required with OIDC (redirect URI) and sets `Secure` on the cookie when `https` |
| `admin.oidc.issuer` | `""` | issuer URL, `https` only; empty turns OIDC off. Discovery at `<issuer>/.well-known/openid-configuration` |
| `admin.oidc.client_id` | `""` | required with `issuer` |
| `admin.oidc.client_secret` | `""` | required with `issuer`; set it with `DVARAPALA__ADMIN__OIDC__CLIENT_SECRET` |
| `admin.oidc.scopes` | `["openid", "email"]` | scopes asked for; add `"groups"` or the IdP's equivalent when using `allow_groups` |
| `admin.oidc.allow_emails` | `[]` | verified emails allowed in |
| `admin.oidc.allow_groups` | `[]` | groups allowed in |
| `admin.oidc.groups_claim` | `"groups"` | the ID token claim holding the groups |
| `admin.oidc.label` | `"SSO"` | the login button: "Sign in with SSO" |

Validation at start: `ui_enabled` without `listen`, `issuer` without
`ui_enabled`, `client_id`, `client_secret` or an `https` `public_url`
(plain `http` only for a loopback host), or with both `allow_emails` and
`allow_groups` empty, is an error naming the key. An OIDC config that
lets nobody in is refused rather than started.

The token login stays available whenever `ui_enabled` is on; with OIDC
configured, operators who want SSO only keep `admin.token` out of human
hands as today (it stays required for `curl` and scripts).

All `[admin]` keys, these included, need a restart, as in RFC 0014.

### Logs and metrics

| | |
|---|---|
| `msg="admin login"` | `method` (`token`, `oidc`), `subject`, `result` (`ok`, `denied`, `failed` with `error`) |
| `msg="admin action"` | `actor`, `call`, the target (`cidr`, `ttl`) and the answer status; for bearer and cookie calls alike |
| `dvarapala_admin_logins_total{method,result}` | logins by outcome |
| `dvarapala_admin_sessions` | sessions alive |
| `dvarapala_admin_requests_total{endpoint,status}` | existing; gains the `ui`, `session` and `oidc` endpoints |

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | `Sessions` with `max = 2`, `ttl = 1h` | create three, look one up past its expiry | the oldest dropped, the expired one not found | unit (`l7::session`) |
| 2 | a session | look up with its id, a flipped byte, a different length | found, not found, not found; the comparison is constant time | unit (`l7::session`) |
| 3 | an OIDC config | build the authorization URL | `response_type=code`, `code_challenge_method=S256`, the challenge is the SHA-256 of the verifier, fresh `state` and `nonce` each time | unit (`l7::oidc`) |
| 4 | ID token claims | wrong `iss`, wrong `aud`, `exp` past, `nonce` mismatch, `email_verified = false` | each refused with its reason | unit (`l7::oidc`) |
| 5 | `allow_groups = ["sre"]`, `groups_claim = "roles"` | claims with `roles: ["sre"]`, `roles: "sre"`, `roles: ["dev"]`, no claim | allowed, allowed, denied, denied | unit (`l7::oidc`) |
| 6 | a callback | unknown `state`, a `state` used twice, a `state` older than 10 min | `400` each, no session | unit (`l7::oidc`) |
| 7 | arbitrary callback query strings and ID token payloads | parse and check | no panic | fuzz (`oidc_callback`) |
| 8 | `ui_enabled = false` | `GET /ui/`, `POST /session` | `404`, `404`; the bearer calls answer as before | integration (`dvarapala/tests`) |
| 9 | `ui_enabled = true` | `GET /ui/`, `GET /ui/blocks`, an asset | `index.html` twice with the CSP below, the asset gzip encoded with a long cache | integration (`dvarapala/tests`) |
| 10 | the console | `POST /session` with the right token, with a wrong one | `204` and a cookie with `HttpOnly` and `SameSite=Lax`; `401` and no cookie | integration (`dvarapala/tests`) |
| 11 | a session cookie | `GET /status`; `POST /blocks` without the CSRF header, with a wrong one, with the right one | `200`; `403`, `403`, `200` | integration (`dvarapala/tests`) |
| 12 | a logged in session | `DELETE /session`, then `GET /status` with the old cookie | `204`, then `401` | integration (`dvarapala/tests`) |
| 13 | a mock issuer (discovery, token endpoint, no network) | the full code flow with an allowed email | session set, `msg="admin login" method=oidc result=ok`, `302` to `/ui/` | integration (`dvarapala/tests`) |
| 14 | the mock issuer | an email not allowed | `403` page, no cookie, `result=denied` | integration (`dvarapala/tests`) |
| 15 | an OIDC session | `POST /blocks?cidr=192.0.2.0/24` | the block, and `msg="admin action" actor=<email>` | integration (`dvarapala/tests`) |
| 16 | `issuer` set with `allow_emails` and `allow_groups` empty, or an `http` `public_url` on a non-loopback host | start | error naming the key | unit (`config`) |
| 17 | traffic through the proxy | `GET /status` twice | `requests` totals grow by the requests sent, per verdict | integration (`dvarapala/tests`) |
| 18 | the console against a mocked API | render Overview in `attack`, block a top talker, a failed reload | the state shown, the confirmation names the CIDR and the block appears, the error is shown | unit (`ui`, Vitest) |
| 19 | the built bundle | measure | at most 120 KiB gzip; `ui/dist` equals a fresh build | CI (`ui`) |
| 20 | the console | an axe accessibility scan of every page in both themes | no violation | CI (`ui`) |

## Alternatives

| Option | Why not |
|---|---|
| React with TanStack Router and Query | the same TanStack APIs, but about 45 KiB more gzip for React; Solid's adapters keep the console under budget with no loss of features |
| TanStack Start | a server rendering framework; the console is static files served by the Rust binary, there is no JS server to run |
| A separate UI binary or container | a second thing to deploy, version and secure; the console is only useful next to the admin listener it talks to |
| Fetch the bundle from a CDN at runtime | an admin console must work on an isolated management network, and a CDN script is a supply chain path into the control plane |
| Build the UI in `build.rs` | every `cargo build` would need Node and the npm registry, where the checked in XDP object already keeps the build Rust only |
| Keep the token in browser storage and send it on each call | any XSS reads it, and it never expires; the cookie is `HttpOnly` and short lived |
| Verify the ID token signature with a JWT crate (JWKS fetch, RSA and EC) | the token comes straight from the token endpoint over a verified TLS connection, which OIDC Core 3.1.3.7 accepts in place of the signature check; skips a crypto dependency and the key rotation logic. Claims are still checked |
| OIDC with the implicit flow or as a public client in the browser | tokens in the URL and in JS; the code flow with a confidential client keeps them in the gateway |
| Basic auth or local user accounts | a password store to build and protect; teams that need more than the shared token have an IdP |
| SAML | XML signatures, a large attack surface and dependency set; every common IdP speaks OIDC |
| Metrics history kept by the gateway for charts | new state and memory in the binary; the browser keeps 15 minutes, Prometheus keeps the rest |

## Security and resource limits

- Off by default, twice: no admin listener without `admin.listen`, no
  console without `ui_enabled`. With the console off the attack surface
  is RFC 0014's, unchanged.
- The listener stays plain HTTP. On anything but loopback, put a TLS
  terminator in front (or an SSH tunnel) and set an `https`
  `public_url`, which makes the cookie `Secure`. A session cookie over
  plain HTTP on a network leaks like the bearer token does today; OIDC
  refuses a non-loopback `http` `public_url` so the IdP never redirects a
  code over plain HTTP.
- Unauthenticated surface: the bundle (public files), `GET
  /session/methods` (which methods are on, the button label) and the
  OIDC redirect and callback. No state, version, config or IdP detail is
  shown before login.
- Cookies: `HttpOnly`, `SameSite=Lax` (Strict would drop the cookie on
  the redirect back from the IdP), `Path=/`, no `Domain`. Cross-site
  requests cannot make state changing calls: they lack the cookie (Lax)
  and the CSRF header. Same-site pages, for example an app on another
  port of the same host, cannot read the CSRF value: `GET /session`
  answers no CORS headers.
- Every console response carries `Content-Security-Policy: default-src
  'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;
  connect-src 'self'; frame-ancestors 'none'; base-uri 'none';
  form-action 'self'`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`. The console renders API values as text,
  never as HTML.
- OIDC: `state`, `nonce` and the PKCE verifier are 256 bit random, kept
  server side, single use, at most 64 pending and 10 min old. Discovery
  and the token exchange go to `https` only with certificate
  verification, a 5 s timeout and a 64 KiB answer cap. Discovery runs at
  start and on failure again at the next login, never on an attacker's
  request rate: one login is in flight per pending `state`.
- Bounds: `max_sessions` (64) sessions of about 200 bytes, 64 pending
  logins, the 16 connection cap of RFC 0014 shared with the console.
  Polling at 2 s from a few tabs is a few requests a second.
- The CSPRNG and SHA-256 are `ring`, JSON is `serde_json` and the HTTPS
  client is `hyper-rustls`: all already in the lock file, so no new Rust
  dependency. The UI's npm dependencies
  are pinned by `package-lock.json` and only reach the repo as the built
  bundle, reviewed in the PR that changes it.

## Implementation notes

Found while building:

- Failed and denied OIDC logins (cases 6 and 14) answer `303` to
  `/ui/login?error=<reason>` rather than a `403` page, so the console
  shows the reason next to the login buttons. No cookie is set either way.
- The bundle is `ui/dist/index.html.gz`, `app.js.gz` and `app.css.gz`,
  served at `/ui/`, `/ui/app.js` and `/ui/app.css` with fixed names, so
  they revalidate with an `ETag` and `Cache-Control: no-cache` instead of
  a long cache. CI's stale check compares the decompressed files with a
  fresh build: gzip bytes differ between platforms. 61 KiB gzip at first.
- `admin.oidc.issuer` and the discovery endpoints may be `http` on a
  loopback host, like `public_url`: a local IdP, and the mock issuer of
  cases 13 to 15.
- Sessions are keyed by the SHA-256 of their id, so a lookup's timing says
  nothing about the ids held (case 2). The CSRF value and the bearer token
  are compared in constant time.
- The reload answer only lists the keys waiting for a restart (RFC 0014),
  so the console shows those and "applied in place" for the rest.
- A failed discovery is tried again at a login at most every 10 s. The
  gateway starts when the issuer is down; the OIDC button then reports it.
- The token exchange uses `client_secret_post`.
- The axe scan (case 20) runs in jsdom, which cannot compute colours, so
  only its `color-contrast` rule is off there; the theme tokens were
  checked by ratio (at least 5.5:1 for text in both themes).
- `ui` is a cargo feature in the default build (on `tls`); a build
  without it refuses `ui_enabled = true` at start.
- RSA and EC verification, `getrandom`, `sha2` and `base64` were not
  needed: `ring` (already in `l7`) gives SHA-256 and the CSPRNG, and
  base64url is a few lines in `l7::oidc`.

## Rollout

- **Rollout:** the release after acceptance. Nothing changes on upgrade:
  `ui_enabled` defaults to `false`, the bearer calls answer as before and
  `/status` only gains a field.
- **Off switch:** `ui_enabled = false` and a restart; this also drops
  every session. Emptying `admin.oidc.issuer` turns SSO off and keeps the
  token login.
