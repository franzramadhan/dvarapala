# 0020: Trust the issuer's email for console login

| Status | Date | PR | Release |
|---|---|---|---|
| accepted | 2026-10-29 | #153 | |

> A new `admin.oidc.require_email_verified` key (default `true`) lets the
> console accept an `email` claim that comes without `email_verified`, for
> issuers such as Cloudflare Access that verify the email themselves but
> never send the claim.

## Problem

RFC 0018 lets a console user in by `allow_emails` only when the ID token
says `email_verified: true`. The rule is right for an identity provider
where a user can type any address into a profile: without it, someone
registers `ops@example.com` there and walks in.

Cloudflare Access, as an OIDC issuer for a SaaS application, never sends
`email_verified`. Its built-in Google login drops the claim even when it is
listed under OIDC Claims (`oidc_fields` stays empty in the login test), and
marking it as a required claim on the application makes the token
endpoint answer `400`. Cloudflare has no setting for it
([community thread](https://community.cloudflare.com/t/access-for-saas-oidc-verified-email-assurance-with-otp-or-native-cloudflare-idp/973378)). The email in the
token is still verified: Access issues a token only to an identity that
logged in with the upstream provider and passed the application's policy.

Today such an issuer can only log in through `allow_groups`, which needs a
groups claim the operator may not have. With Google consumer accounts
there are no groups, so the console falls back to token login.

## Proposal

- `[admin.oidc] require_email_verified = false` accepts the `email` claim
  for `allow_emails` when `email_verified` is absent.
- An explicit `email_verified: false` (or `"false"`) still denies: the
  issuer has said the address is not proven, and no setting overrides it.
- Default `true`: no change for existing configs.
- At start, `false` logs a warning naming the issuer, so the choice is
  visible in the logs.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/l7/src/oidc.rs` | `OidcConfig.require_email_verified`; `check` treats a missing claim as verified when it is `false`. The file is at 498 lines: its tests move to `oidc/tests.rs` in the same change |
| `crates/dvarapala/src/config/admin.rs` | the key, its default, the start warning |

### Configuration

| Key | Default | |
|---|---|---|
| `admin.oidc.require_email_verified` | `true` | `false`: an `email` claim without `email_verified` counts as verified for `allow_emails`. Only for an issuer that verifies the email itself and lets only its own users through (Cloudflare Access). `allow_groups` is unchanged |

### Logs and metrics

| | |
|---|---|
| `msg="oidc email trusted without email_verified" issuer=...` | warning at start when the key is `false` |

No new metric: logins keep `dvarapala_admin_logins_total{method="oidc",result}`.

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | `require_email_verified = false`, `allow_emails = ["ops@example.com"]` | ID token with `email: "Ops@example.com"`, no `email_verified` | allowed, subject `Ops@example.com` | unit |
| 2 | `require_email_verified = false` | ID token with `email_verified: false` | denied, `not_allowed` | unit |
| 3 | `require_email_verified = false` | ID token with `email_verified: "false"` | denied | unit |
| 4 | default (`true`) | ID token without `email_verified` | denied (RFC 0018 behavior unchanged) | unit |
| 5 | `require_email_verified = false` | email not in `allow_emails`, no groups | denied | unit |
| 6 | config without the key | load | `require_email_verified` is `true` | unit |
| 7 | mock issuer that omits `email_verified`, key `false` | browser login through `/session/oidc` and the callback | `302` to `/ui/` with the session cookie; with the key `true`, `303` to `/ui/login?error=` | integration |

## Alternatives

| Option | Why not |
|---|---|
| Change the Cloudflare side (custom claim, generic OIDC connector) | Tried: Access drops the claim, and a required claim breaks the token call. Nothing to configure there |
| `allow_subjects` (match `sub`) | Works without trusting email, but `sub` is an opaque per-issuer ID the operator has to dig out of a token, and it changes per issuer and application. Could come later on its own |
| Drop the `email_verified` check for every issuer | Opens the impersonation hole the check closes for providers with self-asserted emails |
| Per-email exception list | More surface than a per-issuer switch, and the trust decision is about the issuer, not the address |

## Security and resource limits

The attacker controls nothing new: the ID token still comes straight from
the configured issuer's token endpoint over verified TLS, and `iss`, `aud`,
`exp` and `nonce` are checked as before. The switch moves trust in the
email to the issuer: with `false`, anyone who can get the issuer to put an
allowed address in `email` gets in. Safe only where the issuer verifies
addresses (Cloudflare Access behind Google, an enterprise directory);
unsafe with a provider that lets users edit their email. CONFIG.md says so
next to the key. No CPU or memory change.

## Rollout

- **Rollout:** next minor release. Default `true`, so upgrades change
  nothing. Cloudflare Access users set `require_email_verified = false`.
- **Off switch:** remove the key or set it to `true` (applies on restart;
  `[admin]` keys are not reloaded).
