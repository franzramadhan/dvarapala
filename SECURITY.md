# Security policy

Dvarapala is a protection layer, so a bug in it can expose what sits behind
it. Please report vulnerabilities privately.

## Reporting

Use GitHub private vulnerability reporting:
**Security** tab, **Report a vulnerability**
(<https://github.com/franzramadhan/dvarapala/security/advisories/new>).
Do not open a public issue or pull request for a vulnerability.

Include the version or commit, the configuration involved (with secrets and
real addresses removed), and the steps or traffic that reproduce it.

## What to expect

- Acknowledgement within 7 days.
- A fix or a mitigation plan within 30 days for confirmed issues, sooner for
  bypasses of the protection path or remote crashes.
- Credit in the advisory and the release notes, unless you prefer otherwise.

## Supported versions

Dvarapala is 0.x (alpha). Only the latest release gets security fixes.

## In scope

- Bypasses of a limiter, rule or challenge.
- Crashes, panics, unbounded memory or CPU from attacker-controlled input.
- Request smuggling, header injection, or proxying to an unintended target.
- Memory safety issues in `unsafe` code, the C ABI or the eBPF programs.

Volumetric attacks that exceed the host's bandwidth are out of scope: no
single host can absorb them.
