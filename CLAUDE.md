# CLAUDE.md

Dvarapala: anti-DDoS gateway with L4 to L7 protection, in Rust. Runs as a
standalone reverse or forward proxy, or embeds as a library (Rust crate or
C ABI). The design and the milestones are in
[rfc/0001-foundation.md](rfc/0001-foundation.md).
`AGENTS.md` is a symlink to this file: edit `CLAUDE.md` only.

## Layout

| Path | Contents |
|---|---|
| `crates/engine` | verdict engine, rules, limiters. No I/O, no async runtime |
| `crates/l4` | listener wrapper, connection limits, timeouts |
| `crates/l7` | `tower` layers: rate limit, rules, challenges |
| `crates/proxy` | reverse and forward proxy core |
| `crates/store` | memory and Redis state backends |
| `crates/xdp` | `aya` eBPF programs (Linux only, optional) |
| `crates/ffi` | C ABI for non-Rust embedders |
| `crates/dvarapala` | the binary |
| `rfc/` | one RFC per feature, from `0000-template.md` |
| `site/` | GitHub Pages site: landing page, docs, pages generated from `CONFIG.md`, `ROADMAP.md` and `examples/` |

Crates appear when the RFC that needs them is accepted. Do not scaffold empty
crates ahead of time.

## Product rules

- RFC first for every feature or enhancement: write `rfc/NNNN-<topic>.md`
  from `0000-template.md` (status `draft`) in a PR of its own, discuss it,
  and start the implementation only after the maintainer explicitly accepts
  it (status `accepted`). Implementation PRs link the RFC; deviations found
  while building go back into the RFC. After the release: status
  `implemented`. Not needed for bug fixes, docs, CI, dependency bumps or
  refactors without visible behavior change; when unsure, treat it as a
  feature.
- `CONFIG.md` is the configuration reference. The PR that adds, changes or
  removes a config key or a metric updates it (and
  `examples/dvarapala.toml`) in the same layer.
- `ROADMAP.md` follows every RFC: the RFC PR adds its row (status
  `draft`), acceptance sets `accepted` (or `rejected`), and the release
  PR sets `implemented` with the version in Target.
- Generic first. Every protection layer is optional and configurable. Lab
  or deployment specifics belong in `examples/`, never in defaults.
- Fail closed on the protection path, fail open only where an RFC says so
  (for example a lost Redis connection), and log it.

## Test-driven development

- Write the tests first. The RFC's "Test cases" table lists them before any
  code. The first implementation commit adds those tests failing (or
  `#[ignore]`d with the RFC number), the next commits make them pass.
- Test behavior, not internals: verdicts for given inputs, bytes on the
  wire, metrics emitted. A refactor must not break a test.
- Bug fixes start with a regression test that fails on the old code.
- Unit tests live next to the code (`#[cfg(test)] mod tests`). Cross-crate
  and network tests live in each crate's `tests/`.
- Parsers and anything that reads attacker input get a `cargo fuzz` target
  in `fuzz/` in the same PR. CI's `fuzz` job runs every target for 60 s;
  a crash reproducer becomes a regression test.
- Resource budget is a test too: the `footprint` CI job (added with the
  RFC 0001 implementation) fails when the idle binary's RSS exceeds the
  budget in that RFC. Hot paths get a `criterion` bench in `benches/`.

## Domain scoping

- One crate per domain (table above), one module per concern inside it.
  `lib.rs` and `mod.rs` only declare modules and re-export; logic goes in
  named files.
- No Rust file over 500 lines, tests included. CI fails above that
  (`file-size` step in `ci.yml`). Split by concern, not by line count.
- `engine` depends on no other workspace crate and no async runtime.
  Dependencies point inward: `dvarapala` and `ffi` depend on the rest,
  never the other way.

## Public repo hygiene

This repository is public. Never commit secrets, tokens, private keys,
internal hostnames, IP addresses of real hosts, customer names or email
addresses. Use placeholders such as `<host>`, `<token>`, `<email>`, and
RFC 5737 / RFC 3849 documentation ranges (`192.0.2.0/24`, `2001:db8::/32`)
in tests and examples.

- `betterleaks` runs in the pre-commit hook (`.pre-commit-config.yaml`,
  run `pre-commit install` once) and in CI on every PR.
- Scan the full history before making anything public:
  `betterleaks git . --redact`.
- A leaked secret is rotated first, then removed from history.
- No agent session links (`claude.ai/code/session_...`) in PR bodies,
  comments or issues. The `title` check fails a PR body that has one.
- Vulnerabilities are reported privately (`SECURITY.md`). Never discuss an
  unfixed one in a public issue, PR or commit message.

## Writing

No em dashes or en dashes anywhere (docs, comments, commit messages). Use a
comma, colon, parentheses or a new sentence.

## CI and releases

- `.github/workflows/ci.yml` runs on pull requests only: `betterleaks` on
  the PR commits always; `cargo fmt --check`, `cargo clippy -D warnings`,
  `cargo test` (also the binary with `--no-default-features`), the file-size check, `cargo deny check` (`deny.toml`) and
  the fuzz targets, plus the `footprint` job (release build, idle RSS
  under the RFC 0001 budget, smoke request) when Rust code changed (`crates/`, `fuzz/`, `examples/`,
  Cargo files, `deny.toml`, toolchain). Release PRs also get
  `release-check`. Docs-only PRs skip the Rust jobs (skipped required
  checks count as passing).
- `main` is protected by a ruleset: PRs only, squash merge only, signed
  commits, no force push or deletion, required checks `secrets`, `test`,
  `deny`, `fuzz`, `footprint`, `release-check` and `title`. A new job that must gate
  merges is added to the ruleset in the same PR.
- New dependencies must pass `deny.toml` (permissive licenses, crates.io
  only, no advisories). Prefer `default-features = false` and the smallest
  feature set: binary size is a product goal.
- `.github/workflows/coverage.yml` runs on pushes to `main` that touch Rust
  code: `cargo llvm-cov`, then writes the test and coverage badge JSON to the
  orphan branch `badges`. Never merge `badges`.
- `.github/workflows/pages.yml` runs on pushes to `main` that touch
  `site/`, `CONFIG.md`, `ROADMAP.md` or `examples/`: `site/build.sh`, then
  Jekyll, then a GitHub Pages deploy.
- `.github/workflows/release.yml` runs on `v*` tags only: checks the tag
  matches the workspace version and is on `main`, builds the per-target
  binaries, and publishes a GitHub release with `SHA256SUMS` and the notes
  from `CHANGELOG.md`. Merges to `main` publish nothing.
- `.github/workflows/title-check.yml` checks every PR title (it becomes the
  squash commit): `type(scope): subject`, types `feat fix docs ci test
  refactor perf build chore release rfc`, an optional scope from the list in
  the workflow, a subject that does not start with an uppercase letter.
- Versioning: `v0.MINOR.PATCH` only. 0.x is alpha; no v1 until the
  maintainer decides. No pre-release suffixes for now.

### Stacked PRs

- A PR that depends on another open PR goes in a stack with the `gh stack`
  extension (`gh extension install github/gh-stack`), never a branch based
  on another branch by hand. Agents load the `gh-stack` skill
  (`gh skill install github/gh-stack`).
- Typical split for an accepted RFC: the failing tests at the bottom, then
  the implementation in one layer per domain (for example `engine`, then
  `l7`, then the binary wiring), each one reviewable alone.
- `gh stack add <branch>` for the next layer, `gh stack submit` to open
  the PRs, `gh stack sync` after a lower layer changes (cascade rebase and
  push).
- Fuzz targets go in the layer that implements the code they call: CI
  fuzzes every target, so a target over `todo!()` stubs fails the tests
  layer.
- Mark the PRs ready (`gh pr ready`), then merge as soon as every PR in the
  stack has all required checks green, without waiting for a manual
  approval: `gh stack merge <top PR> --squash --yes`. All layers up to that
  PR land on `main` in one all-or-nothing step, each as its own squash
  commit.
- After the merge: `git switch main && git pull --ff-only && gh stack sync
  --prune`.

### Release flow

1. Branch `release/v<version>` from `main`.
2. Bump `version` under `[workspace.package]` in `Cargo.toml`.
3. `git cliff --tag v<version> -o CHANGELOG.md` (config: `cliff.toml`).
4. Set the released RFCs to `implemented` in `ROADMAP.md` and in each RFC.
   Check `README.md` (features, status) and `CONFIG.md` (every key, type,
   default and metric) match what ships.
   Check the hand-written site pages (`site/index.html`, `site/docs/`)
   too; the configuration, examples and roadmap pages are generated.
5. Open the PR titled `release: v<version>`. `release-check` fails when the
   branch name, the `Cargo.toml` version and the `CHANGELOG.md` heading
   disagree.
6. Squash-merge to `main`, then tag the merge commit:
   `git tag -s v<version> -m v<version> && git push origin v<version>`.
7. `release.yml` builds and publishes the release.

## GitHub Actions

- Always use the latest release of each action, pinned by full commit SHA
  with the version as a comment: `uses: owner/repo@<40-char sha> # vX.Y.Z`.
  Never pin by tag or branch.
- Resolve a tag to its commit SHA (annotated tags need the second lookup):

  ```bash
  r=actions/checkout; t=$(gh api repos/$r/releases/latest --jq .tag_name)
  set -- $(gh api repos/$r/git/ref/tags/$t --jq '.object.type, .object.sha')
  [ "$1" = tag ] && set -- commit $(gh api repos/$r/git/tags/$2 --jq .object.sha)
  echo "$r@$2 # $t"
  ```

- Tools downloaded in a workflow (betterleaks) are pinned by version and
  sha256 from the release's `checksums.txt`, never a piped installer.
- `actions/checkout` always with `persist-credentials: false`.
- `permissions: contents: read` at the top; grant more per job only where
  needed.
- Pass `${{ }}` values into `run:` scripts through `env:`, never inline.

## Tooling

- Rust is pinned in `rust-toolchain.toml`. Bump it there.
- `betterleaks`, `git-cliff` and `cargo-deny` are pinned in `mise.toml`
  (`mise install`). Run `cargo deny check` before opening a PR that adds a
  dependency.
  Keep the `betterleaks` version in `mise.toml` and `ci.yml` in step.
