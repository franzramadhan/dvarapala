---
name: rfc-stack
description: Implement an accepted dvarapala RFC as a gh stack, from a working branch to merged layers on main. Use when asked to implement RFC NNNN, or to split finished RFC work into stacked PRs.
---

# Implement an accepted RFC as a stack

Follow `CLAUDE.md` (product rules, TDD, domain scoping, stacked PRs) and
load the `gh-stack` skill. The RFC must be `accepted`; if it is `draft`,
stop and ask.

## 1. Build it whole on a working branch

1. `git switch main && git pull --ff-only && git switch -c rfcNNNN/wip`.
2. Implement everything: tests from the RFC's "Test cases" table first,
   then code, `CONFIG.md`, `examples/dvarapala.toml`, fuzz targets for
   anything that reads attacker input, CI steps, `CLAUDE.md` layout rows,
   and an "Implementation notes" section in the RFC for every deviation.
3. Verify before splitting:
   - `cargo fmt --all --check`
   - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
   - `cargo test --workspace --all-features` and
     `cargo test -p dvarapala --no-default-features`
   - `cargo deny check` when a dependency was added
   - each new fuzz target for 60 s:
     `cd fuzz && cargo +nightly fuzz run <target> -- -max_total_time=60`
   - Linux-only code (XDP, anything under `cfg(target_os = "linux")`) in
     a privileged Linux container with the repo mounted, and a separate
     `CARGO_TARGET_DIR` so the host build is not clobbered
   - Postgres or Redis tests against local containers
   - every Rust file under 500 lines
4. `git commit -m "wip: rfc NNNN"`. Never push this branch.

## 2. Split into layers

Plan the layers before touching branches. The usual order:

1. `rfcNNNN/tests`: `test(<scope>): rfc NNNN <topic> cases, ignored`
2. one layer per domain, inner first (`engine`, then `store`/`l4`/`l7`/
   `proxy`, then the binary): `feat(<scope>): ...`
3. `rfcNNNN/cli`: config section, wiring in `main.rs`, `CONFIG.md`,
   `examples/dvarapala.toml`

Rules for the split:

- A layer compiles, lints and passes tests alone. Code a layer needs moves
  down to the first layer that uses it (record that in the PR body).
- A new required CI job goes in the bottom layer with a skip guard, or
  `gh stack merge` fails on lower layers that never report it.
- Fuzz targets go in the layer that implements what they call.
- Root `Cargo.toml` and `Cargo.lock` go in the tests layer when new crates
  appear there.

### The tests layer

```bash
git switch main && gh stack init rfcNNNN/tests
git checkout rfcNNNN/wip -- <new crates> <changed tests> <Cargo files>
python3 .claude/skills/rfc-stack/stub.py NNNN <src file>          # stub bodies, ignore tests
python3 .claude/skills/rfc-stack/stub.py NNNN <test file> --tests-only
```

Then by hand:

- In existing test files, ignore only the new tests (`#[ignore = "rfc NNNN"]`);
  restore the file from `main` plus the new tests if `--tests-only` caught
  old ones.
- `const fn` stubs use `panic!("rfc NNNN")`, not `todo!`.
- Private helpers returning `impl Trait` cannot be stubbed: delete them.
- Unused parameters and fields: `let _ = (a, b);` before the `todo!`.
- New fields on existing structs (and their `None` at every call site) go
  in this layer, so later layers only change logic.
- Embedded build artifacts (`include_bytes!`) become `&[]` here.

Lint and test, then commit. Every stubbed test must show as ignored, no
old test may be ignored.

### Each next layer

```bash
gh stack add rfcNNNN/<layer>
git checkout rfcNNNN/wip -- <paths of this layer>
# lint, test (Linux container for Linux code), commit
```

The top layer takes the rest: `git checkout rfcNNNN/wip -- .`, then
`git diff rfcNNNN/wip --stat` must be empty and no test may be ignored.

## 3. Submit, check, merge

1. `gh stack submit --auto`, then per PR `gh pr edit <n> --title "<commit
   subject>" --body-file <file>`: what the layer adds, which RFC cases it
   covers. No session links in bodies.
2. `gh pr ready <n>` for each.
3. Wait for checks in the background. On a CI-only failure, get the real
   error into the log first, fix in the owning layer, `gh stack rebase
   --upstack`, `gh stack push`, batching fixes into one push.
4. All green: `gh stack merge <top PR> --squash --yes`.
5. `git switch main && git pull --ff-only`, delete the local
   `rfcNNNN/*` branches including `wip`.

The RFC stays `accepted` until its release (see the `release` skill).
