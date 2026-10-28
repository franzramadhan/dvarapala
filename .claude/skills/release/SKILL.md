---
name: release
description: Cut a dvarapala release v0.MINOR.PATCH, from the release branch to the published GitHub release, with every doc brought up to date. Use when asked to release, cut a version, or mark RFCs implemented.
---

# Release

Follows "Release flow" in `CLAUDE.md`. Versions are `v0.MINOR.PATCH`: a
minor for new RFCs, a patch for fixes only.

## 1. Branch and versions

```bash
git switch main && git pull --ff-only && git switch -c release/v<version>
```

- `version` under `[workspace.package]` in `Cargo.toml`
- `sdk/js/package.json` and `sdk/python/pyproject.toml`
- `cargo update -w` and `(cd fuzz && cargo update -w)` for both lock files
- `git cliff --tag v<version> -o CHANGELOG.md`

## 2. Status

For each RFC merged since the last release (`git log v<prev>..main`):

- `ROADMAP.md` row: `implemented`, Target `v<version>`
- the RFC header table: `implemented`, Release `v<version>`; its Rollout
  line names the version

## 3. Docs: everything a user reads must match what ships

Search for stale words first:
`grep -rniE "accepted|unplanned|no rfc yet|<previous version>" README.md CONFIG.md site/index.html site/docs examples sdk`.

- `CONFIG.md`: every key, type, default and metric of the released RFCs
  (the feature layers should have done it; check against
  `crates/dvarapala/src/config*`).
- `README.md`: the modes table, the "What it protects" table (one row per
  RFC, tagged `RFC NNNN`), build features in Quick start, the
  architecture diagram, the crates table, the stack line, the Status
  paragraph.
- `site/index.html`: a feature card per released RFC (`<span
  class="tag">RFC NNNN</span>`), the "How it works" list, the metrics
  card, the examples hint.
- `site/docs/protection.md` for new protections,
  `site/docs/architecture.md` for new stages, crates, modes and failure
  policy, `site/docs/index.md` when getting started or build features
  change.
- A new `site/docs/<surface>.md` page plus its `nav` entry in
  `site/_config.yml` for a new surface (a mode, a deployment shape, an
  SDK).
- `examples/`: one config per new mode or deployment, with the header
  comment (use case, why these values), and a row in `examples/README.md`.
  `example_configs_load` loads every file.
- `site/build.sh` regenerates the configuration, examples and roadmap
  pages; run it to check, do not commit its output.

## 4. Check locally

```bash
cargo test -p dvarapala            # includes example_configs_load
for n in $(sed -n 's/^| \[\([0-9]\{4\}\)\](.*| implemented |.*/\1/p' ROADMAP.md); do
  for f in README.md CONFIG.md site/index.html; do
    grep -q "RFC $n" "$f" || echo "missing RFC $n in $f"; done; done
grep -rnP "[\x{2013}\x{2014}]" README.md CONFIG.md site examples rfc CHANGELOG.md
```

## 5. PR, merge, tag

1. Commit `release: v<version>`, push, `gh pr create --title "release:
   v<version>" --body-file <file>`. The body lists the RFCs, the version
   bumps and every doc touched. No session links.
2. Wait for the checks (`release-check` included). All green:
   `gh pr merge <n> --squash`.
3. Tag the merge commit:

   ```bash
   git switch main && git pull --ff-only
   git tag -s v<version> -m v<version> && git push origin v<version>
   ```

4. Watch `release.yml` (`gh run list --workflow release.yml`), then check
   `gh release view v<version>`: one tarball per target and `SHA256SUMS`.
5. Check the Pages deploy (`pages.yml`) and the live site at
   `https://dvarapala.franzramadhan.dev`: the new cards, pages and the
   roadmap statuses.
6. Delete the local release branch.

## 6. After the release

Hand off to the maintainer's own steps outside this repo (a blog post,
the project page), if they asked for them.
