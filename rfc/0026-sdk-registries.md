# 0026: SDK packages on npm and PyPI

| Status | Date | PR | Release |
|---|---|---|---|
| implemented | 2026-10-31 | #233 | v0.20.0 |

> Publish the JavaScript SDK to npm and the Python SDK to PyPI from
> `release.yml`, with the prebuilt library inside the package, so
> `npm install dvarapala` and `pip install dvarapala` work without a
> checkout, a Rust toolchain or a downloaded tarball.

## Problem

RFC 0008 ships the SDKs as source in `sdk/` plus prebuilt libraries in
`dvarapala-sdk-<tag>-<target>.tar.gz` on the GitHub release, and leaves
registry publishing as a separate decision. Today a Python or Node user:

- downloads the tarball for their platform, unpacks it, and points
  `DVARAPALA_LIB` or `DVARAPALA_NODE` at the library, or
- clones the repo and builds `dvarapala-ffi` or `dvarapala-node` with
  cargo.

Neither works in a lock file, a Dockerfile `RUN pip install`, Dependabot
or Renovate. The libraries are also built on `ubuntu-24.04`: the v0.18.0
`libdvarapala.so` and `dvarapala.node` need `GLIBC_2.34`, so they fail to
load on RHEL 8 and its rebuilds (2.28), Amazon Linux 2 (2.26), Debian 11
and Ubuntu 20.04 (2.31).

Both names are free today (`registry.npmjs.org/dvarapala` and
`pypi.org/pypi/dvarapala/json` return 404).

## Proposal

- Each release publishes `dvarapala` to PyPI and npm at the workspace
  version, from the tagged commit on `main`, with no stored token:
  trusted publishing (OIDC) on both registries, npm provenance and PyPI
  attestations.
- The Linux libraries are built in a `manylinux_2_28` container (glibc
  2.28), so one build loads on every glibc distribution from RHEL 8 and
  Debian 10 on. The GitHub release tarballs use the same build.
- Platforms: Linux x86_64 and aarch64 (glibc), macOS arm64 and x86_64,
  the same four as the tarballs. musl Linux and Windows stay out (see
  Alternatives).
- Python: one wheel per platform, tagged `py3-none-<platform>` (the
  package loads the library with `ctypes`, so one wheel covers every
  Python 3.10+): `manylinux_2_28_x86_64`, `manylinux_2_28_aarch64`,
  `macosx_11_0_arm64`, `macosx_11_0_x86_64`. No sdist: it could not build
  the library, and without one pip reports "no matching distribution" on
  an unsupported platform instead of installing a broken package.
- npm: the main package `dvarapala` (JavaScript and types, no binary)
  with an `optionalDependencies` entry per platform package,
  `@dvarapala/linux-x64-gnu`, `@dvarapala/linux-arm64-gnu`,
  `@dvarapala/darwin-arm64` and `@dvarapala/darwin-x64`, each holding
  `dvarapala.node` and declaring `os`, `cpu` and (Linux) `libc`. npm
  installs only the one that matches. The pattern esbuild and the napi-rs
  packages use.
- The addon is found at `DVARAPALA_NODE`, else `dvarapala.node` next to
  `index.js` (a checkout or the tarball), else the platform package. The
  Python library stays `DVARAPALA_LIB`, else next to the module, which is
  where the wheel puts it. Existing setups keep working.
- On an unsupported platform, `require('dvarapala')` and
  `import dvarapala` fail with an error that names the platform and the
  supported list, never a raw `dlopen` message.
- The bytes published are the ones the `sdk` job built and attached to
  the GitHub release: the publish jobs take its artifacts and never
  rebuild.
- The Go module is out of scope: its cgo flags link
  `target/release/libdvarapala.a` from the checkout, so a `go get` needs
  its own design (a later RFC).

### Domain

| Path | Responsibility |
|---|---|
| `sdk/js/index.js` | addon lookup order and the unsupported platform error |
| `sdk/js/package.json` | `optionalDependencies` on the four platform packages |
| `sdk/js/npm/<platform>/package.json` | platform package manifests (`os`, `cpu`, `libc`, `files: ["dvarapala.node"]`); the release sets their versions |
| `sdk/python/src/dvarapala/_lib.py` | the unsupported platform error |
| `sdk/python/pyproject.toml` | wheel contents (unchanged keys) |
| `.github/workflows/release.yml` | `sdk` job in `manylinux_2_28` for Linux; new `pypi` and `npm` jobs after the GitHub release |
| `.github/workflows/ci.yml` | `release-check`: package versions, `npm pack --dry-run`, a wheel built and `twine check`ed |
| `site/docs/sdk.md`, `sdk/README.md` | install lines |
| `.claude/skills/release/SKILL.md` | registry checks after a release |

### Configuration

None: no gateway or SDK key changes.

### Logs and metrics

None.

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | the wheel for the runner's platform | installed in a fresh venv, no `DVARAPALA_LIB` | `Guard({}).check("192.0.2.1")` is allow | integration (CI, Linux x86_64 and macOS arm64) |
| 2 | the Linux wheel | `auditwheel show` | reports `manylinux_2_28` with no newer glibc symbol | integration |
| 3 | the Linux library and addon | loaded in an `almalinux:8` container (glibc 2.28) | the Python and Node tests of case 1 and 4 pass | integration |
| 4 | `npm pack` of `dvarapala` and the runner's platform package | installed from the tarballs into an empty directory, no `DVARAPALA_NODE` | `new Guard({}).check('192.0.2.1').kind` is `allow` | integration |
| 5 | `DVARAPALA_NODE`, a local `dvarapala.node` and a platform package all present | `require('dvarapala')` | loads `DVARAPALA_NODE`; without it the local file; without both the platform package | unit |
| 6 | Linux with musl, or Windows | `require('dvarapala')` | throws an error naming the platform and the four supported ones | unit |
| 7 | a platform with no library next to `_lib.py` and no `DVARAPALA_LIB` | `import dvarapala` | `ImportError` naming the platform and the supported ones | unit |
| 8 | `sdk/js/package.json` or `sdk/python/pyproject.toml` at another version than `[workspace.package]` | `release-check` | fails, naming the file | CI |
| 9 | a release whose versions are already on npm and PyPI | the `npm` and `pypi` jobs rerun | they succeed and publish nothing | integration (release dry run) |
| 10 | the four platform package manifests | `npm pack --dry-run` | each holds only `package.json` and `dvarapala.node`, with `os`, `cpu` (and `libc` on Linux) set | CI |

## Alternatives

| Option | Why not |
|---|---|
| Keep the tarballs only | the problem above: no lock files, no dependency bots, a manual env var |
| One npm package with every platform's addon | four addons in every install, about four times the size |
| Build the addon on install (`node-gyp`, `cargo` in `postinstall`) | needs a Rust toolchain on every host; install scripts are what `npm --ignore-scripts` and most CI turn off |
| Download the addon in `postinstall` | same, plus a network fetch at install time outside the lock file and the registry's integrity check |
| Unscoped platform packages (`dvarapala-linux-x64-gnu`) | four more top-level names to reserve and squat-watch; the `@dvarapala` scope groups them under one org |
| An sdist on PyPI | it cannot build the library (no Rust build in `setuptools`), so it would install a package that fails on import |
| A compiled extension (`maturin`, `pyo3`) instead of `ctypes` | a wheel per Python version; the C ABI is already the boundary (RFC 0008) |
| musl Linux (Alpine) now | Rust `cdylib` on musl needs `-C target-feature=-crt-static` and its own test matrix; add `musllinux_1_2` wheels and `@dvarapala/linux-*-musl` when someone asks |
| Windows now | no Windows build of `ffi` or `node` exists yet; a separate change |
| A stored `NPM_TOKEN` and PyPI API token | a long-lived secret in the repo; trusted publishing needs none, as for crates.io since v0.16.1 |

## Security and resource limits

- No new attacker input: the SDK API and the library are unchanged.
- Supply chain:
  - publish only from `release.yml` on a `v*` tag on `main` (the
    existing `verify` job);
  - OIDC trusted publishing on both registries, with npm provenance and
    PyPI attestations, so each published file links back to its workflow
    run;
  - no install scripts;
  - the `manylinux_2_28` images pinned by digest, as actions are pinned
    by SHA;
  - the published files are the ones in `SHA256SUMS` on the GitHub
    release.
- Account side: the maintainer's npm and PyPI accounts use 2FA. The
  `@dvarapala` npm org and the PyPI project are created before the first
  publish, which also reserves the names.
- Size: one library per install. The wheel carries `libdvarapala.so`
  (404 KB in v0.18.0, x86_64 Linux) and the platform package
  `dvarapala.node` (455 KB); the static `libdvarapala.a` (24 MB) stays in
  the tarball only.

## Rollout

- **Before the first publish (maintainer, once):**
  - create the npm org `dvarapala`;
  - add a PyPI pending trusted publisher for project `dvarapala`
    (workflow `release.yml`, repository `franzramadhan/dvarapala`);
  - add npm trusted publishers for the five packages. If npm needs a
    package to exist before a trusted publisher can be added, the first
    publish uses a granular token scoped to these packages, revoked
    right after.
- **Rollout:** v0.20.0, the next minor after acceptance. The GitHub release keeps
  its SDK tarballs, now built for glibc 2.28. Existing `DVARAPALA_LIB` and
  `DVARAPALA_NODE` setups keep working.
- **After each release:**
  - `npm view dvarapala@<v>` and `pip download dvarapala==<v>` succeed
    for each platform;
  - the npm page shows provenance.
- **Off switch:** drop the `npm` and `pypi` jobs. A bad version is
  yanked on PyPI and deprecated on npm (`npm deprecate`; npm unpublish
  is limited to 72 hours), then fixed in a patch release.

## Implementation notes

- The wheels are written by `scripts/wheel.py` (stdlib only, no build
  tools in the release), and a new `packages` job builds them and the npm
  tarballs from the `sdk` job's files. They are attached to the GitHub
  release and listed in `SHA256SUMS`, then the `pypi` and `npm` jobs
  publish those same files.
- The Linux `sdk` legs run `cargo` inside the pinned `manylinux_2_28`
  image with the runner's Rust toolchain mounted, so no toolchain is
  downloaded into the container.
- Case 2: no `auditwheel`. The `sdk` job reads the glibc symbol versions
  of `libdvarapala.so` and `dvarapala.node` with `objdump -T` and fails
  above 2.28, which is the check `auditwheel` would make for these two
  files.
- Case 3 is not run: `almalinux:8` has neither Python 3.10 nor Node 20.
  The symbol check above covers the glibc floor.
- `twine check` is replaced by installing the wheel into a fresh venv
  and calling `Guard`. `scripts/sdk-packages-check.sh` runs cases 1, 4,
  8 and 10 for the host platform, in `release-check` and in the `js` job
  (so a change to the scripts is tested before a release). CI runs it on
  Linux x86_64 only, which keeps `release-check` a single check; macOS
  arm64 was run locally.
- Case 9 rests on `skip-existing` (PyPI) and `npm view` before each
  `npm publish`; the first release confirms it.
- The main npm package no longer lists `dvarapala.node` in `files`, so
  it can never ship a binary.
