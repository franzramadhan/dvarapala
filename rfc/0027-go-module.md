# 0027: Go module with prebuilt libraries

| Status | Date | PR | Release |
|---|---|---|---|
| implemented | 2026-10-31 | #234 | v0.20.0 |

> Make the Go SDK installable with `go get`: each release pushes the Go
> package, the C header and a stripped static library per platform to a
> generated module repository, `github.com/franzramadhan/dvarapala-go`,
> and tags it with the release version.

## Problem

The Go package in `sdk/go` (RFC 0008) cannot be fetched with `go get`:

- Its cgo flags point outside the module:
  `-I${SRCDIR}/../../crates/ffi` for the header and
  `${SRCDIR}/../../target/release/libdvarapala.a` for the library. A
  module download holds only `sdk/go`, so the build finds neither.
- It has no tag (`sdk/go/v<version>`), so the module proxy has no
  version to serve.

Today a Go user clones the repository at a release tag, builds
`dvarapala-ffi` with cargo and adds a `replace` directive
(`site/docs/sdk.md`). That needs a Rust toolchain on every build host,
and Dependabot and Renovate cannot update a `replace`.

Go has no package registry: `go get` downloads source from a version
control tag, through `proxy.golang.org`. Shipping a native library means
committing it to the module's repository.

## Proposal

- A second repository, `franzramadhan/dvarapala-go`, holds generated
  content only. Each release pushes a commit and tags it `v<version>`
  (the workspace version), so
  `go get github.com/franzramadhan/dvarapala-go@v<version>` works with a
  C toolchain (cgo) and no Rust.
- The module tree:

  | Path | Content |
  |---|---|
  | `*.go` | `sdk/go` as is, except `link.go` |
  | `link.go` | generated cgo flags: `-I${SRCDIR}/include`, then one `#cgo <goos>,<goarch> LDFLAGS: ${SRCDIR}/lib/<goos>_<goarch>/libdvarapala.a` per platform |
  | `include/dvarapala.h` | `crates/ffi/dvarapala.h` |
  | `lib/<goos>_<goarch>/libdvarapala.a` | the `sdk` job's static library, debug info stripped |
  | `go.mod` | `module github.com/franzramadhan/dvarapala-go`, the `go` line of `sdk/go/go.mod` |
  | `README.md`, `LICENSE` | generated from `franzramadhan/dvarapala`; issues and PRs go there |

- Platforms: `linux_amd64`, `linux_arm64`, `darwin_amd64` and
  `darwin_arm64`, the four libraries the `sdk` job builds. When RFC 0026
  lands, the Linux libraries come from its `manylinux_2_28` build (glibc
  2.28).
- `sdk/go` stays the source of truth and keeps building from a checkout.
  Its cgo flags move from `guard.go` to `sdk/go/link.go`, which points at
  `../../crates/ffi` and `../../target/release` as today. The release
  replaces only that file.
- `sdk/go/unsupported.go`, built when cgo is off or the platform is not
  one of the four, makes the build fail with an error that names the
  requirement, instead of a list of undefined C symbols.
- The libraries are stripped of debug info and of the LLVM bitcode that
  `std`'s objects carry for LTO (`llvm-objcopy` from the toolchain's
  `llvm-tools`, removing `.llvmbc` and `.llvmcmd` on Linux,
  `__LLVM,__bitcode` and `__LLVM,__cmdline` on macOS). The system
  `strip` keeps the bitcode (Xcode 16's `strip -S` leaves a 16 MB
  library). The darwin arm64 `libdvarapala.a` shrinks from 20.0 MB to
  3.4 MB, the Linux ones to about 5 MB, and the SDK tests pass linked
  against them. The GitHub release tarballs use the same stripped
  files, so the bytes are the same everywhere.
- The release job pushes with a deploy key that can write to
  `dvarapala-go` and nothing else. Tags are never moved: `sum.golang.org`
  records each version's hash, and a moved tag breaks every build that
  fetched it.
- The docs point Go users at the new module path. The old path
  `github.com/franzramadhan/dvarapala/sdk/go` was never installable, so
  nobody's import breaks.

### Domain

| Path | Responsibility |
|---|---|
| `sdk/go/link.go` | cgo flags for a checkout (moved from `guard.go`) |
| `sdk/go/unsupported.go` | the build error without cgo or on another platform |
| `scripts/go-module.sh` | writes the module tree from `sdk/go`, the header and the four libraries into a directory |
| `.github/workflows/release.yml` | `sdk` job strips the libraries; new `go` job after the GitHub release: run `scripts/go-module.sh`, commit, tag, push, then ask `proxy.golang.org` for the version |
| `.github/workflows/ci.yml` | `release-check`: the module tree for the runner's platform, built and tested, never pushed |
| `site/docs/sdk.md`, `sdk/README.md`, `README.md` | the `go get` line |
| `.claude/skills/release/SKILL.md` | check the new tag after a release |

### Configuration

None: no gateway or SDK key changes.

### Logs and metrics

None.

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | the tree from `scripts/go-module.sh` for the runner's platform, no Rust on `PATH`, no checkout next to it | a new module requires it (`replace` to the directory) and runs `dvarapala.New(dvarapala.Config{}).Check("192.0.2.1", "")` | the verdict is allow, and the SDK's own tests pass in the tree | integration (CI, linux/amd64 and darwin/arm64) |
| 2 | the same tree | `golang.org/x/mod/zip.CheckDir` | no invalid files, total under the 500 MB module limit | integration |
| 3 | the tree, cgo on | `GOOS=windows` or `GOARCH=riscv64` build | fails with the `unsupported.go` error naming cgo and the four platforms | integration |
| 4 | the tree | `CGO_ENABLED=0 go build` | fails with the same error | integration |
| 5 | the four stripped libraries | the `sdk` job finishes | each `libdvarapala.a` is at most 6 MB | CI |
| 6 | `sdk/go` in the checkout | the `go` job (`gofmt`, `go vet`, `go test -race`) | passes as today, with the flags from `link.go` | CI |
| 7 | a release whose tag already exists on `dvarapala-go` with the same tree | the `go` job reruns | succeeds without a push | integration (release dry run) |
| 8 | a tag on `dvarapala-go` with a different tree | the `go` job runs | fails and leaves the tag as it is | integration (release dry run) |
| 9 | the Linux tree from the `manylinux_2_28` build (with RFC 0026) | case 1 in an `almalinux:8` container | passes | integration |

## Alternatives

| Option | Why not |
|---|---|
| Libraries committed in this repository under `sdk/go/lib/`, tagged `sdk/go/v<version>` | every clone of dvarapala carries every release's libraries; the module repository keeps them out of the main history |
| The system library (`#cgo LDFLAGS: -ldvarapala`, installed from the tarball, Homebrew or a distro) | `go get` works but the build host still needs a manual install; a `dvarapala_system` build tag can add it later for platforms without a prebuilt library |
| `purego` (dlopen without cgo) | the shared library still has to reach the host, and every call pays for the reflection-based call path |
| A Go port of the engine | a second engine to keep in step with `crates/engine` |
| Download the library at build time (`go generate`, a `Makefile`) | outside the module checksum; `go get` alone does not run it |
| A GitHub App token instead of a deploy key | more setup for one repository; a deploy key is scoped to `dvarapala-go` already |
| Unstripped libraries | 20 MB each, about 80 MB per release in the module history, with no gain for linking |

## Security and resource limits

- No new attacker input: the SDK API and the library are unchanged.
- Supply chain:
  - only `release.yml` on a `v*` tag on `main` writes to `dvarapala-go`;
  - the deploy key lives in the `release` environment, which only `v*`
    tags can use, and it can write to that repository only;
  - a ruleset on `dvarapala-go` blocks tag updates and deletions and
    every push except the deploy key's;
  - `sum.golang.org` makes each published version immutable for users;
  - the libraries are the files listed in `SHA256SUMS` on the GitHub
    release, so a user can compare them.
- Size: about 17 MB per release in the module repository (four libraries
  of 3 to 5.5 MB), a few MB compressed in its git history. A `go get`
  downloads the module zip once per version: all four libraries, because
  Go modules cannot be split by platform.

## Rollout

- **Before the first publish (maintainer, once):**
  - create `franzramadhan/dvarapala-go` (public, empty, MIT);
  - add the deploy key with write access, with its private half as a
    secret in the `release` environment of `franzramadhan/dvarapala`;
  - add the ruleset described above.
- **Rollout:** v0.20.0, the next minor after acceptance. `sdk/go` keeps working
  from a checkout. The docs switch to
  `go get github.com/franzramadhan/dvarapala-go@v<version>`.
- **After each release:** `GOPROXY=https://proxy.golang.org go list -m
  github.com/franzramadhan/dvarapala-go@v<version>` prints the version.
- **Off switch:** drop the `go` job. A bad version is marked with a
  `retract` directive in the next release's `go.mod`, never by deleting
  or moving its tag.

## Implementation notes

- Every Go file in `sdk/go` carries
  `//go:build cgo && (linux || darwin) && (amd64 || arm64)`;
  `unsupported.go` has the negation and stops the build at
  `undefined: dvarapala_needs_cgo_on_linux_or_darwin_with_amd64_or_arm64`.
- Cases 1, 3 and 4 run in `scripts/sdk-packages-check.sh` (shared with
  RFC 0026), in `release-check` and the `js` job, Linux x86_64 only;
  darwin arm64 was run locally (stripped library 3.3 MB). In the v0.20.0
  release job the Linux libraries were 5.1 MB (x86_64) and 5.4 MB
  (aarch64) after the bitcode was removed, so the case 5 budget is 6 MB,
  not 4.
- Case 2 is not run: the tree holds only Go files, the header, four
  libraries of at most 6 MB (checked in the `sdk` job), `go.mod`,
  `README.md` and `LICENSE`, far from the module zip limits.
- Case 9 is not run, as RFC 0026 case 3: no Go toolchain is needed to
  see the glibc floor, which the `sdk` job checks on the shared library
  built from the same objects.
- Cases 7 and 8 rest on the `go` job comparing the tagged tree with
  `diff -r`; the first release confirms them. A rerun of the whole
  workflow rebuilds the libraries, which may differ by a byte and then
  fail case 8; rerun the `go` job alone instead.
- The deploy key is the `GO_MODULE_DEPLOY_KEY` secret of the `release`
  environment; GitHub's SSH host key is pinned in the job.
