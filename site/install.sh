#!/bin/sh
# Installs the dvarapala binary from a GitHub release, after checking it
# against the release's SHA256SUMS.
#
#   curl -fsSL https://dvarapala.franzramadhan.dev/install.sh | sh
#
# DVARAPALA_VERSION   release to install, for example v0.6.0 (default: latest)
# DVARAPALA_INSTALL   directory for the binary (default: /usr/local/bin when
#                     writable, else ~/.local/bin)
set -eu

repo=https://github.com/franzramadhan/dvarapala

fail() { echo "install.sh: $*" >&2; exit 1; }
command -v curl >/dev/null || fail "needs curl"
command -v tar >/dev/null || fail "needs tar"

case "$(uname -s)" in
  Linux) os=unknown-linux-musl ;;
  Darwin) os=apple-darwin ;;
  *) fail "no release binary for $(uname -s); build from source: $repo" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=x86_64 ;;
  aarch64 | arm64) arch=aarch64 ;;
  *) fail "no release binary for $(uname -m); build from source: $repo" ;;
esac

version=${DVARAPALA_VERSION:-}
if [ -z "$version" ]; then
  # the latest release redirects to .../releases/tag/<tag>: no API rate limit
  version=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$repo/releases/latest")
  version=${version##*/}
fi
case "$version" in
  v[0-9]*) ;;
  *) fail "bad version: $version" ;;
esac

dir=${DVARAPALA_INSTALL:-}
if [ -z "$dir" ]; then
  if [ -w /usr/local/bin ]; then dir=/usr/local/bin; else dir="$HOME/.local/bin"; fi
fi

file="dvarapala-$version-$arch-$os.tar.gz"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
echo "downloading $file"
curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/$file" "$repo/releases/download/$version/$file"
curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/SHA256SUMS" "$repo/releases/download/$version/SHA256SUMS"

want=$(awk -v f="$file" '$2 == f {print $1}' "$tmp/SHA256SUMS")
[ -n "$want" ] || fail "$file is not in SHA256SUMS"
if command -v sha256sum >/dev/null; then
  got=$(sha256sum "$tmp/$file" | awk '{print $1}')
else
  got=$(shasum -a 256 "$tmp/$file" | awk '{print $1}')
fi
[ "$got" = "$want" ] || fail "checksum mismatch for $file"

tar -xzf "$tmp/$file" -C "$tmp" dvarapala
mkdir -p "$dir"
# install(1) replaces the file instead of writing into a running binary
install -m 0755 "$tmp/dvarapala" "$dir/dvarapala"
echo "installed $("$dir/dvarapala" --version) to $dir/dvarapala"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "add $dir to your PATH" ;;
esac
