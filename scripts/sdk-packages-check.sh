#!/bin/bash
# RFC 0026 and 0027: the npm, PyPI and Go packages for the host platform,
# built from target/release and installed the way a user would, before a
# release publishes them. Run by release-check after
#   cargo build --release -p dvarapala-ffi -p dvarapala-node
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fail=0
# json <file> <python expression over p>
json() { python3 -c "import json, sys; p = json.load(open(sys.argv[1])); print($2)" "$1"; }

# case 8 (RFC 0026): every package at the workspace version
version=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' Cargo.toml)
for f in sdk/js/package.json sdk/js/npm/*/package.json; do
  v=$(json "$f" 'p["version"]')
  [ "$v" = "$version" ] || { echo "::error file=$f::version $v, Cargo.toml says $version"; fail=1; }
done
for dep in $(json sdk/js/package.json '" ".join(k + "@" + v for k, v in p["optionalDependencies"].items())'); do
  [ "${dep##*@}" = "$version" ] || { echo "::error file=sdk/js/package.json::optional dependency $dep, Cargo.toml says $version"; fail=1; }
done
v=$(sed -n 's/^version = "\(.*\)"/\1/p' sdk/python/pyproject.toml)
[ "$v" = "$version" ] || { echo "::error file=sdk/python/pyproject.toml::version $v, Cargo.toml says $version"; fail=1; }
[ "$fail" = 0 ] || exit 1

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) npm=linux-x64-gnu wheel=manylinux_2_28_x86_64 go=linux_amd64 ext=so ;;
  Linux-aarch64) npm=linux-arm64-gnu wheel=manylinux_2_28_aarch64 go=linux_arm64 ext=so ;;
  Darwin-arm64) npm=darwin-arm64 wheel=macosx_11_0_arm64 go=darwin_arm64 ext=dylib ;;
  Darwin-x86_64) npm=darwin-x64 wheel=macosx_11_0_x86_64 go=darwin_amd64 ext=dylib ;;
esac
lib=target/release/libdvarapala.$ext

echo "== RFC 0026 case 1: the wheel in a fresh venv"
python3 scripts/wheel.py "$wheel" "$lib" "$work/wheels"
python3 -m venv "$work/venv"
"$work/venv/bin/pip" install -q --no-index "$work"/wheels/*.whl
(cd "$work" && env -u DVARAPALA_LIB "$work/venv/bin/python" -c \
  'from dvarapala import ALLOW, Guard; assert Guard({}).check("192.0.2.1").kind == ALLOW')

echo "== RFC 0026 case 10: platform package contents"
for d in sdk/js/npm/*/; do
  k=$(basename "$d")
  cp -R "$d" "$work/npm-$k"
  cp "target/release/libdvarapala_node.$ext" "$work/npm-$k/dvarapala.node"
  files=$(cd "$work/npm-$k" && npm pack --dry-run --json \
    | python3 -c 'import json, sys; print(" ".join(sorted(f["path"] for f in json.load(sys.stdin)[0]["files"])))')
  [ "$files" = "README.md dvarapala.node package.json" ] || { echo "::error file=$d::packs '$files'"; fail=1; }
  [ "$(json "$d/package.json" 'bool(p.get("os") and p.get("cpu") and (p["os"] != ["linux"] or p.get("libc")))')" = True ] \
    || { echo "::error file=$d::os, cpu or libc missing"; fail=1; }
done

echo "== RFC 0026 case 4: npm install from the tarballs"
(cd "$work" && npm pack -q "$root/sdk/js" "$work/npm-$npm" >/dev/null)
mkdir "$work/app"
(cd "$work/app" && npm init -y >/dev/null && npm install -q --no-audit --no-fund --omit=optional "$work"/dvarapala-*.tgz \
  && env -u DVARAPALA_NODE node -e "const {Guard}=require('dvarapala'); if (new Guard({}).check('192.0.2.1').kind !== 'allow') process.exit(1)")

echo "== RFC 0027 cases 1, 3, 4: the Go module tree"
mkdir -p "$work/libs/$go"
cp target/release/libdvarapala.a "$work/libs/$go/"
if [ "$(uname -s)" = Linux ]; then strip --strip-debug "$work/libs/$go/libdvarapala.a"; else strip -S "$work/libs/$go/libdvarapala.a"; fi
scripts/go-module.sh "$work/mod" "$work/libs"
(cd "$work/mod" && go vet ./... && go test -count=1 ./...)
mkdir "$work/use"
cat > "$work/use/main.go" <<'EOF'
package main

import (
	"net/netip"

	dvarapala "github.com/franzramadhan/dvarapala-go"
)

func main() {
	g, err := dvarapala.New(dvarapala.Config{})
	if err != nil {
		panic(err)
	}
	if g.Check(netip.MustParseAddr("192.0.2.1"), "").Kind != dvarapala.Allow {
		panic("not allowed")
	}
}
EOF
printf 'module use\n\ngo 1.26\n\nrequire github.com/franzramadhan/dvarapala-go v0.0.0\n\nreplace github.com/franzramadhan/dvarapala-go => ../mod\n' > "$work/use/go.mod"
(cd "$work/use" && go run .)
for env in CGO_ENABLED=0 GOOS=windows; do
  out=$(cd "$work/mod" && env "$env" go build ./... 2>&1) && { echo "::error::$env go build succeeded"; fail=1; }
  grep -q dvarapala_needs_cgo_on_linux_or_darwin <<<"$out" || { echo "::error::$env: $out"; fail=1; }
done

exit "$fail"
