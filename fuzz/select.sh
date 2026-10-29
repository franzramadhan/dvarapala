#!/usr/bin/env bash
# Prints the fuzz targets a change touches, one per line. Reads the changed
# paths on stdin. A target runs when its own file changes or when the source
# of a workspace crate it reaches changes (dependencies followed through
# `cargo metadata`). Shared build inputs run every target, and so does a
# target missing from the map below.
set -euo pipefail
cd "$(dirname "$0")/.."

declare -A crate=(
  [admin_query]=dvarapala-l7 [challenge]=dvarapala-l7
  [grpc_content_type]=dvarapala-l7 [oidc_callback]=dvarapala-l7
  [replay_line]=dvarapala-l7 [route_match]=dvarapala-l7
  [waf_frame]=dvarapala-l7
  [client_key]=dvarapala-engine [tree_model]=dvarapala-engine
  [ffi_check]=dvarapala-ffi
  [forward_route]=dvarapala-proxy [ja4]=dvarapala-proxy
  [pem]=dvarapala-proxy [upgrade_headers]=dvarapala-proxy
  [quic_datagram]=dvarapala-proxy
  [store_reply]=dvarapala-store
  [xdp_parse]=dvarapala-xdp-common
)

files=$(cat)
targets=$(basename -s .rs fuzz/fuzz_targets/*.rs)

if grep -qE '^(fuzz/(Cargo\.(toml|lock)|select\.sh)|Cargo\.(toml|lock)|rust-toolchain\.toml|\.github/workflows/ci\.yml)$' <<<"$files"; then
  printf '%s\n' "$targets"
  exit 0
fi

meta=$(cargo metadata --no-deps --format-version 1 --manifest-path Cargo.toml)

# the crate's directory plus those of every workspace crate it depends on
dirs() {
  jq -r --arg p "$1" '
    (.packages | map({key: .name, value: .}) | from_entries) as $all
    | def reach($n): [$n] + ($all[$n].dependencies
        | map(select(.path != null) | .name) | map(reach(.)) | add // []);
    reach($p) | unique[] | $all[.].manifest_path
    | sub("/Cargo\\.toml$"; "") | sub("^.*?/crates/"; "crates/")' <<<"$meta"
}

for t in $targets; do
  if grep -qx "fuzz/fuzz_targets/$t.rs" <<<"$files" || [ -z "${crate[$t]:-}" ]; then
    echo "$t"
    continue
  fi
  for d in $(dirs "${crate[$t]}"); do
    if grep -qE "^$d/(src/|build\.rs$|Cargo\.toml$)" <<<"$files"; then
      echo "$t"
      break
    fi
  done
done
