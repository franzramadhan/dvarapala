#!/bin/sh
# Writes the generated docs pages from the repo sources, so CONFIG.md,
# ROADMAP.md and examples/ stay the single source. Run from anywhere.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
docs=$root/site/docs
blob=https://github.com/franzramadhan/dvarapala/blob/main

# repo-relative links in the sources point at GitHub
links() { sed -e "s#](rfc/#]($blob/rfc/#g" -e "s#](examples/#]($blob/examples/#g" -e "s#](sdk/#]($blob/sdk/#g"; }

page() { printf -- '---\ntitle: %s\nsource: %s\n---\n\n' "$1" "$2"; }

{ page Configuration CONFIG.md; sed 1d "$root/CONFIG.md" | links; } > "$docs/configuration.md"
{ page Roadmap ROADMAP.md; sed 1d "$root/ROADMAP.md" | links; } > "$docs/roadmap.md"

{
  page Examples examples
  echo 'Configs for common deployments, from [`examples/`]('"$blob"'/examples).'
  echo 'Run one with `dvarapala serve --config examples/<file>`. Names, paths'
  echo 'and addresses are placeholders. Every key is in [Configuration](configuration.html).'
  for f in "$root"/examples/*.toml; do
    n=$(basename "$f")
    printf '\n## %s\n\n' "$n"
    # the leading comment block is the use case: render it as prose
    awk '/^#/ { sub(/^# ?/, ""); gsub(/</, "\\&lt;"); print; next } { exit }' "$f"
    printf '\n```toml\n'
    cat "$f"
    printf '```\n'
  done
} > "$docs/examples.md"
