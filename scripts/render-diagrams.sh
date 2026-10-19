#!/usr/bin/env bash
# Renders every ```mermaid block in README.md and docs/*.md to docs/diagrams/<page>-<n>.svg and .png.
# Build tool only: needs Node, runs mermaid-cli through npx, and is not part of the Maven build.
set -euo pipefail
cd "$(dirname "$0")/.."
out=docs/diagrams
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$out"
rm -f "$out"/*.svg "$out"/*.png
for md in README.md docs/*.md; do
  page=$(basename "$md" .md)
  [ "$md" = README.md ] && page=readme
  [ "$md" = docs/README.md ] && page=index
  awk -v dir="$tmp" -v page="$page" '
    /^```mermaid[[:space:]]*$/ { n++; f = dir "/" page "-" n ".mmd"; inblock = 1; next }
    inblock && /^```[[:space:]]*$/ { inblock = 0; close(f); next }
    inblock { print > f }
  ' "$md"
done
for f in "$tmp"/*.mmd; do
  name=$(basename "$f" .mmd)
  npx -y @mermaid-js/mermaid-cli -q -i "$f" -o "$out/$name.svg" -b white
  npx -y @mermaid-js/mermaid-cli -q -i "$f" -o "$out/$name.png" -b white -s 2
done
ls "$out"
