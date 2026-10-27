#!/usr/bin/env bash
#
# Rebuild the whole comparison: fetch better-auth's source, map both suites,
# diff them, and regenerate the maps.
#
#   benchmark/scripts/refresh.sh [better-auth-tag] [checkout-dir]
#
# Defaults to the tag the current numbers were measured against. Pass a newer
# one to re-measure; FINDINGS.md names the version it refers to, so update that
# line when the tag changes.

set -euo pipefail

TAG="${1:-v1.7.2}"
SRC="${2:-${TMPDIR:-/tmp}/better-auth-src-$TAG}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG="$(cd "$HERE/.." && pwd)"
cd "$PKG"
mkdir -p "$HERE/out"

# The npm package ships `dist` only, so the tests exist in git and nowhere else.
if [ ! -d "$SRC/.git" ]; then
  echo "==> cloning better-auth $TAG into $SRC"
  rm -rf "$SRC"
  git clone --depth 1 --branch "$TAG" --quiet \
    https://github.com/better-auth/better-auth.git "$SRC"
else
  echo "==> reusing checkout at $SRC"
fi

echo "==> mapping duck-auth"
bun "$HERE/scripts/harvest.ts" "$PKG/src" duck-auth --out "$HERE/out/duck-auth.json"

# docs/ and demo/ carry tests for their documentation site and demo app, which
# are not the library under comparison.
echo "==> mapping better-auth $TAG"
bun "$HERE/scripts/harvest.ts" "$SRC" better-auth --out "$HERE/out/better-auth.json" --exclude docs,demo

echo "==> diffing"
bun "$HERE/scripts/compare.ts" "$HERE/out/duck-auth.json" "$HERE/out/better-auth.json" > /dev/null

echo "==> writing maps"
bun "$HERE/scripts/map.ts" "$HERE/out/better-auth.json" "better-auth $TAG" > "$HERE/MAP-better-auth.md"
bun "$HERE/scripts/map.ts" "$HERE/out/duck-auth.json" "duck-auth (@gentleduck/auth)" > "$HERE/MAP-duck-auth.md"

echo
echo "benchmark/out/GAP-TABLE.md    the per-cluster diff"
echo "benchmark/MAP-better-auth.md  their suite, file by file"
echo "benchmark/MAP-duck-auth.md    ours, file by file"
echo
echo "Those counts are static and a lower bound. For counts to quote, run:"
echo "  benchmark/scripts/run-suites.sh all $SRC"
