#!/usr/bin/env bash
# Mirrors this repo's docs content into the sibling @duck-ui docs site, run from
# .husky/pre-push so every push republishes the latest docs there too.
#
#   bun run sync-docs                     copy now (also runs automatically on push)
#
# Never fails the push: a missing sibling checkout (CI, a fresh clone without
# @duck-ui beside it) is a skip, not an error.
set -euo pipefail

ROOT="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
SRC="$ROOT/docs/duck-iam-docs/content/docs"
DUCK_UI="$(cd "$ROOT/../@duck-ui" 2>/dev/null && pwd -P)" || {
  echo "[sync-docs] ../@duck-ui not found next to this repo, skipping" >&2
  exit 0
}
DEST="$DUCK_UI/apps/duck/content/docs/duck-iam"

if [ ! -d "$SRC" ]; then
  echo "[sync-docs] $SRC not found, skipping" >&2
  exit 0
fi

if [ -d "$DEST" ]; then
  rm -rf "$DEST.back"
  mv "$DEST" "$DEST.back"
  echo "[sync-docs] backed up existing docs to $DEST.back"
fi

mkdir -p "$DEST"

count=0
while IFS= read -r -d '' f; do
  rel="${f#"$SRC"/}"
  # The docs root's own index.mdx is unreachable at its site route (the package
  # landing page owns that slot); every other index.mdx is a normal, reachable
  # section index and is copied as-is.
  if [ "$rel" = "index.mdx" ]; then
    rel="introduction.mdx"
  fi
  mkdir -p "$DEST/$(dirname "$rel")"
  cp "$f" "$DEST/$rel"
  count=$((count + 1))
done < <(find "$SRC" -name "*.mdx" -print0)

echo "[sync-docs] synced $count files to $DEST"
