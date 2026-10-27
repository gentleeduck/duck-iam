#!/usr/bin/env bash
# Which published versions of a package contain a pattern, read from the npm tarballs themselves.
#
#   bun run advisory:probe -- @gentleduck/auth 'aal: 2' dist/providers/saml
#   bun run advisory:probe -- @gentleduck/iam "x-user-id" dist 1.1.1 2.0.1 3.0.1
#
# An advisory's range is a claim about what consumers installed, and git history answers a different
# question: a commit can sit on main for days before a release carries it, and a release can skip a version
# number. So this reads the published `dist/` instead. With no versions given it probes every one.
#
# Each tarball is unpacked into its own empty directory and only ever read with grep: nothing inside it is run.
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: advisory-probe.sh <package> <pattern> [subpath=dist] [version...]" >&2
  exit 2
fi

PKG="$1"
PATTERN="$2"
SUBPATH="${3:-dist}"
shift $(( $# >= 3 ? 3 : 2 ))

if [[ $# -gt 0 ]]; then
  VERSIONS=("$@")
else
  # npm prints a JSON array; one version per line without jq, and without mapfile, which macOS's bash 3.2 lacks.
  VERSIONS=()
  while IFS= read -r line; do VERSIONS+=("$line"); done < <(npm view "$PKG" versions --json | tr -d '[]", ' | grep -v '^$')
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/advisory-probe.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

printf '%-10s %6s  %s\n' version hits "first match in $SUBPATH"
for v in "${VERSIONS[@]}"; do
  dir="$WORK/$v"
  mkdir -p "$dir"
  if ! (cd "$dir" && npm pack "$PKG@$v" --silent >/dev/null 2>&1 && tar xzf ./*.tgz); then
    printf '%-10s %6s  %s\n' "$v" '-' 'could not fetch'
    continue
  fi
  target="$dir/package/$SUBPATH"
  if [[ ! -e "$target" ]]; then
    printf '%-10s %6s  %s\n' "$v" 0 "($SUBPATH absent)"
    continue
  fi
  # grep exits 1 on no match, which pipefail would turn into an abort on the first version that is clean.
  hits=$( (grep -rF -- "$PATTERN" "$target" 2>/dev/null || true) | wc -l | tr -d ' ')
  first=$( (grep -rlF -- "$PATTERN" "$target" 2>/dev/null || true) | head -1 | sed "s|^$dir/package/||")
  printf '%-10s %6s  %s\n' "$v" "$hits" "${first:-}"
done
