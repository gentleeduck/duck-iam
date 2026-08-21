#!/usr/bin/env bash
# OpenSSF Scorecard for this repository.
#
#   bun run scorecard                     full remote scan of the origin repo
#   bun run scorecard:local               offline scan, no token, file-based checks only
#   bun run scorecard -- --checks=SAST    one or more checks by name
#   bun run scorecard -- --format=json    machine-readable output
#
# Scorecard scores a REPOSITORY, not a package, so one score covers duck-auth and
# duck-iam together. There is no per-package score to produce.
set -euo pipefail

# Pinned by digest so a rerun measures the same thing. Refresh deliberately.
IMAGE="${SCORECARD_IMAGE:-gcr.io/openssf/scorecard@sha256:54c7ea4ddec6e3941887cb7933898c352f59e7f59e17a7a730f97ed348a8dfce}"
ROOT="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"

LOCAL=0
ARGS=()
for arg in "$@"; do
  case "$arg" in
    --local) LOCAL=1 ;;
    *) ARGS+=("$arg") ;;
  esac
done

command -v docker >/dev/null || { echo "scorecard: docker is required" >&2; exit 1; }

if [[ $LOCAL -eq 1 ]]; then
  # Snapshot rather than scan in place, for two reasons: Scorecard walks every file
  # and dies on the broken symlinks in node_modules, and an ignored file it can see
  # locally is not on GitHub, so scanning it reports findings the real score cannot
  # have. Tracked plus untracked-but-not-ignored is what a push would publish.
  SNAP="$(mktemp -d)"
  trap 'rm -rf "$SNAP"' EXIT
  # --ignore-failed-read: a staged deletion is still listed but no longer on disk.
  git -C "$ROOT" ls-files -z --cached --others --exclude-standard \
    | tar -cf - -C "$ROOT" --null --no-recursion --ignore-failed-read -T - 2>/dev/null \
    | tar -xf - -C "$SNAP"
  # mktemp -d is 0700 and the image does not run as root.
  chmod -R a+rX "$SNAP"
  exec docker run --rm -v "$SNAP:/repo:ro" "$IMAGE" --local /repo "${ARGS[@]+"${ARGS[@]}"}"
fi

# Most checks read the GitHub API: branch protection, review history, CI results.
TOKEN="${GITHUB_AUTH_TOKEN:-${GITHUB_TOKEN:-}}"
if [[ -z "$TOKEN" ]] && command -v gh >/dev/null; then
  TOKEN="$(gh auth token 2>/dev/null || true)"
fi
if [[ -z "$TOKEN" ]]; then
  echo "scorecard: no token. Set GITHUB_AUTH_TOKEN, or run 'gh auth login', or use --local." >&2
  exit 1
fi

REPO="${SCORECARD_REPO:-}"
if [[ -z "$REPO" ]]; then
  REMOTE="$(git -C "$ROOT" remote get-url origin)"
  REPO="github.com/$(echo "$REMOTE" | sed -E 's#^(git@github\.com:|https://github\.com/)##; s#\.git$##')"
fi

GITHUB_AUTH_TOKEN="$TOKEN" exec docker run --rm -e GITHUB_AUTH_TOKEN \
  "$IMAGE" --repo="$REPO" "${ARGS[@]+"${ARGS[@]}"}"
