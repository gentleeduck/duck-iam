#!/usr/bin/env bash
#
# Run both suites and record what each one actually executed.
#
# This exists because counting `it(` in the source undercounts duck-auth by 25%:
# the store-compliance matrices are registered by helpers in `src/test/`, which
# is not a test file, and `it.each` expands at runtime. `vitest list` is no help
# either - it reports 0 tests for a file `vitest run` executes 110 from. The
# only honest number is the one a run prints.
#
# Usage:
#   benchmark/scripts/run-suites.sh duck        # our three tiers
#   benchmark/scripts/run-suites.sh better <path-to-better-auth-checkout>
#   benchmark/scripts/run-suites.sh all   <path-to-better-auth-checkout>
#
# Writes logs and a summary to benchmark/out/.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$HERE/out"
PKG="$(cd "$HERE/.." && pwd)"
mkdir -p "$OUT"

# `Tests  4308 passed (4308)` -> 4308; the trailing total is the one to read,
# because the leading count omits skipped and failed.
summarise() {
  local log="$1" label="$2"
  local files tests
  files=$(grep -oE 'Test Files[[:space:]]+.*\(([0-9]+)\)' "$log" | tail -1 | grep -oE '\(([0-9]+)\)' | tr -d '()')
  tests=$(grep -oE 'Tests[[:space:]]+.*\(([0-9]+)\)' "$log" | tail -1 | grep -oE '\(([0-9]+)\)' | tr -d '()')
  local failed
  failed=$(grep -coE '[0-9]+ failed' "$log")
  printf '%-34s files=%-6s tests=%-6s failing_lines=%s\n' "$label" "${files:-?}" "${tests:-?}" "$failed"
}

# Add up every per-package vitest summary in a turbo log, and report failures
# separately rather than folding them into the pass count.
sum_turbo() {
  local log="$1"
  perl -ne '
    # Strip ANSI so the counts can be matched.
    s/\e\[[0-9;]*m//g;
    if (/^\s*(\S+):test:\s+Tests\s+(.*)\((\d+)\)\s*$/) {
      my ($pkg, $detail, $total) = ($1, $2, $3);
      $files_total += 0;
      $tests{$pkg} = $total;
      $failed{$pkg} = $1 if $detail =~ /(\d+)\s+failed/;
      $skipped{$pkg} = $1 if $detail =~ /(\d+)\s+skipped/;
    }
    if (/^\s*(\S+):test:\s+Test Files\s+(.*)\((\d+)\)\s*$/) {
      $files{$1} = $3;
    }
    END {
      my ($t, $f, $fl, $sk) = (0, 0, 0, 0);
      for my $p (sort keys %tests) {
        $t  += $tests{$p};
        $fl += $files{$p}   // 0;
        $f  += $failed{$p}  // 0;
        $sk += $skipped{$p} // 0;
        printf("  %-34s files=%-5s tests=%-6s failed=%s\n",
               $p, $files{$p} // "?", $tests{$p}, $failed{$p} // 0);
      }
      printf("  %-34s files=%-5s tests=%-6s failed=%s skipped=%s\n",
             "TOTAL", $fl, $t, $f, $sk);
    }
  ' "$log"
}

run_duck() {
  echo "==> duck-auth unit + bun tier"
  (cd "$PKG" && bun run test) > "$OUT/duck-unit.log" 2>&1
  echo "    exit=$?"

  echo "==> duck-auth e2e tier (docker-backed; DUCKAUTH_E2E_REQUIRE=1 so an"
  echo "    unprovisioned backend fails instead of skipping)"
  (cd "$PKG" && DUCKAUTH_E2E_REQUIRE=1 bun run test:e2e) > "$OUT/duck-e2e.log" 2>&1
  echo "    exit=$?"

  {
    summarise "$OUT/duck-unit.log" "duck-auth unit (vitest)"
    # The bun tier prints `111 pass`, not a vitest summary.
    printf '%-34s %s\n' "duck-auth sqlite compliance (bun)" "$(grep -oE '^ *[0-9]+ pass' "$OUT/duck-unit.log" | tail -1 | tr -s ' ')"
    summarise "$OUT/duck-e2e.log" "duck-auth e2e (vitest)"
  } | tee "$OUT/duck-summary.txt"
}

run_better() {
  local SRC="${1:?pass the better-auth checkout path}"
  if [ ! -d "$SRC/packages/better-auth" ]; then
    echo "!! $SRC does not look like a better-auth checkout" >&2
    return 1
  fi

  # A third-party checkout: read and run it in place, never from inside our tree,
  # and never import anything out of it into our own test process.
  echo "==> better-auth unit tier ($SRC)"
  (cd "$SRC" && pnpm test) > "$OUT/ba-unit.log" 2>&1
  echo "    exit=$?"

  # turbo runs one vitest per package, so there is a summary block per package
  # and the totals have to be added up rather than read off the last one.
  sum_turbo "$OUT/ba-unit.log" | tee "$OUT/ba-summary.txt"
  echo "    NOTE: better-auth's e2e/adapter tier needs its own docker-compose stack"
  echo "    (postgres x4, mysql x3, mssql, mongo, redis) on fixed host ports; see"
  echo "    docker-compose.yml in the checkout. Not started by this script."
}

case "${1:-}" in
  duck) run_duck ;;
  better) run_better "${2:-}" ;;
  all)
    run_duck
    run_better "${2:-}"
    ;;
  *)
    echo "usage: $0 {duck|better <path>|all <path>}" >&2
    exit 2
    ;;
esac
