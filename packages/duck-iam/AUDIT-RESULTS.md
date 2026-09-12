# Dependency Audit - `@gentleduck/iam`

Tool: `bun audit`

A dependency audit is a point-in-time record. Every section below is dated and
describes the run it names, not today. Re-run before relying on any of it.

## Run of 2026-09-07 (bun 1.3.10)

The workspace reported **22 vulnerabilities** (10 high, 10 moderate, 2 low).
Two dev-only advisory chains resolve through `@gentleduck/iam` itself, both
through `@stryker-mutator/core`:

| Advisory | Severity | Path | Affects runtime? |
|---|---|---|---|
| GHSA-x5fp-wj9c-mxmx (array-limit bypass via bracket-key comma parsing), GHSA-4mjr-xmp4-gh2g (DoS via attacker-controlled `isBuffer`) | moderate x2 | `@stryker-mutator/core` -> `qs` | **No** |
| GHSA-f65p-4m7j-42xc, GHSA-fph4-wmhf-6fwf (SSRF), GHSA-jqff-g426-hqxp, GHSA-7p8r-x3mc-p8w7, GHSA-v2hh-gcrm-f6hx, GHSA-4c8g-83qw-93j6 (host confusion) | high x6 | `@stryker-mutator/core` -> `fast-uri` | **No** |

A third dev-only chain reaches `@gentleduck/iam` transitively and was not called
out on 2026-08-29: `@gentleduck/vitest-config` (a `workspace:*` devDependency of
this package) -> `@vitest/ui` -> `fflate`, GHSA-px8p-9vwx-vf98, moderate,
infinite loop on malformed ZIP64 archives. `bun audit` attributes it to the
`@gentleduck/vitest-config` workspace rather than to `@gentleduck/iam`, which is
why a per-workspace reading of the output misses it.

The rest are workspace-wide (browserslist, dompurify, undici, shell-quote,
`@tiptap/core`, esbuild, `@simplewebauthn/server`) and reach other workspace
packages and apps: the docs site, the examples, `@gentleduck/auth`, and
duck-auth-demo.

### What moved since 2026-08-29

- Total count fell from 44 to 22.
- Both `qs` advisory ids changed. GHSA-q8mj-m7cp-5q26, the qs DoS named in the
  previous run, no longer appears; two different qs advisories took its place.
- `fast-uri` went from three advisories to six. The three named previously
  (GHSA-7p8r-x3mc-p8w7, GHSA-v2hh-gcrm-f6hx, GHSA-4c8g-83qw-93j6) are still
  listed, joined by GHSA-f65p-4m7j-42xc, GHSA-fph4-wmhf-6fwf and
  GHSA-jqff-g426-hqxp.
- The advisory *packages* touching `@gentleduck/iam` are unchanged: `qs` and
  `fast-uri`, both only through `@stryker-mutator/core`, both dev-only.

## Run of 2026-08-29

The workspace reported 44 vulnerabilities, but only two dev-only advisory
chains resolved through `@gentleduck/iam` itself:

| Advisory | Severity | Path | Affects runtime? |
|---|---|---|---|
| GHSA-q8mj-m7cp-5q26 (qs DoS) | moderate | `@stryker-mutator/core` → `qs` (mutation testing) | **No** |
| GHSA-7p8r-x3mc-p8w7, GHSA-v2hh-gcrm-f6hx, GHSA-4c8g-83qw-93j6 (fast-uri host confusion) | high ×3 | `@stryker-mutator/core` → `fast-uri` (mutation testing) | **No** |

Both chains are dev-only, through `@stryker-mutator/core` (mutation
testing, `bun run mutation`) — a `devDependencies` entry never installed by
a consumer of `@gentleduck/iam`.

The `role-acl` / `jsonpath-plus` RCE advisories flagged in the run before
that (GHSA-pppg-cpfq-h7wr, GHSA-hw8r-x6gr-5gjp) no longer apply:
`role-acl` (the benchmark competitor that pulled them in) has since been
removed from `scripts/benchmark.ts` and `devDependencies` entirely.

The remaining ~40 advisories were workspace-wide (js-yaml, nanoid, postcss,
next, sharp, dompurify, better-auth, etc.), affecting other workspace packages
and apps (docs site, examples, duck-auth-demo). This run recorded that none of
them touched `@gentleduck/iam`'s dependency graph; the 2026-09-07 run above
found the `@gentleduck/vitest-config` -> `@vitest/ui` -> `fflate` chain, which
does. There is still no equivalent per-package audit doc for `duck-auth` to
cross-reference.

## How to re-run

```bash
bun audit
```

## Refresh cadence

No fixed cadence is enforced; re-run before each release and whenever
`devDependencies` changes materially (as happened here — `role-acl`'s
removal alone flipped the two headline advisories).

Record each run as a new dated section rather than editing an existing one. The
advisory set moves under a fixed dependency tree - between 2026-08-29 and
2026-09-07 nothing in `@gentleduck/iam`'s dependencies changed, and both `qs`
advisory ids still turned over - so a silently refreshed number destroys the
only thing the record is good for.
