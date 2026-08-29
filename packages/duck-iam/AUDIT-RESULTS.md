# Dependency Audit - `@gentleduck/iam`

Run date: 2026-08-29
Tool: `bun audit`

## Result

The workspace currently reports 44 vulnerabilities, but only two dev-only
advisory chains resolve through `@gentleduck/iam` itself:

| Advisory | Severity | Path | Affects runtime? |
|---|---|---|---|
| GHSA-q8mj-m7cp-5q26 (qs DoS) | moderate | `@stryker-mutator/core` → `qs` (mutation testing) | **No** |
| GHSA-7p8r-x3mc-p8w7, GHSA-v2hh-gcrm-f6hx, GHSA-4c8g-83qw-93j6 (fast-uri host confusion) | high ×3 | `@stryker-mutator/core` → `fast-uri` (mutation testing) | **No** |

Both chains are dev-only, through `@stryker-mutator/core` (mutation
testing, `bun run mutation`) — a `devDependencies` entry never installed by
a consumer of `@gentleduck/iam`.

The `role-acl` / `jsonpath-plus` RCE advisories flagged in the previous run
of this doc (GHSA-pppg-cpfq-h7wr, GHSA-hw8r-x6gr-5gjp) no longer apply:
`role-acl` (the benchmark competitor that pulled them in) has since been
removed from `scripts/benchmark.ts` and `devDependencies` entirely.

The remaining ~40 advisories are workspace-wide (js-yaml, nanoid, postcss,
next, sharp, dompurify, better-auth, etc.). They affect other workspace
packages and apps (docs site, examples, duck-auth-demo); none touch
`@gentleduck/iam`'s dependency graph. Run `bun audit` from the repo root
for the full breakdown — there is currently no equivalent per-package
audit doc for `duck-auth` to cross-reference.

## How to re-run

```bash
bun audit
```

## Refresh cadence

No fixed cadence is enforced; re-run before each release and whenever
`devDependencies` changes materially (as happened here — `role-acl`'s
removal alone flipped the two headline advisories).
