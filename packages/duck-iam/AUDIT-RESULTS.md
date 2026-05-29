# Dependency Audit - `@gentleduck/iam`

Run date: 2026-05-29
Tool: `bun audit` (bun 1.3.10)

## Result

7 workspace-level vulnerabilities. The two that touch `@gentleduck/iam`
are both in `role-acl`, a **benchmark competitor** loaded only by
`packages/duck-iam/scripts/benchmark.ts` (see `vitest bench`):

| Advisory | Severity | Path | Affects runtime? |
|---|---|---|---|
| GHSA-pppg-cpfq-h7wr (jsonpath-plus RCE) | critical | `role-acl` → `jsonpath-plus` (benchmark only) | **No** |
| GHSA-hw8r-x6gr-5gjp (jsonpath-plus RCE 2) | high | same | **No** |
| GHSA-q8mj-m7cp-5q26 (qs DoS) | moderate | `@stryker-mutator/core` (mutation testing) | **No** |

The benchmark dependency is dev-only and is **never installed by a
consumer of `@gentleduck/iam`** — it's a tooling-only entry in
`devDependencies`.

The remaining advisories are workspace-wide (vite, postcss, esbuild,
storybook, uuid). They affect the duck-auth-demo app, the docs site,
and the examples; none affect the runtime path of `@gentleduck/iam`
itself. See `packages/duck-auth/AUDIT-RESULTS.md` for the full
workspace-level breakdown.

## How to re-run

```bash
bun audit
```

## Refresh cadence

Same as the workspace policy in `packages/duck-auth/AUDIT-RESULTS.md`.
