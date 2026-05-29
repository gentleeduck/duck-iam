---
'@gentleduck/iam': minor
---

# @gentleduck/iam 3.1

Engine structure cleanup + adapter validation hardening.

## New exports

- **`parsePolicyRow` / `parseRoleRow`** from `@gentleduck/iam/core/validate`. Helpers for custom-adapter authors: take an `unknown` row, return the typed `AccessControl.IPolicy<...>` / `AccessControl.IRole<...>` when structurally valid, or `null` to drop the row. Replaces the pattern of calling `validatePolicy(row)` then casting `row as IPolicy<...>`.

## Internal refactors (no public API change)

- `engine.ts` split into five single-purpose modules under `core/engine/`:
  - `engine.invalidation.ts` - cross-instance + in-flight cache invalidation
  - `engine.loaders.ts` - cache-fronted loaders with single-flight coalescing + adapter timeout + max-row guards
  - `engine.hooks.ts` - safe hook calls + metrics emission with throw-swallowing
  - `engine.lifecycle.ts` - preload / health-check / dispose
  - `engine.stats.ts` - snapshot / reset / hit-rate aggregation
- File, Redis, Drizzle, and Prisma adapters now route every row-decode path through `parsePolicyRow` / `parseRoleRow` instead of bare `as` casts. Prisma's `listPolicies` / `getPolicy` / `listRoles` / `getRole` now actually validate before returning - this was a latent gap.
- `core/explain` is now lazy-loaded by `engine.explain()` via dynamic `import()`. Production-mode bundles drop the explain chunk entirely.

## Tests

- 50 new direct unit tests for the extracted engine helpers (invalidation, hooks, stats, lifecycle, loaders). The class-method shims are proved to delegate to the extracted free functions, not just rename.

## Documentation

- `AUDIT-RESULTS.md` checked in. 0 runtime advisories.
- The two reported workspace-level vulnerabilities affecting `@gentleduck/iam` are both in `role-acl` (a benchmark competitor in `devDependencies` only); never installed by consumers.

## Migration

None required. All changes are additive or internal.
