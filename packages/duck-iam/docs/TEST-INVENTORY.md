# duck-iam — Test Inventory

Every test file in `packages/duck-iam/src`, grouped by resource, with what
each one pins down. Modeled on duck-auth's `docs/superpowers/AUDIT-LIST.md`
resource-table format, adapted for a straight test catalog instead of an
audit-status tracker.

**This is a snapshot, not generated.** Counts were captured via
`bunx vitest run --reporter=json` on 2026-08-28 (63 files, 1340 tests, all
passing). Re-run that command and update this file by hand when test files
are added, removed, or grow meaningfully — there is no `bun run` script that
regenerates it (unlike duck-auth's `FINDINGS.md`, which is script-generated).

---

## How to read this

| Column | Meaning |
|---|---|
| File | Path under `src/`, relative |
| Tests | Assertion/`it`-count from the vitest JSON reporter (`it.each` rows count individually) |
| Covers | The file's top-level `describe(...)` string, i.e. what it says it's testing |

---

## Adapters — `src/adapters/`

Every backend an `IamEngine` can load roles/policies/subjects from.

| File | Tests | Covers |
|---|---|---|
| `adapters/drizzle/__tests__/drizzle.test.ts` | 54 | `IamDrizzleAdapter` |
| `adapters/drizzle/__tests__/drizzle-assignment-expiry-attributes.test.ts` | 27 | `IamDrizzleAdapter` assignment expiry |
| `adapters/drizzle/__tests__/drizzle-native-attr-shape.test.ts` | 8 | `IamDrizzleAdapter` native JSONB shape validation |
| `adapters/drizzle/__tests__/drizzle-update-assignment-scope.test.ts` | 6 | `IamDrizzleAdapter.updateAssignmentScope` |
| `adapters/file/__tests__/file.test.ts` | 47 | `IamFileAdapter` |
| `adapters/file/__tests__/file-malformed-payload.test.ts` | 15 | `IamFileAdapter` malformed assignments/attributes |
| `adapters/http/__tests__/http.test.ts` | 57 | `IamHttpAdapter` |
| `adapters/http/__tests__/http-subject-shape.test.ts` | 18 | `IamHttpAdapter` subject-data shape validation |
| `adapters/http/__tests__/http-error-body-cap.test.ts` | 6 | `IamHttpAdapter` error body cap |
| `adapters/memory/__tests__/memory.test.ts` | 42 | `IamMemoryAdapter` |
| `adapters/memory/__tests__/memory-input-shape.test.ts` | 8 | `IamMemoryAdapter` direct-call input shape |
| `adapters/prisma/__tests__/prisma.test.ts` | 42 | `IamPrismaAdapter` |
| `adapters/prisma/__tests__/prisma-attribute-corruption.test.ts` | 10 | `IamPrismaAdapter` attribute corruption defense |
| `adapters/redis/__tests__/redis.test.ts` | 68 | `IamRedisAdapter` |
| **Subtotal** | **408** | |

## Clients — `src/client/`

Framework bindings that call an engine from the frontend.

| File | Tests | Covers |
|---|---|---|
| `client/react/__tests__/react.test.ts` | 16 | `createIamAccessControl` |
| `client/vanilla/__tests__/vanilla.test.ts` | 17 | `IamAccessClient` |
| `client/vue/__tests__/vue.test.ts` | 14 | `createIamVueAccess` / `createAccessState` |
| **Subtotal** | **47** | |

## Core — `src/core/`

### Top-level

| File | Tests | Covers |
|---|---|---|
| `core/__tests__/integration.test.ts` | 9 | End-to-end: `config -> engine -> evaluate` |

### `core/builder/` — fluent policy/condition builders

| File | Tests | Covers |
|---|---|---|
| `core/builder/__tests__/builder.test.ts` | 52 | `When` (condition builder) + policy/rule builders |

### `core/conditions/` — condition-group evaluation, operators

| File | Tests | Covers |
|---|---|---|
| `core/conditions/__tests__/conditions.test.ts` | 44 | Condition operators (`eq`,`in`,`matches`, etc.) |
| `core/conditions/__tests__/conditions-scalar-narrowing.test.ts` | 15 | Scalar-type narrowing across operators |
| `core/conditions/__tests__/conditions-temporal.test.ts` | 6 | Temporal operators: `after`/`before` |

### `core/config/` — top-level `createIam()` factory

| File | Tests | Covers |
|---|---|---|
| `core/config/__tests__/config.test.ts` | 12 | `createIam()` |

### `core/engine/` — `IamEngine`, its interpreter path, and lifecycle

| File | Tests | Covers |
|---|---|---|
| `core/engine/__tests__/engine.test.ts` | 86 | `Engine.can()` — basic RBAC + the full public surface |
| `core/engine/__tests__/engine-admin-input-validation.test.ts` | 21 | `engine.admin` input validation |
| `core/engine/__tests__/engine.loaders.test.ts` | 16 | `loadPolicies`/`loadRoles`/single-flight loaders |
| `core/engine/__tests__/engine.libs.enrich-scope.test.ts` | 15 | `enrichSubjectWithScopedRoles` |
| `core/engine/__tests__/engine.invalidation.test.ts` | 12 | `invalidateAll`/`invalidateRoles`/`invalidatePolicies` |
| `core/engine/__tests__/engine.lifecycle.test.ts` | 10 | `runHealthCheck`, `preloadEngine`, invalidator disposal |
| `core/engine/__tests__/engine-import-error-cap.test.ts` | 8 | `engine.admin.import` schemaVersion error interpolation cap |
| `core/engine/__tests__/engine.hooks.test.ts` | 7 | `safeHookCall` |
| `core/engine/__tests__/engine-subject-roles-type-confusion.test.ts` | 5 | Subject `.roles` type-confusion defense |
| `core/engine/__tests__/engine.stats.test.ts` | 5 | `statsSnapshot`/`resetStats` |
| `core/engine/__tests__/engine-temporal-now.test.ts` | 4 | Engine auto-injects `environment.now` for temporal policies |
| **Subtotal** | **189** | |

### `core/engine/compiled/` — the compiled permission table (production mode's sole evaluator)

Rewritten this session: flat RBAC/ABAC classification (`CONST_ALLOW`/
`CONST_DENY`/`DYNAMIC` per cell) + an independent `rbacVote()` + residual
(targeted/wildcard/scoped/conditioned) policies evaluated per-request. No
opt-in flag, no interpreter fallthrough — `mode: 'production'` always uses
this path. See `docs/engine-rewrite.md`'s "What actually shipped" section
for the full design history and the bugs found/fixed getting here.

| File | Tests | Covers |
|---|---|---|
| `compiled/__tests__/compiled.engine-wiring.test.ts` | 13 | `IamEngine` wired to the compiled table: production/development parity, `'and'`-mode soundness, mixed simple+residual RBAC regression, >32-role fail-closed, stale-in-flight-table-after-invalidation regression, RBAC-abstain-on-throw regression, invalidation rebuild |
| `compiled/__tests__/compiled.dynamic.test.ts` | 26 | `compileTable`: `DYNAMIC` cells (real ABAC conditions) |
| `compiled/__tests__/compiled.differential.test.ts` | 23 | Differential: `lookup()` vs `evaluate()` oracle, `isWildcard` fix, mixed simple+residual RBAC (Finding 1 regression) |
| `compiled/__tests__/compiled.compile.test.ts` | 21 | `compileTable`: basic cell classification, RBAC-residual routing, role-count limit (32), `hasFlatSource`/`hasRbacSource` bookkeeping |
| `compiled/__tests__/compiled.boundary.test.ts` | 20 | Boundary role counts (0/1/32, bit-31 round-trip), the full fail-skip/abstain matrix (3 paths × presence × `defaultEffect`), per-instance cache isolation, concurrent-invalidation stress, `permissions()` parity |
| `compiled/__tests__/compiled.compile.test.ts` *(see above, not duplicated)* | — | — |
| `compiled/__tests__/compiled.lookup.test.ts` | 7 | `lookup()`: RBAC mask (fast path) + `CONST_ALLOW`/`CONST_DENY`, differential vs `evaluate()` |
| `compiled/__tests__/compiled.combine-invariance.test.ts` | 4 | `policyCombine` declaration-order invariance (policy/role array permutation); wildcard separator-boundary confirmation (`admin:*` vs `adminXban`, `org.*` vs `org-settings`) |
| `compiled/__tests__/compiled.property-fuzz.test.ts` | 1 | Property fuzz: production (compiled) vs development (interpreter) agree — 1 seeded test asserting **2240** comparisons across 160 randomized role/policy/subject/request configurations |
| **Subtotal** | **115** | |

### `core/evaluate/` — the plain per-request interpreter (development mode; also the compiled path's oracle)

| File | Tests | Covers |
|---|---|---|
| `core/evaluate/__tests__/evaluate.test.ts` | 51 | `evaluatePolicy()` / `evaluate()` |
| `core/evaluate/__tests__/oracle.test.ts` | 6 | Property oracle: `evaluate()` == `evaluateFast()` |

### `core/explain/` — human-readable decision tracing

| File | Tests | Covers |
|---|---|---|
| `core/explain/__tests__/explain.test.ts` | 26 | `explain()` output, `escapeHtml` |

### `core/rbac/` — role → policy synthesis, inheritance

| File | Tests | Covers |
|---|---|---|
| `core/rbac/__tests__/rbac.test.ts` | 16 | `resolveEffectiveRoles()`, `rolesToPolicy()` |

### `core/resolve/` — field-path resolution, action/resource matching

| File | Tests | Covers |
|---|---|---|
| `core/resolve/__tests__/resolve.test.ts` | 39 | `resolve()`, `matchesAction`/`matchesResource`/`matchesResourceHierarchical` |

### `core/schema/` — JSON Schema export

| File | Tests | Covers |
|---|---|---|
| `core/schema/__tests__/policy.schema.test.ts` | 3 | `POLICY_JSON_SCHEMA` |

### `core/validate/` — policy/role structural validation

| File | Tests | Covers |
|---|---|---|
| `core/validate/__tests__/validate.test.ts` | 64 | `validateRoles()`/`validatePolicies()` |
| `core/validate/__tests__/validate-unreachable-target.test.ts` | 11 | `validatePolicy()` — unreachable targets |
| `core/validate/__tests__/validate-value-length.test.ts` | 8 | `validatePolicy` condition value length cap |

---

## Devtools — `src/dt/`

| File | Tests | Covers |
|---|---|---|
| `dt/__tests__/iam-devtools.test.tsx` | 8 | `IamDevtools` production guard |

## Invalidators — `src/invalidators/`

Cross-instance cache-invalidation transport.

| File | Tests | Covers |
|---|---|---|
| `invalidators/redis/__tests__/redis-invalidator.test.ts` | 19 | `createIamRedisInvalidator` |
| `invalidators/redis/__tests__/redis-invalidator-event-shape.test.ts` | 8 | Redis invalidator event-shape validation |

## Observability — `src/observability/`

| File | Tests | Covers |
|---|---|---|
| `observability/metrics/__tests__/metrics.test.ts` | 7 | `iamCreateMetricsAggregator` |

## Server integrations — `src/server/`

Framework middleware/decorators that call an engine from the backend.

| File | Tests | Covers |
|---|---|---|
| `server/http/…` *(see adapters/http above — HTTP adapter, not a server integration)* | — | — |
| `server/express/__tests__/express.test.ts` | 32 | `iamAccessMiddleware` (Express) |
| `server/hono/__tests__/hono.test.ts` | 28 | `iamAccessMiddleware` (Hono) |
| `server/next/__tests__/next.test.ts` | 28 | `withIamAccess` (Next.js) |
| `server/nest/__tests__/nest.test.ts` | 26 | `@IamAuthorize` decorator (NestJS) |
| `server/generic/__tests__/generic.test.ts` | 21 | `generateIamPermissionMap()` |
| `server/generic/__tests__/extract-environment-xff.test.ts` | 16 | `iamExtractEnvironment` XFF normalization |
| **Subtotal** | **151** | |

## Shared — `src/shared/`

| File | Tests | Covers |
|---|---|---|
| `shared/__tests__/cache.test.ts` | 18 | `IamLRUCache` |
| `shared/__tests__/keys.test.ts` | 8 | `iamBuildPermissionKey()` |

---

## Totals by area

| Area | Files | Tests |
|---|---|---|
| Adapters | 14 | 408 |
| Clients | 3 | 47 |
| Core (excl. compiled) | 20 | 421 |
| Core / compiled engine | 8 | 115 |
| Devtools | 1 | 8 |
| Invalidators | 2 | 27 |
| Observability | 1 | 7 |
| Server | 6 | 151 |
| Shared | 2 | 26 |
| **Total** | **63** (some files span two rows above by cross-reference) | **1340** |

Run `bun run test` from `packages/duck-iam/` to reproduce. For per-file
counts, `bunx vitest run --reporter=json` and read `testResults[].assertionResults.length`.
