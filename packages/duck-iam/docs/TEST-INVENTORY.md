# duck-iam — Test Inventory

Every test file in `packages/duck-iam/src`, grouped by area, with what each
one pins down.

**This file is generated.** Do not edit it by hand - run
`bun run gen:test-inventory` from `packages/duck-iam/`. The suite fails if it
is stale (`src/__tests__/test-inventory-freshness.test.ts`), so it cannot
drift the way the hand-maintained version did.

| Column | Meaning |
|---|---|
| File | Path under `src/`, relative |
| Tests | Assertion count from the vitest JSON reporter (`it.each` rows count individually) |
| Covers | The file's first top-level `describe(...)` string |

---

## Core / compiled engine

| File | Tests | Covers |
|---|---|---|
| `core/engine/compiled/__tests__/compiled-interpreter-parity.test.ts` | 10 | compiled table / interpreter parity (round 13) |
| `core/engine/compiled/__tests__/compiled.boundary.test.ts` | 17 | boundary: 0 roles - no RBAC source at all |
| `core/engine/compiled/__tests__/compiled.combine-invariance.test.ts` | 4 | wildcard action/resource patterns are separator-bound, not raw substring prefixes (confirmation) |
| `core/engine/compiled/__tests__/compiled.compile.test.ts` | 27 | compileTable: basic classification |
| `core/engine/compiled/__tests__/compiled.differential.test.ts` | 25 | differential: isWildcard fix - action/resource prefix patterns are not silently inert |
| `core/engine/compiled/__tests__/compiled.dynamic.test.ts` | 27 | compileTable: DYNAMIC cells |
| `core/engine/compiled/__tests__/compiled.engine-wiring.test.ts` | 11 | production mode: 'and'-mode soundness - an irrelevant untargeted policy no longer vetoes a role grant |
| `core/engine/compiled/__tests__/compiled.lookup-sources.test.ts` | 15 | a wildcarded role permission grants only through `rbacResidual` |
| `core/engine/compiled/__tests__/compiled.lookup.test.ts` | 12 | lookup: RBAC mask (fast path) + CONST_ALLOW + CONST_DENY, differential vs evaluate() |
| `core/engine/compiled/__tests__/compiled.property-fuzz.test.ts` | 1 | property fuzz: production (compiled table) vs development (interpreter) agree |
| **Subtotal** | **149** | |

---

## Adapters

| File | Tests | Covers |
|---|---|---|
| `adapters/__tests__/adapter-contract-parity.test.ts` | 58 | assignRole options are refused, not discarded |
| `adapters/__tests__/attributes-caller-isolation.test.ts` | 20 | the file adapter’s copy survives a reopen |
| `adapters/__tests__/e2e-adapter-drizzle-pg.e2e.test.ts` | 129 | E2E harness reachability (drizzle/pg) |
| `adapters/__tests__/e2e-adapter-prisma-pg.e2e.test.ts` | 94 | E2E harness reachability (prisma/pg) |
| `adapters/__tests__/e2e-adapter-redis.e2e.test.ts` | 82 | E2E harness reachability (redis) |
| `adapters/__tests__/optional-method-matrix.test.ts` | 8 | the optional-method support matrix is what the adapters actually implement |
| `adapters/__tests__/role-id-reuse-resurrection.test.ts` | 12 |  |
| `adapters/__tests__/rows-caller-isolation.test.ts` | 14 | memory: a seeded row is not the caller object either |
| `adapters/__tests__/save-time-validation.test.ts` | 19 | every adapter refuses to save a row its reads would drop |
| `adapters/drizzle/__tests__/drizzle-actor-provenance.test.ts` | 11 | assignRole records who made the grant |
| `adapters/drizzle/__tests__/drizzle-assignment-expiry-attributes.test.ts` | 54 | IamDrizzleAdapter assignment expiry |
| `adapters/drizzle/__tests__/drizzle-native-attr-shape.test.ts` | 13 | IamDrizzleAdapter native JSONB shape validation |
| `adapters/drizzle/__tests__/drizzle-sqlite-real-engine.test.ts` | 9 | drizzle sqlite dialect, against a real SQLite engine |
| `adapters/drizzle/__tests__/drizzle-update-assignment-scope.test.ts` | 6 | IamDrizzleAdapter.updateAssignmentScope |
| `adapters/drizzle/__tests__/drizzle.test.ts` | 230 | IamDrizzleAdapter |
| `adapters/drizzle/__tests__/ops-wiring-types.test.ts` | 3 | drizzle-orm operators satisfy the adapter ops bundle as-is |
| `adapters/drizzle/__tests__/schema-parity.test.ts` | 33 | the dialect-only allow-list stays honest |
| `adapters/drizzle/__tests__/with-client.test.ts` | 5 | IamAdapter.withClient |
| `adapters/file/__tests__/file-atomic-write.test.ts` | 7 | file adapter writes atomically when the driver supports rename |
| `adapters/file/__tests__/file-containment-window.test.ts` | 3 | file adapter containment is checked on a cache miss and on every write |
| `adapters/file/__tests__/file-corrupt-assignments.test.ts` | 16 | file adapter: a malformed assignments row fails closed |
| `adapters/file/__tests__/file-corrupt-attributes-persist.test.ts` | 3 | file adapter: a corrupt attributes row survives a flush |
| `adapters/file/__tests__/file-failed-write-cache.test.ts` | 5 | a write the store refused leaves no grant behind |
| `adapters/file/__tests__/file-input-shape.test.ts` | 3 | IamFileAdapter direct-call input shape |
| `adapters/file/__tests__/file-io-failure.test.ts` | 5 | IamFileAdapter I/O failure handling |
| `adapters/file/__tests__/file-malformed-payload.test.ts` | 21 | IamFileAdapter malformed assignments/attributes |
| `adapters/file/__tests__/file-rootdir-warn.test.ts` | 5 | the missing-rootDir warning, against a module whose latch has not fired |
| `adapters/file/__tests__/file.test.ts` | 111 | IamFileAdapter |
| `adapters/http/__tests__/http-compliance.test.ts` | 75 |  |
| `adapters/http/__tests__/http-config-numbers.test.ts` | 13 | a numeric option that would disable what it configures is refused |
| `adapters/http/__tests__/http-empty-body.test.ts` | 8 | a bodiless success is not a parse error |
| `adapters/http/__tests__/http-error-body-cap.test.ts` | 6 | IamHttpAdapter error body cap |
| `adapters/http/__tests__/http-input-shape.test.ts` | 1 | IamHttpAdapter direct-call input shape |
| `adapters/http/__tests__/http-io-failure.test.ts` | 15 | IamHttpAdapter I/O failure handling |
| `adapters/http/__tests__/http-malformed-row.test.ts` | 5 | IamHttpAdapter refuses malformed policy rows and drops malformed role rows |
| `adapters/http/__tests__/http-path-segments.test.ts` | 13 | http adapter builds path segments safely |
| `adapters/http/__tests__/http-subject-shape.test.ts` | 18 | IamHttpAdapter subject-data shape validation |
| `adapters/http/__tests__/http-timeout-timer.test.ts` | 2 | IamHttpAdapter per-request timeout timer |
| `adapters/http/__tests__/http.test.ts` | 61 | IamHttpAdapter |
| `adapters/memory/__tests__/memory-input-shape.test.ts` | 8 | IamMemoryAdapter direct-call input shape |
| `adapters/memory/__tests__/memory-seed-parity.test.ts` | 11 | the memory adapter seed agrees with the equivalent write |
| `adapters/memory/__tests__/memory.test.ts` | 107 | IamMemoryAdapter |
| `adapters/prisma/__tests__/prisma-actor-provenance.test.ts` | 3 | prisma definition writes record their author |
| `adapters/prisma/__tests__/prisma-attribute-corruption.test.ts` | 18 | IamPrismaAdapter attribute corruption defense |
| `adapters/prisma/__tests__/prisma-malformed-row-drop.test.ts` | 9 | IamPrismaAdapter malformed-row handling |
| `adapters/prisma/__tests__/prisma-null-scope-rows.test.ts` | 4 | prisma getSubjectScopedRoles |
| `adapters/prisma/__tests__/prisma-unreadable-role.test.ts` | 6 | prisma names a role row it cannot read |
| `adapters/prisma/__tests__/prisma-update-assignment-scope.test.ts` | 12 | IamPrismaAdapter.updateAssignmentScope |
| `adapters/prisma/__tests__/prisma-with-client.test.ts` | 4 | IamPrismaAdapter.withClient rebinds writes onto the given client |
| `adapters/prisma/__tests__/prisma.test.ts` | 119 | IamPrismaAdapter |
| `adapters/redis/__tests__/redis-attributes-merge.test.ts` | 6 | redis setSubjectAttributes distinguishes corruption from a failed read |
| `adapters/redis/__tests__/redis-input-shape.test.ts` | 5 | IamRedisAdapter direct-call input shape |
| `adapters/redis/__tests__/redis-io-failure.test.ts` | 8 | IamRedisAdapter connection failure |
| `adapters/redis/__tests__/redis-legacy-migration-optin.test.ts` | 8 | redis legacy assignment migration is opt-in |
| `adapters/redis/__tests__/redis-mutation-survivors.test.ts` | 18 | M-1: the legacy-encoding heuristic |
| `adapters/redis/__tests__/redis.test.ts` | 127 | IamRedisAdapter |
| **Subtotal** | **1669** | |

---

## Clients

| File | Tests | Covers |
|---|---|---|
| `client/__tests__/client-parity.test.ts` | 33 | the three clients answer the same map identically |
| `client/react/__tests__/react-shared-and-stale-closures.test.ts` | 7 | the loading placeholder is not shared writable state |
| `client/react/__tests__/react-use-permissions-stale.test.ts` | 6 | usePermissions does not serve a previous subject |
| `client/react/__tests__/react.test.ts` | 22 | createIamAccessControl |
| `client/vanilla/__tests__/vanilla-fail-closed.test.ts` | 11 | vanilla client: a non-boolean map value denies |
| `client/vanilla/__tests__/vanilla-map-ownership.test.ts` | 4 | the client owns its permission map |
| `client/vanilla/__tests__/vanilla-partial-map.test.ts` | 2 | IamAccessClient partial permission map |
| `client/vanilla/__tests__/vanilla.test.ts` | 31 | IamAccessClient |
| `client/vue/__tests__/vue-partial-map.test.ts` | 1 | createIamVueAccess partial permission map |
| `client/vue/__tests__/vue-reactivity-triggers.test.ts` | 5 | every vue state change the client makes is one a real ref would notify on |
| `client/vue/__tests__/vue.test.ts` | 14 | createIamVueAccess - createAccessState |
| **Subtotal** | **136** | |

---

## Core

| File | Tests | Covers |
|---|---|---|
| `core/__tests__/integration.test.ts` | 9 | Integration: config -> engine -> evaluate |
| `core/__tests__/policy-error-handler-shapes.test.ts` | 6 | the evaluator hands its handler the policy object |
| `core/batch/__tests__/credit-writes.test.ts` | 9 | creditWrites |
| `core/batch/__tests__/loop-fallback.test.ts` | 6 | loopFallback |
| `core/builder/__tests__/builder-authoring-hazards.test.ts` | 23 | a condition callback that returns a different builder |
| `core/builder/__tests__/builder-composition-and-aliasing.test.ts` | 18 | RuleBuilder: repeated condition groups |
| `core/builder/__tests__/builder-fuzz-authoring.test.ts` | 2 | a random condition tree means the same thing to everyone who reads it |
| `core/builder/__tests__/builder.test.ts` | 72 | When (condition builder) |
| `core/builder/__tests__/e2e-builder-round-trip.e2e.test.ts` | 15 |  |
| `core/builder/__tests__/guide-abac-examples.test.ts` | 9 | guide §4: post-owner policy |
| `core/builder/__tests__/inherits-replaces.test.ts` | 4 | RoleBuilder.inherits replaces |
| `core/builder/__tests__/rule-untouched-refusal.test.ts` | 16 | RuleBuilder refuses an untouched builder |
| `core/conditions/__tests__/conditions-polynomial-redos.test.ts` | 19 | detectCatastrophicRegex: adjacent unbounded quantifiers |
| `core/conditions/__tests__/conditions-scalar-narrowing.test.ts` | 16 | condition ops Scalar narrowing |
| `core/conditions/__tests__/conditions-temporal.test.ts` | 8 | temporal operators: after / before |
| `core/conditions/__tests__/conditions.test.ts` | 57 | condition operators |
| `core/conditions/__tests__/dangling-operand-reference.test.ts` | 9 | B-F1 a $-reference that resolves to nothing has no operand |
| `core/conditions/__tests__/inherited-operator-names.test.ts` | 43 | an inherited name is not an operator |
| `core/conditions/__tests__/matches-operand-type.test.ts` | 10 | `matches` is bound by the operand-type guard |
| `core/conditions/__tests__/matches-user-sourced-value.test.ts` | 13 | `matches` refuses a $-resolved pattern |
| `core/conditions/__tests__/redos-separated-quantifiers.test.ts` | 8 | unbounded quantifiers separated by characters they can match |
| `core/conditions/__tests__/regex-detector-false-positives.test.ts` | 20 | detectCatastrophicRegex accepts safe lookaround guards |
| `core/conditions/__tests__/regex-safety-agreement.test.ts` | 17 | regex safety: one predicate, two call sites |
| `core/conditions/__tests__/unrecognised-node.test.ts` | 9 | an unrecognised condition node does not read as "no conditions" |
| `core/config/__tests__/config.test.ts` | 18 | createIam() |
| `core/config/__tests__/declared-surface.test.ts` | 17 | createIam().validateRoles checks grants against the declared vocabulary |
| `core/engine/__tests__/adapter-interchangeability.test.ts` | 5 | the memory and file adapters |
| `core/engine/__tests__/admin-actor-provenance.test.ts` | 9 | every admin write tells the adapter who made it |
| `core/engine/__tests__/admin-adapter-timeout.test.ts` | 39 | adapterTimeoutMs bounds the admin facade, not only the decision path |
| `core/engine/__tests__/admin-star-scope.test.ts` | 7 | admin refuses a "*" scope on a grant |
| `core/engine/__tests__/admin-write-cache-coherence.test.ts` | 7 | a long-lived engine after every admin write |
| `core/engine/__tests__/admin.batch.test.ts` | 9 | IAdmin batch writes |
| `core/engine/__tests__/broken-adapter-fail-closed.test.ts` | 5 | a broken store read |
| `core/engine/__tests__/compile-failure-is-reported.test.ts` | 12 | a role count past the compiled table capacity falls back and says so |
| `core/engine/__tests__/decision-failure-discriminant.test.ts` | 6 | IDecision distinguishes a policy deny from a broken engine |
| `core/engine/__tests__/e2e-resilience-db-kill.e2e.test.ts` | 11 | E2E fail-closed: Postgres frozen (docker pause) mid-flight |
| `core/engine/__tests__/e2e-resilience-hooks.e2e.test.ts` | 18 | E2E fail-closed: a throwing hook |
| `core/engine/__tests__/e2e-resilience-net.e2e.test.ts` | 15 | E2E fail-closed: connection reset mid-flight |
| `core/engine/__tests__/e2e-resilience-redis.e2e.test.ts` | 6 | E2E fail-closed: the Redis the decision is READ from |
| `core/engine/__tests__/e2e-verdict-pg-fallback.e2e.test.ts` | 13 |  |
| `core/engine/__tests__/e2e-verdict-rbac-divergence.e2e.test.ts` | 4 | E2E verdict divergence: RBAC role permissions |
| `core/engine/__tests__/engine-admin-input-validation.test.ts` | 21 | engine.admin input validation |
| `core/engine/__tests__/engine-admin-reads.test.ts` | 8 | engine.admin readers return what was written |
| `core/engine/__tests__/engine-check-invalid-subject.test.ts` | 2 | engine.check() with an invalid subjectId |
| `core/engine/__tests__/engine-compiled-table-ttl.test.ts` | 12 |  |
| `core/engine/__tests__/engine-cross-scope-inheritance.test.ts` | 6 | Engine.can() - cross-scope role inheritance |
| `core/engine/__tests__/engine-eval-error-fails-closed.test.ts` | 10 |  |
| `core/engine/__tests__/engine-hook-timeout.test.ts` | 16 | a hook whose promise never settles does not hold the call open |
| `core/engine/__tests__/engine-import-error-cap.test.ts` | 8 | engine.admin.import schemaVersion error interpolation cap |
| `core/engine/__tests__/engine-permissions-key-collision.test.ts` | 1 | permissions() key collisions |
| `core/engine/__tests__/engine-priority-nonfinite.test.ts` | 28 |  |
| `core/engine/__tests__/engine-subject-load-shed.test.ts` | 7 | IamEngine constructor: maxConcurrentSubjectLoads validation |
| `core/engine/__tests__/engine-subject-roles-type-confusion.test.ts` | 5 | Engine subject.roles type-confusion defense |
| `core/engine/__tests__/engine-temporal-now.test.ts` | 4 | engine auto-injects environment.now for temporal policies |
| `core/engine/__tests__/engine.bound.test.ts` | 12 | IamEngine.withTransaction |
| `core/engine/__tests__/engine.factory.test.ts` | 3 | iamEngine factory |
| `core/engine/__tests__/engine.hooks.test.ts` | 7 | safeHookCall |
| `core/engine/__tests__/engine.invalidation.test.ts` | 15 | invalidateAll |
| `core/engine/__tests__/engine.libs.enrich-scope.test.ts` | 19 | enrichSubjectWithScopedRoles |
| `core/engine/__tests__/engine.libs.test.ts` | 27 | ensureEnvNow |
| `core/engine/__tests__/engine.lifecycle.test.ts` | 10 | runHealthCheck |
| `core/engine/__tests__/engine.loaders.test.ts` | 23 | loadPolicies |
| `core/engine/__tests__/engine.mutation-events.test.ts` | 13 | engine.admin emits a mutation event per write |
| `core/engine/__tests__/engine.production-hooks.test.ts` | 18 | afterEvaluate / onDeny fire in production too |
| `core/engine/__tests__/engine.stats.test.ts` | 5 | statsSnapshot |
| `core/engine/__tests__/engine.test.ts` | 86 | Engine.can() - basic RBAC |
| `core/engine/__tests__/failopen-metric-parity.test.ts` | 5 | failOpen metric: development and production agree |
| `core/engine/__tests__/grant-expiry-vs-cache.test.ts` | 13 | a grant that expires stops granting, whatever the cache thinks |
| `core/engine/__tests__/import-validates-before-write.test.ts` | 4 | admin.import validates the whole snapshot before writing |
| `core/engine/__tests__/invalidate-roles-inflight.test.ts` | 3 | invalidateRoles drops in-flight subject loads |
| `core/engine/__tests__/mode-config-guard.test.ts` | 17 | mode is checked at boot, like policyCombine |
| `core/engine/__tests__/mode-type-argument-does-not-set-mode.test.ts` | 3 | the mode type argument does not set the mode |
| `core/engine/__tests__/partial-batch-invalidation.test.ts` | 6 | a batch that fails part-way still settles the rows that landed |
| `core/engine/__tests__/permission-map-resource-attributes.test.ts` | 5 | a permission check and the instance it names |
| `core/engine/__tests__/policy-combine-validation.test.ts` | 11 | policyCombine validation |
| `core/engine/__tests__/preload-surfaces-compile-error.test.ts` | 6 |  |
| `core/engine/__tests__/preload-validates-storage.test.ts` | 9 | preload is the only check on rows the write path never saw |
| `core/engine/__tests__/role-created-after-subject-cached.test.ts` | 4 | a role created after a subject was cached |
| `core/engine/__tests__/role-limit-fallback-parity.test.ts` | 5 | the compiled table and the interpreter it falls back to |
| `core/engine/__tests__/role-limit-latch.test.ts` | 6 | the role-limit latch clears when the role set changes |
| `core/engine/__tests__/scope-config-guards.test.ts` | 14 | scopeMode and scopeCombine are checked at boot, like policyCombine |
| `core/engine/__tests__/scope-covers-contract.test.ts` | 45 | scopeCovers agrees with matchesScope on the flat axis |
| `core/engine/__tests__/subject-cache-vs-role-snapshot.test.ts` | 4 | a subject entry does not outlive the role snapshot it was resolved against |
| `core/engine/__tests__/surface-parity.test.ts` | 4 | every way of asking for a verdict |
| `core/engine/__tests__/transaction.pg.e2e.test.ts` | 17 |  |
| `core/engine/__tests__/two-node-convergence.test.ts` | 4 | two nodes on one store |
| `core/engine/__tests__/unevaluable-condition-group.test.ts` | 7 | a condition group nobody can evaluate does not retire the deny holding it |
| `core/engine/__tests__/unevaluated-deny-is-observed.test.ts` | 10 | a deny the engine returned without evaluating is still observed |
| `core/engine/__tests__/unified-verdict-path.test.ts` | 11 | development keeps the rich decision while the table supplies the verdict |
| `core/engine/__tests__/unvalidated-policy-operand.test.ts` | 12 | a policy that never passed the validator still cannot over-grant |
| `core/engine/__tests__/verdict-differential.test.ts` | 2 | E2E verdict parity: compiled table vs interpreter over generated catalogs |
| `core/evaluate/__tests__/algorithm-alias-precompute.test.ts` | 9 | precompute covers every algorithm that can be precomputed |
| `core/evaluate/__tests__/error-hook-isolation.test.ts` | 6 | a throwing onPolicyError does not unwind the evaluation |
| `core/evaluate/__tests__/evaluate-error-indeterminate.test.ts` | 15 | evaluate ('and') with a throwing deny policy |
| `core/evaluate/__tests__/evaluate-fast-caches.test.ts` | 2 |  |
| `core/evaluate/__tests__/evaluate-missing-conditions.test.ts` | 4 | indexPolicy with a rule missing `conditions` |
| `core/evaluate/__tests__/evaluate-priority-nonfinite.test.ts` | 22 | CONTROL: a finite priority still ranks |
| `core/evaluate/__tests__/evaluate-priority-tie-shuffle.test.ts` | 3 | equal-priority tie-break under shuffled rule order |
| `core/evaluate/__tests__/evaluate-priority-tie-source-order.test.ts` | 9 | priority ties resolve by source order on both evaluation paths |
| `core/evaluate/__tests__/evaluate.libs.test.ts` | 19 | ruleTargetsMatch() |
| `core/evaluate/__tests__/evaluate.test.ts` | 54 | evaluatePolicy() |
| `core/evaluate/__tests__/fail-open-optin-parity.test.ts` | 8 | fail-open opt-in is required by every public evaluator entry point |
| `core/evaluate/__tests__/failopen-signal.test.ts` | 39 | failOpen on an applicable policy whose rules all evaluated false |
| `core/evaluate/__tests__/fast-path-throwable-delegation.test.ts` | 6 | a policy that can throw is decided by the interpreter, whatever the fast path would have said |
| `core/evaluate/__tests__/first-applicable-rbac-order.test.ts` | 13 | a role grant no longer retires the operator’s deny |
| `core/evaluate/__tests__/first-applicable.test.ts` | 7 | first-applicable: an applicable policy that votes its default |
| `core/evaluate/__tests__/index-cache-and-nul-keys.test.ts` | 8 | indexPolicy memo tracks the rules array, not the policy object |
| `core/evaluate/__tests__/malformed-conditions-object.test.ts` | 43 | a condition group that is not an object |
| `core/evaluate/__tests__/oracle.test.ts` | 6 | property oracle: evaluate == evaluateFast |
| `core/evaluate/__tests__/priority-tie-parity.test.ts` | 16 | priority ties resolve identically in the interpreter and the fast path |
| `core/evaluate/__tests__/rbac-abstain-scope.test.ts` | 5 | only the generated RBAC union lets a throwing rule abstain |
| `core/evaluate/__tests__/resource-separator-parity.test.ts` | 50 | a resource pattern means the same thing everywhere |
| `core/evaluate/__tests__/unconditional-agreement.test.ts` | 47 | matchesUnconditionally agrees with evalConditionGroup |
| `core/evaluate/__tests__/unknown-algorithm.test.ts` | 6 | a policy with an unrecognised combining algorithm |
| `core/evaluate/__tests__/unknown-effect-fail-closed.test.ts` | 12 | an unrecognised rule effect is Indeterminate, never an abstention |
| `core/explain/__tests__/explain-agrees-with-the-decision.test.ts` | 13 | explain() agrees with the decision path |
| `core/explain/__tests__/explain-evaluate-parity.test.ts` | 30 |  |
| `core/explain/__tests__/explain-group-parity.test.ts` | 9 | a traced condition group agrees with the group the engine decided on |
| `core/explain/__tests__/explain-indeterminate-parity.test.ts` | 28 | explain() absorbs a throwing rule exactly as the decision path does |
| `core/explain/__tests__/explain-leaf-parity.test.ts` | 2 | a traced leaf agrees with the leaf the engine decided on |
| `core/explain/__tests__/explain-reserved-refusal-parity.test.ts` | 6 | explain() refuses the reserved token the way the decision path does |
| `core/explain/__tests__/explain.libs.test.ts` | 22 | tracePolicy() combining algorithms |
| `core/explain/__tests__/explain.test.ts` | 26 | iamEscapeHtml |
| `core/pending/__tests__/pending.test.ts` | 23 | createPending |
| `core/rbac/__tests__/e2e-scope-inheritance.e2e.test.ts` | 25 |  |
| `core/rbac/__tests__/e2e-scope-modes-and-order.e2e.test.ts` | 15 |  |
| `core/rbac/__tests__/e2e-scope-prod-parity.e2e.test.ts` | 12 |  |
| `core/rbac/__tests__/e2e-scope-tenant-isolation.e2e.test.ts` | 41 |  |
| `core/rbac/__tests__/inheritance-order-independence.test.ts` | 5 | inheritance resolution does not depend on the order of `inherits` |
| `core/rbac/__tests__/permission-condition-depth-parity.test.ts` | 19 | an `any` permission condition costs the same depth as an `all` one |
| `core/rbac/__tests__/rbac-scope-attribution.test.ts` | 6 | rolesToPolicy() scope attribution |
| `core/rbac/__tests__/rbac-scope-inheritance.test.ts` | 27 | a permission inherited across a scope boundary keeps its declarer scope |
| `core/rbac/__tests__/rbac.test.ts` | 25 | resolveEffectiveRoles() |
| `core/rbac/__tests__/role-declared-scope-hierarchy.test.ts` | 20 |  |
| `core/resolve/__tests__/empty-scope-contract.test.ts` | 16 | matchesScope treats an empty scope as a value, not a wildcard |
| `core/resolve/__tests__/resolve-attribute-value-contract.test.ts` | 19 | resolve() returns only values that conform to AttributeValue |
| `core/resolve/__tests__/resolve-own-properties.test.ts` | 21 | resolve reads own properties only |
| `core/resolve/__tests__/resolve.test.ts` | 43 | resolve() |
| `core/schema/__tests__/policy.schema.test.ts` | 8 | POLICY_JSON_SCHEMA |
| `core/schema/__tests__/schema-validator-agreement.test.ts` | 52 | the mini evaluator is able to fail |
| `core/types/__tests__/types.test.ts` | 4 | iamCreateEvalCaches() |
| `core/validate/__tests__/condition-depth-agreement.test.ts` | 22 | condition nesting limit agrees between validator and evaluator |
| `core/validate/__tests__/matches-pattern-agreement.test.ts` | 38 | a `matches` pattern the validator accepts compiles at evaluation time |
| `core/validate/__tests__/operand-type-matrix.test.ts` | 196 | operator x operand type |
| `core/validate/__tests__/policy-declared-vocabulary.test.ts` | 16 | a rule action outside the declared vocabulary |
| `core/validate/__tests__/policy-optional-field-types.test.ts` | 23 | policy.description |
| `core/validate/__tests__/policy-target-entry-types.test.ts` | 23 | a non-string target entry is what the engine cannot survive |
| `core/validate/__tests__/policy-targets-types.test.ts` | 22 | every key of targets is type-checked, not just the first two |
| `core/validate/__tests__/resolvable-path-parity.test.ts` | 12 | isResolvablePath agrees with resolve about what will not resolve |
| `core/validate/__tests__/role-grant-wildcards.test.ts` | 10 | a prefix grant the engine honours is not unreachable |
| `core/validate/__tests__/validate-boundary-robustness.test.ts` | 14 | validatePolicy never throws on a malformed rule row |
| `core/validate/__tests__/validate-control-chars.test.ts` | 28 | validatePolicy rejects control characters in action and resource names |
| `core/validate/__tests__/validate-operand.test.ts` | 29 | condition operand presence |
| `core/validate/__tests__/validate-role-permissions.test.ts` | 13 | validateRole: permission entry shape |
| `core/validate/__tests__/validate-role-scope.test.ts` | 9 | validateRole: role-level scope |
| `core/validate/__tests__/validate-roles-untrusted-input.test.ts` | 14 | validateRoles on input it does not trust |
| `core/validate/__tests__/validate-rows.test.ts` | 35 | parsePolicyRow() |
| `core/validate/__tests__/validate-rule-conditions.test.ts` | 4 | validateRuleShape - conditions |
| `core/validate/__tests__/validate-unknown-keys.test.ts` | 13 | unknown fields |
| `core/validate/__tests__/validate-unreachable-target.test.ts` | 12 | validatePolicy() - unreachable targets |
| `core/validate/__tests__/validate-value-length.test.ts` | 8 | validatePolicy condition value length cap |
| `core/validate/__tests__/validate.test.ts` | 64 | validateRoles() |
| **Subtotal** | **2743** | |

---

## Devtools

| File | Tests | Covers |
|---|---|---|
| `dt/__tests__/devtools-engine-contract.test.tsx` | 17 | the devtools guard reads the mode of a real engine |
| `dt/__tests__/dt-selfcontained.test.tsx` | 18 | the devtools do not need the optional peer dependencies |
| `dt/__tests__/flow.test.ts` | 20 | iamCreateFlowRecorder |
| `dt/__tests__/format.test.ts` | 15 | formatAttrValue |
| `dt/__tests__/guard.test.ts` | 11 | devtools guard: a production engine is an absolute block |
| `dt/__tests__/iam-devtools.test.tsx` | 8 | IamDevtools production guard |
| `dt/__tests__/panels-render.test.tsx` | 34 | every exported panel renders against a real engine |
| `dt/v2/__tests__/v2-contract.test.tsx` | 12 | v2 is a real, separate devtools built on duck-ui |
| `dt/v2/__tests__/v2-render.test.tsx` | 66 | every v2 export renders against a real engine and real duck-ui |
| **Subtotal** | **201** | |

---

## Invalidators

| File | Tests | Covers |
|---|---|---|
| `invalidators/redis/__tests__/e2e-invalidation-cross-instance.e2e.test.ts` | 11 | E2E reachability (invalidation: cross-instance) |
| `invalidators/redis/__tests__/e2e-invalidation-failure-modes.e2e.test.ts` | 12 | E2E reachability (invalidation: failure-modes) |
| `invalidators/redis/__tests__/envelope-channel-binding.test.ts` | 7 | a signed envelope is bound to the channel it was signed for |
| `invalidators/redis/__tests__/envelope-replay.test.ts` | 9 | a signed envelope is applied at most once |
| `invalidators/redis/__tests__/redis-invalidator-channel-redaction.test.ts` | 6 | drop warning does not disclose the tenant id |
| `invalidators/redis/__tests__/redis-invalidator-drop-reporting.test.ts` | 8 | an inbound drop is reported to the operator, not only to the log |
| `invalidators/redis/__tests__/redis-invalidator-event-shape.test.ts` | 8 | Redis invalidator event-shape validation |
| `invalidators/redis/__tests__/redis-invalidator-handler-isolation.test.ts` | 5 | redis invalidator isolates a throwing handler |
| `invalidators/redis/__tests__/redis-invalidator-publish-failure.test.ts` | 7 | createIamRedisInvalidator publish failure |
| `invalidators/redis/__tests__/redis-invalidator-signed-preimage.test.ts` | 4 | signed Redis invalidator pre-image |
| `invalidators/redis/__tests__/redis-invalidator-subscribe-failure.test.ts` | 6 | a rejected client.subscribe() |
| `invalidators/redis/__tests__/redis-invalidator.test.ts` | 20 | createIamRedisInvalidator |
| `invalidators/redis/__tests__/redis-signed-path.test.ts` | 32 | a signed round-trip carries every event kind |
| `invalidators/redis/__tests__/subscribe-failure-visibility.test.ts` | 10 | a redis invalidator that cannot subscribe |
| **Subtotal** | **145** | |

---

## Observability

| File | Tests | Covers |
|---|---|---|
| `observability/metrics/__tests__/metrics-hostile-durations.test.ts` | 6 | the latency ring buffer refuses samples that are not durations |
| `observability/metrics/__tests__/metrics-sample-size.test.ts` | 6 | iamCreateMetricsAggregator sampleSize validation |
| `observability/metrics/__tests__/metrics.test.ts` | 12 | iamCreateMetricsAggregator |
| **Subtotal** | **24** | |

---

## Server

| File | Tests | Covers |
|---|---|---|
| `server/__tests__/adapter-failure-mode-parity.test.ts` | 13 | a throwing getUserId denies through the adapter, not the framework |
| `server/__tests__/admin-actor-parity.test.ts` | 16 | the actor an admin router authenticated |
| `server/__tests__/admin-cross-adapter.test.ts` | 84 |  |
| `server/__tests__/admin-request-validation-parity.test.ts` | 15 | the four admin routers answer one bad request the same way |
| `server/__tests__/cross-adapter.test.ts` | 111 | the path-deriving integrations build the same tuple |
| `server/__tests__/e2e-http-servers.e2e.test.ts` | 173 | harness |
| `server/__tests__/guard-resource-attributes.test.ts` | 17 | a guard and the row it has not loaded |
| `server/__tests__/guard-resource-id.test.ts` | 19 | a guard and the instance it names |
| `server/__tests__/guard-scope.test.ts` | 23 | a guard and the scope it runs under |
| `server/express/__tests__/express-path-bypass.test.ts` | 12 | iamAccessMiddleware refuses a path it cannot map, even for a wildcard admin |
| `server/express/__tests__/express.test.ts` | 51 | iamAccessMiddleware (express) |
| `server/generic/__tests__/admin-audit-target-id.test.ts` | 9 | admin audit targetId is read, not asserted |
| `server/generic/__tests__/admin-authorize-actor-typing.test.ts` | 6 | an admin authorize may return the actor, in the type as well as at runtime |
| `server/generic/__tests__/admin-body-status.test.ts` | 18 | IamValidationError |
| `server/generic/__tests__/admin-shared.test.ts` | 29 | iamDefaultCsrfCheck |
| `server/generic/__tests__/extract-environment-ua-cap.test.ts` | 2 | iamExtractEnvironment user-agent cap |
| `server/generic/__tests__/extract-environment-xff.test.ts` | 20 | iamExtractEnvironment XFF normalization under trustProxy |
| `server/generic/__tests__/generic.test.ts` | 22 | generateIamPermissionMap() |
| `server/generic/__tests__/http-boundary-refusal.test.ts` | 52 | the unknown-action and unknown-resource sentinels are real refusals |
| `server/generic/__tests__/method-action-and-path.test.ts` | 19 | iamActionForMethod |
| `server/hono/__tests__/hono.test.ts` | 33 | iamAccessMiddleware (hono) |
| `server/nest/__tests__/nest-authorize-meta-validation.test.ts` | 22 | a handler decorated with unreadable metadata is denied, not allowed |
| `server/nest/__tests__/nest-infer-resource-parity.test.ts` | 23 | no route template: agrees with iamDefaultResource |
| `server/nest/__tests__/nest.test.ts` | 28 | @IamAuthorize decorator |
| `server/next/__tests__/next-middleware-encoded-path.test.ts` | 6 | next middleware: a path with encoding residue |
| `server/next/__tests__/next-middleware-environment.test.ts` | 8 | createIamNextMiddleware environment |
| `server/next/__tests__/next-middleware-rule-matching.test.ts` | 4 | next middleware: a string rule pattern matches as a prefix |
| `server/next/__tests__/next.test.ts` | 31 | withIamAccess |
| **Subtotal** | **866** | |

---

## Shared

| File | Tests | Covers |
|---|---|---|
| `shared/__tests__/assignment-target.test.ts` | 12 | iamIsForeignKeyViolation recognises every dialect its docblock claims |
| `shared/__tests__/attribute-narrowing.test.ts` | 23 | iamIsAttributeValue |
| `shared/__tests__/cache.test.ts` | 27 | IamLRUCache |
| `shared/__tests__/keys-canonical-image.test.ts` | 17 | iamParsePermissionKey rejects anything outside the builder image |
| `shared/__tests__/keys.test.ts` | 28 | iamBuildPermissionKey() |
| `shared/__tests__/permission-map-scope-blindness.test.ts` | 6 | allowedActions and hasAnyOn ignore scope and record id; can() does not |
| **Subtotal** | **113** | |

---

## Package surface

| File | Tests | Covers |
|---|---|---|
| `__tests__/doc-prose-accuracy.test.ts` | 17 | JSDoc names third-party frameworks correctly |
| `__tests__/docs-import-parity.test.ts` | 8 | documented imports resolve |
| `__tests__/entrypoint-naming.test.ts` | 25 | every subpath entrypoint is Iam-namespaced |
| `__tests__/evaluator-fail-open-gate.test.ts` | 12 | the evaluator applies the same fail-open opt-in as the engine |
| `__tests__/log-prefix-convention.test.ts` | 3 | every log prefix names its module |
| `__tests__/package-exports-parity.test.ts` | 7 | every built module is importable, and every import is built |
| `__tests__/public-error-and-type-surface.test.ts` | 28 | every tagged condition error is reachable |
| `__tests__/public-surface-internals.test.ts` | 7 | public surface: mutable internals stay internal |
| `__tests__/public-surface-naming.test.ts` | 23 | package root naming |
| `__tests__/shipped-docs-parity.test.ts` | 5 | the docs the README points at are the docs that ship |
| `__tests__/test-command-partition.test.ts` | 5 | the two test commands partition every test file |
| `__tests__/test-inventory-freshness.test.ts` | 5 | test inventory stays honest |
| **Subtotal** | **145** | |

---

## Other

| File | Tests | Covers |
|---|---|---|
| `test/__tests__/global-setup-stray-sweep.test.ts` | 4 | globalSetup stray sweep |
| **Subtotal** | **4** | |

---

## Totals by area

| Area | Files | Tests |
|---|---|---|
| Core / compiled engine | 10 | 149 |
| Adapters | 56 | 1669 |
| Clients | 11 | 136 |
| Core | 162 | 2743 |
| Devtools | 9 | 201 |
| Invalidators | 14 | 145 |
| Observability | 3 | 24 |
| Server | 28 | 866 |
| Shared | 6 | 113 |
| Package surface | 12 | 145 |
| Other | 1 | 4 |
| **Total** | **312** | **6195** |
