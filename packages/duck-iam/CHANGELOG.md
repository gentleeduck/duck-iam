# @gentleduck/iam

## 2.1.0

### Adversarial security audit cycle (SEC-001 .. SEC-106 + CAVEAT-1/2/3)

A second multi-round audit pass after 2.0.0. Spans **21 rescan cycles** across two adversarial security-auditor agents plus a silent-failure hunter and a code-smell scanner. Resulted in **~60 fix commits** addressing 1 CRITICAL, 7 HIGH, 11 Medium, 12 Low, and 4 Info findings on top of the 2.0.0 hardening. Three consecutive clean rescans (Med+ free) declared the source tree exhausted: *"the package is genuinely hard to break."*

The change set is **mostly backward compatible** with two notable defaults:

1. **Hono `accessMiddleware` + `guard` no longer default to `x-user-id` header** (SEC-101). Spoofable. Now reads only `c.get('userId')` populated by upstream auth. Operators relying on the header must wire `getUserId` explicitly.
2. **Next `withAccess` requires `getUserId`** (SEC-101). Previous default also trusted the header. Throws at construction when omitted.
3. **Admin routers CSRF-check by default** (CAVEAT-2). New `defaultCsrfCheck` rejects browser requests with `Sec-Fetch-Site: cross-site|cross-origin`. Bearer/mTLS APIs opt out via `csrfCheck: false`. Cookie-auth admin UIs get protection without any opt-in.

#### CRITICAL (1)

- **SEC-054** `FileAdapter._loadState` swallowed every `readFile` error and silently fell back to an empty store. EACCES (permissions drift), EISDIR (path overwritten), EIO (disk corruption) became `{policies:{},roles:{},…}`. With `defaultEffect:'allow'+allowFailOpen` this is total silent fail-open; with `'deny'` it's total silent outage. Only `ENOENT` now recovers as empty; everything else throws a wrapped Error.

#### HIGH (7)

- **SEC-042** HTTP adapter followed fetch redirects without re-validation. A 302 to `169.254.169.254` or `10.0.0.5:6379` bypassed the construction-time `allowedHosts` / private-IP guard. `_fetchOnce` now passes `redirect: 'error'`.
- **SEC-055** `_emitMetrics` invoked `onMetrics` without a try/catch. A throwing operator hook escaped `authorize`'s catch arm and replaced the documented fail-closed deny with a raw error. Wrapped via `_safeHookCall`; double-wrapped around `console.error` itself.
- **SEC-056** `afterEvaluate` / `onDeny` ran inside `authorize`'s main try block; throws caught by the evaluation catch silently rewrote an allow verdict into a fail-closed deny. Trailing hooks now run outside the evaluation try; throws routed to console.error without reshaping the decision.
- **SEC-057** `engine.permissions()` passed `undefined` for `onPolicyError` to evaluator — per-policy throws vanished. UI gates silently allowed under `defaultEffect:'allow'`. Now forwards the same shim `authorize()` uses.
- **SEC-058** Redis + Drizzle `getSubjectAttributes` returned `{}` on JSON.parse failure or non-object root. ABAC conditions silently flipped to deny. Now throws; engine routes through `onError` + fail-closed deny.
- **SEC-064** `FileAdapter` JSON parse failure silently populated `_cache = {}`. Next `_flush()` overwrote the recoverable-but-corrupt file. **Permanent data destruction triggered by a single transient parse error.** Now throws "store corrupt — refusing to load; restore from backup before retrying".
- **SEC-065** `can()` / `check()` invoked `this._hooks.onError?.()` unwrapped — SEC-055/058 throws routed through these catches; a throwing operator `onError` propagated as unhandled rejection. Now `_safeHookCall`.
- **SEC-101** Hono / Next default `getUserId` trusted spoofable `x-user-id` header. **Trivial auth bypass via curl.** Hono: no header fallback. Next: required option, throws on construction without it.

#### Medium (11)

- **SEC-043** Admin write path skipped validation. Hostile admin (or buggy UI) could persist a policy that adapter read-side validator silently drops → tenant ends up with zero policies → `defaultEffect` decides every request. `createAdmin.savePolicy / saveRole / import` now call `validatePolicy / validateRole` and throw on error.
- **SEC-052** `assertValidOrThrow` echoed attacker-controlled values (`Invalid algorithm "<value>"`). Operator who opted into `includeErrorMessage:true` + HTTP body echo got a probe oracle. Now emits `INVALID_ALGORITHM at "algorithm"` — structural codes only.
- **SEC-024** Redis migration vs `revokeRole` race. `_migrateLegacyAssignment`'s SADD-then-SREM let migrator resurrect a just-revoked assignment. `_runSerialised` per-key chain orders writes; revoke now SREMs both encodings.
- **SEC-025** File `_assertWithinRoot` ran once per adapter; attacker swapping the file for a symlink after first I/O steered subsequent writes. Drops latch; realpath re-checks every read/write.
- **SEC-063** `_assertWithinRoot` outside the load try; rejected promise stuck forever in `_loadInFlight`. Restructure clears in-flight via finally on any throw.
- **SEC-067** SEC-058 caused admin lockout: `setSubjectAttributes` called the getter first, getter now throws on corrupt existing data → operator could not overwrite. Setter catches the throw, logs, treats existing as `{}`.
- **SEC-068** HTTP adapter `getSubjectRoles` forwarded server response verbatim; other adapters enforce unscoped-only (SEC-059). JSDoc now documents operator's contract responsibility.
- **SEC-103** Admin router shipped without CSRF guidance. Cookie-auth deployments exposed to cross-site forms. Optional `csrfCheck` added to all 4 framework adapters; default-on via `defaultCsrfCheck` (CAVEAT-2).
- **SEC-070** `engine.permissions()` had no outer try around `Promise.all([_resolveSubject, _loadAllPolicies])`. Adapter rejection crashed the whole batch without `onError` + fail-closed map. Now wraps in try; returns all-deny map keyed by every requested check + invokes `onError`.
- **SEC-045** `_loadAllPolicies` merger had no in-flight sentinel; concurrent invalidate-mid-load repopulated stale data. Added `_mergedInFlight` sentinel.
- **SEC-059** `getSubjectRoles` semantic drift: file/memory returned unscoped-only; redis/drizzle/prisma returned all collapsed. Same subject resolved differently across backends. Aligned all to unscoped-only; documented in `Adapter.ISubjectStore`.

#### Low (12)

- **SEC-044** No way to chart fail-open rate. Added `failOpen: boolean` to `IMetricsEvent` + counter to `createMetricsAggregator`. Threaded through `evaluate`/`evaluateFast` via optional `IEvalSignals`.
- **SEC-046** Redis invalidator v:1 envelope was unwrapped without HMAC verification when `secret: null` — attacker chose `instanceId`, silenced legitimate cross-instance invalidates. v:1 in unsigned mode now dropped + warned.
- **SEC-051** `permissions()` bypassed `_emitMetrics` entirely; dashboards charting fail-open missed every batch UI gate. Now emits per check.
- **SEC-026** File `rootDir` warn fired every construction → log spam → operators filter the warning. Module-global latch fires once per process.
- **SEC-027** File warn echoed resolved path → path-existence oracle via log scraping. Path stripped from message.
- **SEC-032** Redis invalidator one-shot per-channel warn latch let attacker burn the first warn on a benign reason then silently flood. Replaced with 60s rate-limit + suppressed-count surfacing.
- **SEC-047** `errorToAuditString(includeMessage=true)` returned raw `String(err)` for non-Error throws — unbounded leak. Now tagged `<non-Error <typeof>>` + capped at 256 chars + `JSON.stringify` fallback.
- **SEC-048** Devtools `localStorage` prefix `__IAM_DEVTOOLS` → vendor-namespaced `__GENTLEDUCK_IAM_DEVTOOLS_V1`.
- **SEC-053** `_assertWithinRoot` parent-realpath fallback fired on ANY error; ELOOP / EACCES bypassed symlink check via reconstructed path. Now gated on `code === 'ENOENT'`.
- **SEC-060** Vanilla client listener-throw was totally silent. `console.error` surfacing.
- **SEC-061** Invalidator dropped shape-mismatched inner payloads without `warnDropOnce` — operators saw nothing on sustained schema drift. Routed through warn.
- **SEC-062** Invalidator `publish()` failure silently swallowed. Added optional `onPublishError(err, channel)` hook + rate-limited console fallback.
- **SEC-066** `_safeHookCall` / `_emitMetrics` called `console.error` unwrapped; throwing logger (closed stdout, broken pipe) would resurrect SEC-055. Defensive double-wrap.
- **SEC-069** `dt/lib/flow.ts` listener `catch{}` silent. console.error added.
- **SEC-104** Vanilla `extractAction` split key on `:` naively; resources containing `:` mis-tokenised. Added `splitPermissionKey` that honours `\\:`/`\\\\` escapes from `buildPermissionKey`.

#### Info (4)

- **SEC-105** `createNextMiddleware` JSDoc example demonstrated the SEC-101 unsafe pattern. Replaced with `getServerSession` example + warning.
- **SEC-106** Only express had a CSRF regression test; hono/next/nest needed parity. Added.
- **INFO-A** `LRUCache` + Engine `maxPolicies/maxRoles/adapterTimeoutMs` accepted NaN (silently disabled bound). Now `Number.isFinite` required.
- **INFO-B** `Explain.IResult.summary` is plain text with attacker-influenced values; consumers rendering as HTML must escape. JSDoc added.

#### Deployment hardening (CAVEAT-1/2/3 + SEC-050)

- **CAVEAT-1**: `createRedisInvalidator({ tenantId })` auto-prefixes the channel `'duck-iam:invalidate:tenant:${tenantId}'`. Validates `tenantId` against `/^[A-Za-z0-9_-]{1,64}$/` so attacker-controlled tenant slugs cannot inject pub/sub wildcards.
- **CAVEAT-2**: Admin routers default-on CSRF via `defaultCsrfCheck` (Sec-Fetch-Site check). `csrfCheck: false` opts out for bearer/mTLS APIs.
- **CAVEAT-3**: `SECURITY.md` adds a 10-section **Deployment Hardening Guide** covering identity sourcing, admin CSRF, Redis tenancy, cache scoping, `defaultEffect:'allow'`, `explain()` output trust, adapter trust, file `rootDir`, HTTP `allowedHosts`, observability wiring.
- **SEC-050**: `getCachedRegex` / `getSegments` accept optional per-instance cache override. `clearRegexCache()` / `clearPathCache()` exported. `Engine.flushSharedCaches()` ergonomic operator API for multi-tenant deployments.

#### New APIs (additive)

- `Engine.flushSharedCaches()` — wipe process-wide regex + path caches.
- `defaultCsrfCheck(req)` — exported from `server/generic`; built-in Sec-Fetch-Site predicate.
- `AdminAudit.IOptions.csrfCheck?: ((req) => boolean) | false`.
- `RedisInvalidator.IConfig.tenantId?: string`.
- `RedisInvalidator.IConfig.onPublishError?: (err, channel) => void`.
- `IMetricsEvent.failOpen: boolean`.
- `Metrics.ISnapshot.failOpen: number`.
- `splitPermissionKey(key)` — exported from `shared/keys`; escape-aware split.
- `clearRegexCache()` / `clearPathCache()` — process-wide cache flush.
- `Validate.ValidationCode` extended with `'ERR_REGEX_CATASTROPHIC'`.

#### Behaviour changes

- `adminRouter`/`bindAdminRouter`/`createAdminHandlers`/`createAdminOperations` enforce `defaultCsrfCheck` by default. Pass `csrfCheck: false` to restore old behaviour.
- Hono `accessMiddleware`/`guard` no longer fall back to `x-user-id` request header.
- Next `withAccess` requires `getUserId` (throws at construction).
- `FileAdapter.listPolicies/...` throws on non-ENOENT load failures (was silently empty).
- `FileAdapter` throws on malformed JSON (was silently empty + permanent file destruction on next flush).
- Redis/Drizzle `getSubjectAttributes` throws on corrupt blob (was `{}`).
- All 5 adapters' `getSubjectRoles` return unscoped-only (`getSubjectScopedRoles` still surfaces scoped separately).
- Engine ctor rejects NaN/Infinity for `maxPolicies`/`maxRoles`/`adapterTimeoutMs`.
- `LRUCache` ctor rejects NaN/Infinity for `maxSize`/`ttlMs`.

#### Tests

- 785 → **836** tests (+51).
- 5 consecutive clean rescans (Med+ free): 010, 011, 012, 014, 017, 019, 020, 021 (intermediate Med+ found-and-fixed in 015, 018).

#### Audit hygiene

- `audit/` directory gitignored; per-finding markdown reports + per-cycle `rescan-NNN.md` reports tracked locally in `audit/STATE.md`.

## 2.0.1

### Patch Changes

- 41a45ac: Standardize README header to match the @duck-md template (centered logo, h1, tagline, nav, npm badges). Switch docs links from `iam.gentleduck.org` to path-based `gentleduck.org/duck-iam`. No runtime code changes.

## 2.0.0

### Breaking

- **Type API rewrite**: every interface now lives under a per-module namespace (`AccessControl`, `Request`, `Adapter`, `Primitives`, `Client`, `DotPath`, `EngineTypes`, `Evaluate`, `Explain`, `Validate`, `Config`, `Memory`, `File`) with an `I` prefix. Migration: rename `Policy` -> `AccessControl.IPolicy`, `Decision` -> `AccessControl.IDecision`, `AccessRequest` -> `Request.IAccessRequest`, etc.
- **`Adapter.IAdapter` read methods accept an optional `IReadOptions`** with an `AbortSignal`. Backwards-compatible for adapters that ignore the parameter; custom adapters should plumb the signal through to their underlying driver where possible.
- **`adminRouter` (Express) signature changed**: now requires `{ authorize: (req) => boolean }` as the second argument. Mounting unguarded admin endpoints used to be possible; it is no longer.

### Added

- **`policyCombine` cross-policy combine** (`'and'` / `'allow-overrides'` / `'first-applicable'`) configurable via `IConfig.policyCombine`.
- **`hooks.onMetrics`** primitive-only telemetry event fired once per evaluation in both modes.
- **`hooks.onPolicyError`** routed when a single policy throws during evaluation (fail-skip, not fail-crash).
- **`engine.preload()`** warms `mergedPolicyCache` so the first request after boot is hot.
- **`engine.healthCheck()`** returns `{ ok, adapter, cacheHitRate, adapterLatencyMs, lastError? }`.
- **`engine.admin.export()` / `engine.admin.import(snapshot, { mode })`** - schema-versioned policy + role snapshots; `'merge'` and `'replace'` modes.
- **`engine.dispose()`** releases the cross-instance invalidator subscription.
- **`IConfig.adapterTimeoutMs`** (default 5 s) wraps every adapter read in a timeout that triggers `AbortController.abort()`.
- **`IConfig.maxPolicies` / `maxRoles`** load-time caps; over-cap throws and routes to fail-closed deny.
- **`IConfig.allowFailOpen`** required to combine `mode: 'production'` with `defaultEffect: 'allow'`.
- **`IConfig.invalidator`** - cross-instance cache-invalidation broadcaster contract.
- **`createRedisInvalidator`** at `@gentleduck/iam/invalidators/redis` - pub/sub helper with self-echo filtering.
- **`createMetricsAggregator`** at `@gentleduck/iam/observability/metrics` - p50/p95/p99 over `onMetrics` events.
- **Hono `bindAdminRouter`**, **Next.js `createAdminHandlers`**, **NestJS `createAdminOperations`** - all require the `authorize` callback at construction time.
- **HttpAdapter** retry + per-request timeout + circuit-breaker (`retries`, `backoffMs`, `timeoutMs`, `circuitBreakerThreshold`, `circuitBreakerCooldownMs`).
- **FileAdapter** at `@gentleduck/iam/adapters/file` - JSON-on-disk store with pluggable `File.IFS` interface.
- **`POLICY_JSON_SCHEMA`** - Draft 2020-12 JSON schema export.
- **`engine.stats()` / `resetStats()`** - cache hit/miss counters per cache.

### Fixed

- `first-match` combiner now honors `rule.priority` across trace, fast, precomputed, and explain paths.
- `engine.explain()` populates `Decision.rule` from the deciding policy's trace.
- `engine.invalidateRoles(roleId?)` is scoped - only subjects holding the named role are evicted.
- `setSubjectAttributes` documented contract is now `merge`, matching every built-in adapter.
- Single-flight on `loadPolicies` / `loadRoles` / `resolveSubject` / `loadRbacPolicy` coalesces concurrent cold-start adapter calls. Sentinel-compare-on-resolve so a pending load can't write stale data after an invalidate.
- **NotApplicable semantics**: a policy whose `targets` don't match is skipped by the cross-policy combine, not folded as the default effect.
- Empty RBAC policy is skipped from the per-request policy set.
- Fast path matches colon-prefix actions (`'posts:*'`), dot-hierarchy resources (`'dashboard.*'`), and parent-prefix patterns.
- `evaluatePolicyFast` returns `boolean | null` (null = NotApplicable). `evaluateFast` skips null in every combine mode.
- Engine ctor refuses `mode: 'production'` + `policyCombine: 'first-applicable'`.
- RBAC rule ids are opaque (`__rbac__#N`) - no longer dotted.
- `matches` operator refuses `$`-resolved RHS values (ReDoS via user-controlled regex).
- HttpAdapter `getPolicy` / `getRole` return `null` on 404 instead of throwing.
- Validator depth bound (`MAX_CONDITION_DEPTH=10`) and field-length cap (`MAX_FIELD_LENGTH=256`).
- Regex cache is LRU on hit, not FIFO on insert.
- Synthesised RBAC policy is deep-frozen (every rule + conditions tree).
- `Number.isFinite` priority check in validator.

### Tests

- 629 tests across 29 files (up from 309 at 1.7.0).
- Property-based oracle asserts `evaluate == evaluateFast` over 1000 random policy sets per `(combine, defaultEffect)` pair.
- Bench harness: `evaluate.bench.ts` + `resolve.bench.ts` + competitor benchmarks.

### Dot-path attribute access (`When` builder)

The `When.attr()` / `When.resourceAttr()` / `When.env()` methods now accept dot-paths into nested attribute bags. Previously `resourceAttr` and `env` required `keyof` on the raw object shape (one level deep). Now `'profile.tier'` typechecks against `{ profile: { tier: string } }` and the value parameter narrows correctly.

New + reorganized in `DotPath`:

- **`SubjectAttrShape<TContext>`** - raw subject attribute bag object.
- **`ResourceAttrShape<TContext>`** - raw resource attribute bag object.
- **`EnvAttrShape<TContext>`** - raw environment object.
- **`SubjectAttrs<TContext>` / `ResourceAttrs<TContext>` / `EnvAttrs<TContext>`** - now return dot-path string unions (consistent), not raw objects.
- **`AttrValueAt<T, P>`** - walks a dot-path inside an attribute bag to resolve the leaf type.
- **`AttrValue<T, P>`** - rewritten on top of `AttrValueAt`, with `AttributeValue` fallback.
- **`ResolvedResourceAttrPaths<TContext, TResource>`** - dot-paths into per-resource attribute narrowing.
- **`ResolvedResourceAttrs`** - now returns the resolved attribute SHAPE (object), paired with `ResolvedResourceAttrPaths` for keys.

`When` method signatures dropped `keyof` in favour of these dot-path types. Open attribute bags (`IAnyAttributes` via `string` index signature) widen to `string` so the legacy `keyof IAnyAttributes` behaviour is preserved for `IDefaultContext`. File reorganized into 8 labeled sections (context paths, condition adapters, shape extractors, attribute paths, per-resource narrowing, value resolution, defaults, internal helpers).

### Module-local namespaces (added 2.0)

Every bare integration-config interface is now wrapped in a type-only namespace; deprecated bare aliases are kept for back-compat and will be removed in `3.0`.

- `Http.IConfig` (was `IHttpAdapterConfig`) - `@gentleduck/iam/adapters/http`
- `Redis.ILike` + `Redis.IConfig` (was `RedisLike` / `RedisAdapterConfig`) - `@gentleduck/iam/adapters/redis`
- `Drizzle.IConfig` (was `IDrizzleConfig`) - `@gentleduck/iam/adapters/drizzle`
- `Express.IOptions` + `Express.IAdminAuthorize` + `Express.IAdminRouterOptions` (were `IExpressOptions` / `IAdminAuthorize` / `IAdminRouterOptions`) - `@gentleduck/iam/server/express`
- `Hono.IOptions` + `Hono.IAdminAuthorize` + `Hono.IAdminOptions` + `Hono.IRouterLike` (were `IHonoOptions` / `IHonoAdminAuthorize` / `IHonoAdminOptions` / `IHonoRouterLike`) - `@gentleduck/iam/server/hono`
- `Nest.IAuthorizeMeta` + `Nest.IGuardOptions` + `Nest.IAdminAuthorize` + `Nest.IAdminOptions` (were `IAuthorizeMeta` / `INestGuardOptions` / `INestAdminAuthorize` / `INestAdminOptions`) - `@gentleduck/iam/server/nest`
- `Next.IWithAccessOptions` + `Next.IMiddlewareOptions` + `Next.IAdminAuthorize` + `Next.IAdminOptions` (were `IWithAccessOptions` / `INextMiddlewareOptions` / `INextAdminAuthorize` / `INextAdminOptions`) - `@gentleduck/iam/server/next`
- `ReactClient.IContextValue` (was `IContextValue`) - `@gentleduck/iam/client/react`
- `RedisInvalidator.IPubSubLike` + `RedisInvalidator.IConfig` (were `IRedisPubSubLike` / `IRedisInvalidatorConfig`) - `@gentleduck/iam/invalidators/redis`
- `Metrics.IAggregator` + `Metrics.ISnapshot` + `Metrics.IConfig` (were `IMetricsAggregator` / `IMetricsSnapshot` / `IMetricsAggregatorConfig`) - `@gentleduck/iam/observability/metrics`
- `AccessControl.OpFn` (was bare `OpFn` in `conditions.libs.ts`)

Every new namespace is **type-only** (interfaces + type aliases only, no runtime values) so it compiles to nothing and bundle size stays unchanged. Runtime helpers (`evaluatePolicyFast`, `ops`, `regexCache`, `MAX_*`, `POLICY_*`, every adapter class, every server factory, every client factory) remain bare module exports so tree-shaking still works.

### Stability

`2.0.0` commits to SemVer. The type-API namespace rewrite is load-bearing; no further public-API renames until `3.0.0`. Patch + minor releases stay non-breaking.

## Unreleased

### Major refactor: namespaced type API + correctness hardening

13-round audit-driven hardening pass plus a full type-API refactor matching the duck-\* monorepo convention.

**Type API: namespaced + I-prefixed.** Every interface now lives under a per-module namespace (`AccessControl`, `Request`, `Adapter`, `Primitives`, `Client`, `DotPath`, `EngineTypes`, `Evaluate`, `Explain`, `Validate`, `Config`, `Memory`, `File`). Interface names carry an `I` prefix; type aliases stay bare.

**Engine correctness fixes:**

- `first-match` combiner now honors `rule.priority` across trace, fast, precomputed, and explain paths.
- `engine.explain()` populates `Decision.rule` from the deciding policy's trace.
- `engine.invalidateRoles(roleId?)` is scoped - only subjects holding the named role are evicted.
- `setSubjectAttributes` contract is now `merge`, matching every built-in adapter.
- Single-flight on `loadPolicies` / `loadRoles` / `resolveSubject` coalesces concurrent cold-start adapter calls.
- `invalidate()` family clears in-flight slots + sentinel-compare-on-resolve so a pending load can't write stale data.
- **NotApplicable semantics**: a policy whose `targets` don't match is skipped by the cross-policy combine, not folded as the default effect. Largest correctness fix in the project's history.
- Empty RBAC policy is skipped from the per-request policy set so it doesn't contribute a default-deny under AND combine.
- Fast path matches colon-prefix actions (`'posts:*'`), dot-hierarchy resources (`'dashboard.*'`), and parent-prefix patterns (`'org'` matching `'org:project'`) consistently with the trace path.
- `evaluatePolicyFast` returns `boolean | null` (null = NotApplicable). `evaluateFast` skips null in every combine mode.
- Engine ctor refuses `mode: 'production'` + `policyCombine: 'first-applicable'`.
- RBAC rule ids are opaque (`__rbac__#N`) - no longer dotted.

**New APIs:**

- **`AccessControl.PolicyCombine`** - cross-policy combine strategy (`'and'` / `'allow-overrides'` / `'first-applicable'`). Configurable via `Engine.policyCombine`.
- **`EngineTypes.IMetricsEvent` + `onMetrics` hook** - primitive-only telemetry payload fired once per evaluation in both dev and prod modes. Zero overhead when unwired.
- **`FileAdapter`** at `@gentleduck/iam/adapters/file` - JSON-on-disk store with pluggable `File.IFS` interface.
- **`POLICY_JSON_SCHEMA`** - Draft 2020-12 JSON schema export for non-TS consumers and editor tooling.
- **`Engine.stats()` / `resetStats()`** - cache hit/miss counters per cache.
- **Validator semantic checks** - emits `UNRESOLVABLE_FIELD`, `UNRESOLVABLE_VALUE`, `INHERITANCE_TOO_DEEP`, `BROAD_ALLOW`, `LIMIT_EXCEEDED` codes.
- **`POLICY_LIMITS`** - DoS bounds (1000 rules/policy, 100 actions/rule, 100 resources/rule, 1000 actionxresource cartesian/rule).
- **`MAX_INHERITANCE_DEPTH = 32`** exported from `core/rbac`. Validator errors on chains that exceed it.

**Build / package:**

- `sideEffects: false` in `package.json` for tree-shaking.
- `./adapters/file` subpath export added.

**Testing:**

- 584 tests across 28 files (up from 309 at 1.7.0).
- Property-based oracle asserts `evaluate == evaluateFast` over 1000 random policy sets per `(combine, defaultEffect)` pair.
- Bench harness: `evaluate.bench.ts` + `resolve.bench.ts` + competitor benchmarks.

## 1.7.0

### Minor Changes

- 0e80f84: Add Redis adapter, Drizzle schemas, and full integration test coverage.

  **New: `RedisAdapter`** at `@gentleduck/iam/adapters/redis`. Distributed key/value backend with idempotent `assignRole` (set semantics), multi-tenant `keyPrefix`, and a minimal `RedisLike` interface that ioredis, node-redis v4+, and Upstash all satisfy directly.

  **New: pre-built Drizzle schemas** at `@gentleduck/iam/adapters/drizzle/schema/{pg,mysql,sqlite}`. Drop-in tables for all three SQL dialects with the right column types, FK cascade on `roleId`, unique index on `(subjectId, roleId, scope)`, and auto-managed `created_at`/`updated_at`. Generate migrations via `drizzle-kit generate`.

  **Test coverage expansion**: every adapter, server middleware, and client integration now has dedicated tests. Total test count went from 309 to 498. New test files:

  - `adapters/prisma`, `adapters/drizzle`, `adapters/http`, `adapters/redis`
  - `server/express`, `server/hono`, `server/nest`, `server/next`
  - `client/react`, `client/vue`

  **Optional peer deps added**: `drizzle-orm`, `ioredis`, `redis` (all optional).

## 1.6.2

### Patch Changes

- 918b34c: Strip `workspace:*` and `catalog:` protocol tokens from `devDependencies`/`dependencies`/`peerDependencies` of every public package before `changeset publish`. Previously published artifacts leaked these tokens into npm metadata, which broke strict resolvers (bun, deno) for downstream consumers. Adds `scripts/clean-publish.ts` and wires it into the root `release` script with a `git checkout` restore step so source remains workspace-friendly.

## 1.6.1

### Patch Changes

- Add package README for npm page. Remove special characters from all documentation.

## 1.6.0

### Minor Changes

- Performance: evaluatePolicyFast now 2x vs CASL (was 5.2x). Inlined hot path, added pre-computed results cache for unconditional rules, fixed empty conditions bug, added combined action+resource index.

## 1.5.0

### Minor Changes

- e682b61: Add optional scope parameter to grant() for permission-level scoping

  The `grant()` method now accepts an optional third `scope` argument:
  `.grant('update', 'post', 'org-1')`. This enables permission-level
  scoping directly without needing `grantScoped()`. The existing
  `grantScoped(scope, action, resource)` method remains available.

  Also fixed incorrect `first-applicable` references in JSDoc comments
  to use the correct algorithm names `first-match` and `highest-priority`.

## 1.4.0

### Minor Changes

- 72c449b: Add FlexibleDollarPaths for $-value autocomplete and fix AttrValue for optional properties

  - FlexibleDollarPaths<TContext> added directly to method value signatures so the IDE shows $-prefixed autocomplete (e.g. $subject.id) even without a custom context
  - AttrValue now strips undefined from optional properties - yearsExperience?: number correctly resolves to number instead of falling back to AttributeValue
  - StringConditionValue no longer includes (string & {}) internally - the flexible string fallback is handled at the method signature level via FlexibleDollarPaths

## 1.3.2

### Patch Changes

- 2dd9f8b: feat: FlexibleDotPaths for DefaultContext autocomplete and strict ConditionValue type safety

  - DotPaths now bails to `never` (not `string`) for string-indexed types, preventing
    union pollution that killed IDE autocomplete.
  - New FlexibleDotPaths<T> detects open-ended attribute bags (like DefaultContext) and
    adds `(string & {})` so known structural paths autocomplete while arbitrary strings
    are still accepted. Fully typed contexts remain strict.
  - ConditionValue correctly restricts non-string value types: `env('hour', 'lt', '')`
    now errors when `hour` is `number`, instead of accepting any AttributeValue.

## 1.3.1

### Patch Changes

- b62bb5b: fix: prevent DotPaths from recursing into array methods and functions

  DotPaths now treats arrays as leaf paths and skips function-valued properties,
  so autocomplete only shows real data properties instead of array methods like
  `length`, `push`, `toString`, etc.

## 1.3.0

### Minor Changes

- Add DollarPaths type for $-variable autocomplete in conditions, refactor core into modular folders, and add JSDoc and inline FAQs to documentation

## 1.2.0

### Minor Changes

- 7fe860f: Add TContext type parameter for typed dot-path intellisense and per-resource attribute narrowing. Split types.ts into modular types/ directory. Add JSDoc across all source files.

## 1.1.2

### Patch Changes

- 66608fe: Add publishConfig with public access for scoped npm package.

## 1.1.1

### Patch Changes

- 37339e8: Fix release workflow to skip redundant CI checks during publish.

## 1.1.0

### Minor Changes

- 29ed55d: Initial release of @gentleduck/iam - identity and access management utilities.
