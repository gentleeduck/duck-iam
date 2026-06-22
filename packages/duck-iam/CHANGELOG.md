# @gentleduck/iam

## 5.1.0

### Minor Changes

- Restructure core into `engine/` and `config/` subfolders matching duck-iam patterns. Rename `defineAuth` → `createAuth` as primary entry point. Extract `AuthEngineTypes` and `AuthDefine` into dedicated types files. Add `Auth` prefix to all public classes.

## 5.0.1

### Patch Changes

- fix: strip redundant iam/auth prefixes from public exports

## 5.0.0

### Major Changes

- Prefix all public exports with package namespace (`Auth*`/`Iam*`/`IAM_*`/`AUTH_*`) so the origin is clear at the type level when both packages are imported together. This is a breaking change — all consumers must update import references to the new names.

## 4.0.0

### Major Changes

- a5fb285: Rename the policy builder factory to `definePolicy`, matching `defineRule` and
  `defineRole`.

  BREAKING: the `policy()` factory and `access.policy()` method are removed. Use
  `definePolicy()` and `access.definePolicy()` instead - the builder API is
  otherwise unchanged.

## 3.2.0

### Minor Changes

- f77fb5a: Harden and type the Drizzle adapter schemas (pg, mysql, sqlite).

  - Add `json: 'native' | 'string'` adapter option. `'native'` (default) writes plain objects to `jsonb`/`json` columns so payloads stay queryable; `'string'` JSON-stringifies for SQLite/text columns. The read path accepts both, so switching is migration-safe.
  - Type every JSON column with `$type<>()` against the `AccessControl` types; constrain `algorithm` with a Postgres enum, a MySQL enum, and a SQLite CHECK.
  - Add CHECK constraints (non-blank name/subject, `version >= 1`), `created_by` / `updated_by` audit columns, GIN indexes (pg), partial indexes for scoped rows (pg/sqlite), and a `roleId` index.
  - Collapse NULL scopes in unique constraints (`NULLS NOT DISTINCT` on pg, `COALESCE(scope, '')` on mysql/sqlite) so duplicate global rows are rejected.
  - Name every constraint (`pk_`, `fk_`, `uq_`, `idx_`, `ch_`).

  Fixes: pg `inherits` was `text[]` but the shared adapter writes JSON, so it is now `jsonb`; the MySQL timestamp default was a static import-time snapshot and is now per-row `CURRENT_TIMESTAMP(3)`.

  Migration note: regenerate migrations with `drizzle-kit generate`. SQLite users must pass `json: 'string'`.

## 3.1.0

### Minor Changes

- e5fc356: # @gentleduck/iam 3.1

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

## 3.0.1

### Patch Changes

- 1f5ac74: **@gentleduck/auth**: end-to-end input + tenant + config-time hardening sweep.

  - Provider entry-point caps + typeof guards (api-key, magic-link, oauth, passkey, password, saml). Magic-link `callbackPath` validated at construction (refuses protocol-relative + CR/LF). OAuth `redirectUri` + endpoint URLs validated. SAML `relayState` + `host` CR/LF guard.
  - Facet input caps (flows, sessions, mfa, apikeys, identities, idempotency). `isProviderIdSafe` guard in `signIn` / `beginProvider`. CAS-claim on recovery + signup. Email canonicalization (`trim().toLowerCase()`) shared between rate-limit + lookup + stored metadata.
  - Transport hardening: 4 KB bearer cap, 8 KB DPoP cap, 16 KB cookie-header cap, cookie name RFC 6265 validation. JWT `signKey.kid` + `signKey.key` validation. `Number.isFinite` on iat / nonce / counter rollback. timingSafeEqual on `ath` + `nonce`.
  - Adapter parity: memory adapter `findByHashedSecret` respects `ctx.tenantId` (was searching globally) + uses `isRevoked` predicate. `upsert` inherits `tenantId` from ctx. Redis adapter caps key length + clamps NaN/huge ttl. SQL adapters parameterize JSONB queries.
  - `AuthRoot.strict`: refuse `http://` baseUrl in production.
  - Webhooks: `redirect: 'error'` SSRF, 1 MiB payload cap, 20-attempt backoff cap, NaN-timestamp rejection.
  - New `@gentleduck/auth/server/{fastify,koa,nestjs,elysia,grpc}` adapters.
  - New providers: SAML 2.0 SP, Microsoft, Discord, LinkedIn, Sign in with Apple, api-key sign-in.
  - New channels: Resend, Twilio, Web Push, AWS SES.
  - DPoP (RFC 9449) + OAuth refresh-reuse detection.
  - READMEs: parallel structure across both packages, local logo + LICENSE for npm rendering.

  **@gentleduck/iam**: defense-in-depth + adapter hardening + vitest compat shim.

  - `engine.libs.assertNonEmptyStringParam`: enforce 1024-char cap. `assertAttributesParam`: 256-key + depth-16 caps. `engine.permissions()`: refuse batches >1024. `engine.can()` / `check()` / `explain()`: subjectId typeof + length-cap; fail-closed in production.
  - File adapter dicts now `Object.create(null)` (prototype-pollution defense). `setSubjectAttributes('__proto__', ...)` no longer pollutes Object.prototype.
  - HTTP adapter: streaming `readBodyCapped` + `readJsonCapped<T>` so multi-GB remote bodies cannot OOM before slice. ID-length caps. Backoff overflow cap. SSRF `redirect: 'error'`.
  - Redis invalidator: pre-auth UTF-8 byte-length cap + depth/key-count cap on parsed envelopes.
  - Hono adapter: body Reflect.get-parsed with typeof + length guards.
  - Vitest compat shim for bun runtime (`stubGlobal` / `unstubAllGlobals` / `describe.runIf`); 8 previously-failing devtools tests now pass.

  **Tests**: +42 across both packages, all green. No functional behavior changes beyond defensive guards on hostile input.

## 3.0.0

### Breaking - Engine facet split

The flat cache + stats methods on `Engine` move onto two facets. The
evaluation surface (`authorize`, `can`, `check`, `explain`, `permissions`)
and lifecycle (`constructor`, `dispose`, `preload`, `healthCheck`) stay
flat - they are the hot path and benefit from a single noun.

#### Migration

| Before (<= 2.x)                        | After (3.0)                                |
| -------------------------------------- | ------------------------------------------ |
| `engine.invalidate(opts)`              | `engine.cache.invalidate(opts)`            |
| `engine.invalidateSubject(id, opts)`   | `engine.cache.invalidateSubject(id, opts)` |
| `engine.invalidatePolicies(opts)`      | `engine.cache.invalidatePolicies(opts)`    |
| `engine.invalidateRoles(id?, opts)`    | `engine.cache.invalidateRoles(id?, opts)`  |
| `engine.stats()`                       | `engine.stats.get()`                       |
| `engine.resetStats()`                  | `engine.stats.reset()`                     |
| `engine.flushSharedCaches()` (removed) | `import { flushSharedCaches } from ...`    |

Codemod is a five-line `sed`; no behavior change. Reason for cutting now
instead of waiting: bundling the deprecation with `flushSharedCaches`'s
already-scheduled 3.0 removal means one major version, one migration
window.

#### Why

`Engine` had 16 public methods on one class. Four cluster cleanly:
evaluation, cache invalidation, lifecycle, observability. Folding the
last two clusters into facets drops the flat surface to 9 methods + 2
facet handles, which reads cleaner and gives room for future facet
growth (e.g. `engine.cache.prewarm()`, `engine.stats.subscribe()`)
without polluting the root.

The `flushSharedCaches` instance method was misleading - it wiped
process-globals, so calling it on one engine affected every other engine
in the process. Removed; module-level export is the honest surface and
has been the documented one since 2.1.

## 2.2.0

### Architecture debt cleanup + bundle slim

Follow-up to the 2.1.0 security audit. Closes maintenance gaps the cycle
surfaced and trims the bundle so the "import everything" headline is no
longer the only number.

#### Architecture

- **`runSingleFlight` + `runSingleFlightKeyed`**: 5 copies of the sentinel-
  compare in-flight pattern in `engine.ts` (`_loadPolicies`, `_loadRoles`,
  `_loadRbacPolicy`, `_loadAllPolicies`, `_resolveSubject`) collapsed to one
  helper. Same-class bugs (a missed sentinel in the merger) are now
  structurally impossible.
- **`runAdminAuthz` + `withAdminAudit`**: extracted from the 4 server
  adapters (express / hono / nest / next). The csrf + authorize + try +
  audit shape lives in one place. Future changes land in one file instead
  of four.
- **Per-Engine evaluation caches**: `regex` and `path` caches threaded
  end-to-end through `evaluate / evaluateFast / evaluatePolicy /
evaluatePolicyFast / matchCandidate / ruleApplies / evalConditionGroup /
evalCondition / resolve`. Multi-tenant deployments instantiate one
  Engine per tenant; each owns its own caches and cannot be evicted by
  hostile-tenant pattern flooding. `flushSharedCaches()` remains for
  legacy callers.
- **Drizzle typed selects**: 7 `as unknown as` casts at module-edge
  consolidated into 3 typed helpers (`_selectAll`, `_selectFirst`,
  `_selectWhere`). Type system is load-bearing again.
- **Adapter compliance suite** at `src/adapters/__compliance__/`. Every
  shipped adapter passes the same 21 scenarios. Caught a `revokeRole`
  drift in `MemoryAdapter` and `FileAdapter` (omitting `scope` should
  remove all matching role rows, not just the unscoped one).
- **Builder auto-validate**: `PolicyBuilder.build()` and
  `RoleBuilder.build()` run `validatePolicy` / `validateRole` and throw on
  error. Power-users wiring the adapter directly (bypassing
  `engine.admin.savePolicy`) see failures where the bug was introduced.

#### Bundle slim

- **Lazy validator**: `engine.libs.ts` admin write paths
  (`savePolicy / saveRole / import`) now `await import('../validate')` on
  first call. The 12 KB validator chunk is skipped entirely by read-only
  services.
- **Subpath splits**: `@gentleduck/iam/core/validate`,
  `@gentleduck/iam/core/builder`, `@gentleduck/iam/core/explain`,
  `@gentleduck/iam/core/schema` each ship as separate entries.
  Tree-shaking drops them for consumers that don't import the subpath.
- **Barrel cleanup**: `src/index.ts` no longer re-exports `FileAdapter`,
  `MemoryAdapter`, or the validator. Adapter consumers go through subpath
  imports (`@gentleduck/iam/adapters/memory`).
- **Drop 26 `@deprecated` 2.0->3.0 type aliases**. `.d.ts` surface clean.
  The deprecation window from 2.0.0 is closed; consumers were warned for
  two minor versions.
- **Forensic comments scrubbed**: 452 redundant `@author` JSDoc tags and
  326 audit-trail reference comments removed from source.

#### New APIs

- **`flushSharedCaches`** module-level export (`@gentleduck/iam` and
  `@gentleduck/iam/core`). The instance method `Engine#flushSharedCaches`
  is deprecated - it wiped process-globals despite being instance-bound.
- **`engine.preload({ validator: true })`** eagerly loads the lazy
  validator chunk at boot for operators who want every cost up front.
- **`engine.permissions(..., { telemetry: false })`** opt-out of per-check
  `onMetrics` + `signals` allocation. Restores 2.0.x throughput on hot UI
  gates where `authorize()` already captures the metrics signal.
- **`escapeHtml`** from `@gentleduck/iam/core/explain`. Safe HTML escape
  for consumers rendering `Explain.IResult.summary` into a debug panel.
- **`createEvalCaches`** from `@gentleduck/iam/core` constructs a fresh
  per-Engine cache pair if a consumer needs to build their own evaluator
  pipeline.
- **`splitPermissionKey`** from `@gentleduck/iam/shared/keys` reverses
  `buildPermissionKey` honouring escape sequences.

#### Tests

- 836 -> **943** (+107). The +107 is the new adapter compliance matrix
  applied to 5 adapters.

#### Stryker mutation testing scaffold

`bun run mutation` wires Stryker against engine + evaluate + conditions +
resolve + validate + server/generic + all 5 adapters. Not in CI by default
(5-15 min runtime); operators run on demand or via scheduled job.

#### Benchmarks

Measured baselines (2.0.1 from `git worktree` clean build, not eyeballed):

| Path                          | 2.0.1       | 2.1.0    | 2.2.0        |
| ----------------------------- | ----------- | -------- | ------------ |
| `evaluatePolicy` (conditions) | 1.33 µs     | 1.00 µs  | 1.00 µs      |
| `engine.can()` cached         | 4.86 µs     | 5.85 µs  | 5.18 µs      |
| `engine.permissions()` x20    | 20.06 µs    | 42.71 µs | 48.08 µs     |
| Bundle "import everything"    | **38.4 KB** | 44.8 KB  | **41.3 KB**  |
| Bundle realistic profile      | n/a         | n/a      | **15-25 KB** |

Net 2.0.1 -> 2.2.0 bundle delta: **+2.9 KB (+7.5%)**. Earlier docs cited
a ~21 KB pre-cycle number - that was estimated from a partial dist, not
a clean build. The full security cycle cost ~6 KB raw; the bundle slim
cycle recovered ~3 KB; net is +2.9 KB for fail-closed hook contracts,
per-Engine caches, default-on CSRF, and lazy validator scaffolding.

`engine.permissions(..., { telemetry: false })` cuts the batch path back
to ~22 µs for callers who opt out.

`engine.permissions(..., { telemetry: false })` cuts the batch path back
to ~22 µs for callers who opt out.

## 2.1.0

### Adversarial security audit cycle

A second multi-round audit pass after 2.0.0. Spans **21 rescan cycles** across two adversarial security-auditor agents plus a silent-failure hunter and a code-smell scanner. Resulted in **~60 fix commits** addressing 1 CRITICAL, 7 HIGH, 11 Medium, 12 Low, and 4 Info findings on top of the 2.0.0 hardening. Three consecutive clean rescans (Med+ free) declared the source tree exhausted: _"the package is genuinely hard to break."_

The change set is **mostly backward compatible** with two notable defaults:

1. **Hono `accessMiddleware` + `guard` no longer default to `x-user-id` header**. Spoofable. Now reads only `c.get('userId')` populated by upstream auth. Operators relying on the header must wire `getUserId` explicitly.
2. **Next `withAccess` requires `getUserId`**. Previous default also trusted the header. Throws at construction when omitted.
3. **Admin routers CSRF-check by default** (CAVEAT-2). New `defaultCsrfCheck` rejects browser requests with `Sec-Fetch-Site: cross-site|cross-origin`. Bearer/mTLS APIs opt out via `csrfCheck: false`. Cookie-auth admin UIs get protection without any opt-in.

#### CRITICAL (1)

- `FileAdapter._loadState` swallowed every `readFile` error and silently fell back to an empty store. EACCES (permissions drift), EISDIR (path overwritten), EIO (disk corruption) became `{policies:{},roles:{},...}`. With `defaultEffect:'allow'+allowFailOpen` this is total silent fail-open; with `'deny'` it's total silent outage. Only `ENOENT` now recovers as empty; everything else throws a wrapped Error.

#### HIGH (7)

- HTTP adapter followed fetch redirects without re-validation. A 302 to `169.254.169.254` or `10.0.0.5:6379` bypassed the construction-time `allowedHosts` / private-IP guard. `_fetchOnce` now passes `redirect: 'error'`.
- `_emitMetrics` invoked `onMetrics` without a try/catch. A throwing operator hook escaped `authorize`'s catch arm and replaced the documented fail-closed deny with a raw error. Wrapped via `_safeHookCall`; double-wrapped around `console.error` itself.
- `afterEvaluate` / `onDeny` ran inside `authorize`'s main try block; throws caught by the evaluation catch silently rewrote an allow verdict into a fail-closed deny. Trailing hooks now run outside the evaluation try; throws routed to console.error without reshaping the decision.
- `engine.permissions()` passed `undefined` for `onPolicyError` to evaluator - per-policy throws vanished. UI gates silently allowed under `defaultEffect:'allow'`. Now forwards the same shim `authorize()` uses.
- Redis + Drizzle `getSubjectAttributes` returned `{}` on JSON.parse failure or non-object root. ABAC conditions silently flipped to deny. Now throws; engine routes through `onError` + fail-closed deny.
- `FileAdapter` JSON parse failure silently populated `_cache = {}`. Next `_flush()` overwrote the recoverable-but-corrupt file. **Permanent data destruction triggered by a single transient parse error.** Now throws "store corrupt - refusing to load; restore from backup before retrying".
- `can()` / `check()` invoked `this._hooks.onError?.()` unwrapped - /058 throws routed through these catches; a throwing operator `onError` propagated as unhandled rejection. Now `_safeHookCall`.
- Hono / Next default `getUserId` trusted spoofable `x-user-id` header. **Trivial auth bypass via curl.** Hono: no header fallback. Next: required option, throws on construction without it.

#### Medium (11)

- Admin write path skipped validation. Hostile admin (or buggy UI) could persist a policy that adapter read-side validator silently drops -> tenant ends up with zero policies -> `defaultEffect` decides every request. `createAdmin.savePolicy / saveRole / import` now call `validatePolicy / validateRole` and throw on error.
- `assertValidOrThrow` echoed attacker-controlled values (`Invalid algorithm "<value>"`). Operator who opted into `includeErrorMessage:true` + HTTP body echo got a probe oracle. Now emits `INVALID_ALGORITHM at "algorithm"` - structural codes only.
- Redis migration vs `revokeRole` race. `_migrateLegacyAssignment`'s SADD-then-SREM let migrator resurrect a just-revoked assignment. `_runSerialised` per-key chain orders writes; revoke now SREMs both encodings.
- File `_assertWithinRoot` ran once per adapter; attacker swapping the file for a symlink after first I/O steered subsequent writes. Drops latch; realpath re-checks every read/write.
- `_assertWithinRoot` outside the load try; rejected promise stuck forever in `_loadInFlight`. Restructure clears in-flight via finally on any throw.
- caused admin lockout: `setSubjectAttributes` called the getter first, getter now throws on corrupt existing data -> operator could not overwrite. Setter catches the throw, logs, treats existing as `{}`.
- HTTP adapter `getSubjectRoles` forwarded server response verbatim; other adapters enforce unscoped-only. JSDoc now documents operator's contract responsibility.
- Admin router shipped without CSRF guidance. Cookie-auth deployments exposed to cross-site forms. Optional `csrfCheck` added to all 4 framework adapters; default-on via `defaultCsrfCheck` (CAVEAT-2).
- `engine.permissions()` had no outer try around `Promise.all([_resolveSubject, _loadAllPolicies])`. Adapter rejection crashed the whole batch without `onError` + fail-closed map. Now wraps in try; returns all-deny map keyed by every requested check + invokes `onError`.
- `_loadAllPolicies` merger had no in-flight sentinel; concurrent invalidate-mid-load repopulated stale data. Added `_mergedInFlight` sentinel.
- `getSubjectRoles` semantic drift: file/memory returned unscoped-only; redis/drizzle/prisma returned all collapsed. Same subject resolved differently across backends. Aligned all to unscoped-only; documented in `Adapter.ISubjectStore`.

#### Low (12)

- No way to chart fail-open rate. Added `failOpen: boolean` to `IMetricsEvent` + counter to `createMetricsAggregator`. Threaded through `evaluate`/`evaluateFast` via optional `IEvalSignals`.
- Redis invalidator v:1 envelope was unwrapped without HMAC verification when `secret: null` - attacker chose `instanceId`, silenced legitimate cross-instance invalidates. v:1 in unsigned mode now dropped + warned.
- `permissions()` bypassed `_emitMetrics` entirely; dashboards charting fail-open missed every batch UI gate. Now emits per check.
- File `rootDir` warn fired every construction -> log spam -> operators filter the warning. Module-global latch fires once per process.
- File warn echoed resolved path -> path-existence oracle via log scraping. Path stripped from message.
- Redis invalidator one-shot per-channel warn latch let attacker burn the first warn on a benign reason then silently flood. Replaced with 60s rate-limit + suppressed-count surfacing.
- `errorToAuditString(includeMessage=true)` returned raw `String(err)` for non-Error throws - unbounded leak. Now tagged `<non-Error <typeof>>` + capped at 256 chars + `JSON.stringify` fallback.
- Devtools `localStorage` prefix `__IAM_DEVTOOLS` -> vendor-namespaced `__GENTLEDUCK_IAM_DEVTOOLS_V1`.
- `_assertWithinRoot` parent-realpath fallback fired on ANY error; ELOOP / EACCES bypassed symlink check via reconstructed path. Now gated on `code === 'ENOENT'`.
- Vanilla client listener-throw was totally silent. `console.error` surfacing.
- Invalidator dropped shape-mismatched inner payloads without `warnDropOnce` - operators saw nothing on sustained schema drift. Routed through warn.
- Invalidator `publish()` failure silently swallowed. Added optional `onPublishError(err, channel)` hook + rate-limited console fallback.
- `_safeHookCall` / `_emitMetrics` called `console.error` unwrapped; throwing logger (closed stdout, broken pipe) would resurrect . Defensive double-wrap.
- `dt/lib/flow.ts` listener `catch{}` silent. console.error added.
- Vanilla `extractAction` split key on `:` naively; resources containing `:` mis-tokenised. Added `splitPermissionKey` that honours `\\:`/`\\\\` escapes from `buildPermissionKey`.

#### Info (4)

- `createNextMiddleware` JSDoc example demonstrated the unsafe pattern. Replaced with `getServerSession` example + warning.
- Only express had a CSRF regression test; hono/next/nest needed parity. Added.
- **INFO-A** `LRUCache` + Engine `maxPolicies/maxRoles/adapterTimeoutMs` accepted NaN (silently disabled bound). Now `Number.isFinite` required.
- **INFO-B** `Explain.IResult.summary` is plain text with attacker-influenced values; consumers rendering as HTML must escape. JSDoc added.

#### Deployment hardening (CAVEAT-1/2/3 + )

- **CAVEAT-1**: `createRedisInvalidator({ tenantId })` auto-prefixes the channel `'duck-iam:invalidate:tenant:${tenantId}'`. Validates `tenantId` against `/^[A-Za-z0-9_-]{1,64}$/` so attacker-controlled tenant slugs cannot inject pub/sub wildcards.
- **CAVEAT-2**: Admin routers default-on CSRF via `defaultCsrfCheck` (Sec-Fetch-Site check). `csrfCheck: false` opts out for bearer/mTLS APIs.
- **CAVEAT-3**: `SECURITY.md` adds a 10-section **Deployment Hardening Guide** covering identity sourcing, admin CSRF, Redis tenancy, cache scoping, `defaultEffect:'allow'`, `explain()` output trust, adapter trust, file `rootDir`, HTTP `allowedHosts`, observability wiring.
- \*\*\*\*: `getCachedRegex` / `getSegments` accept optional per-instance cache override. `clearRegexCache()` / `clearPathCache()` exported. `Engine.flushSharedCaches()` ergonomic operator API for multi-tenant deployments.

#### New APIs (additive)

- `Engine.flushSharedCaches()` - wipe process-wide regex + path caches.
- `defaultCsrfCheck(req)` - exported from `server/generic`; built-in Sec-Fetch-Site predicate.
- `AdminAudit.IOptions.csrfCheck?: ((req) => boolean) | false`.
- `RedisInvalidator.IConfig.tenantId?: string`.
- `RedisInvalidator.IConfig.onPublishError?: (err, channel) => void`.
- `IMetricsEvent.failOpen: boolean`.
- `Metrics.ISnapshot.failOpen: number`.
- `splitPermissionKey(key)` - exported from `shared/keys`; escape-aware split.
- `clearRegexCache()` / `clearPathCache()` - process-wide cache flush.
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

- 785 -> **836** tests (+51).
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
