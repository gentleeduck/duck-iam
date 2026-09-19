import { IamLRUCache } from '../../shared/cache'
import { iamBuildPermissionKey } from '../../shared/keys'
import { iamIsReservedRefusal } from '../../shared/reserved'
import { iamAsRoleLiteral } from '../../shared/tenant-literals'
import { clearRegexCache } from '../conditions/conditions.libs'
import { VALID_POLICY_COMBINES } from '../evaluate'
import { evaluate } from '../evaluate/evaluate'
import type { Explain } from '../explain'
import { clearPathCache } from '../resolve/resolve'
import type { AccessControl, IamAdapter, IamClient, IamRequest } from '../types'
import { IamPolicyCompileError, IamRoleLimitExceededError } from './compiled/compiled.errors'
import { lookup } from './compiled/compiled.lookup'
import type { CompiledTable } from './compiled/compiled.types'
import { type Bound, buildBoundEngine } from './engine.bound'
import { DEFAULT_HOOK_TIMEOUT_MS, emitMetrics, isThenable, safeHookCall } from './engine.hooks'
import {
  applyInvalidateEvent,
  type IEngineCacheBag,
  type IEngineInFlightBag,
  invalidateAll,
  invalidatePolicies,
  invalidateRoles,
  invalidateSubject,
} from './engine.invalidation'
import { createAdmin, enrichSubjectWithScopedRoles, ensureEnvNow } from './engine.libs'
import { disposeInvalidator, preloadEngine, runHealthCheck } from './engine.lifecycle'
import { type IIamLoaderDeps, loadAllPolicies, loadPolicies, loadRoles, resolveSubject } from './engine.loaders'
import { resetStats as resetStatsHelper, statsSnapshot as statsSnapshotHelper } from './engine.stats'
import type { IamEngineTypes } from './engine.types'

/**
 * Default cap on concurrent cold-subject adapter loads; `0` means unbounded.
 * NOTE: shedding denies real traffic, so keep this well above normal concurrency.
 */
const DEFAULT_MAX_CONCURRENT_SUBJECT_LOADS = 512

/**
 * Clears the process-global regex and dot-path caches used by direct `evaluate()` calls and `explain()`.
 * NOTE: engine checks use per-instance caches this does not touch, so it is not a multi-tenancy measure.
 */
export function iamFlushSharedCaches(): void {
  clearRegexCache()
  clearPathCache()
}

/** Shape check for {@link IamEngine.setInvalidator}, so a missing `subscribe` fails now, not as lost invalidations. */
function isInvalidatorLike<TRole extends string>(value: unknown): value is IamEngineTypes.IInvalidator<TRole> {
  if (value === null || typeof value !== 'object') return false
  if (!('publish' in value) || !('subscribe' in value)) return false
  return typeof value.publish === 'function' && typeof value.subscribe === 'function'
}

/**
 * Reads an invalidator's optional `status()` for {@link IamEngine.healthCheck}; `broken` flags a bad implementation.
 * NOTE: never throws, so a broken invalidator cannot take down the health probe.
 */
function readInvalidatorSubscribed(
  invalidator: unknown,
): { ok: true; subscribed: boolean } | { ok: false; broken: boolean } {
  if (invalidator === null || typeof invalidator !== 'object') return { broken: false, ok: false }
  if (!('status' in invalidator) || invalidator.status === undefined) return { broken: false, ok: false }
  if (typeof invalidator.status !== 'function') return { broken: true, ok: false }
  let reported: unknown
  try {
    reported = invalidator.status()
  } catch {
    return { broken: true, ok: false }
  }
  if (reported === null || typeof reported !== 'object') return { broken: true, ok: false }
  if (!('subscribed' in reported) || typeof reported.subscribed !== 'boolean') return { broken: true, ok: false }
  return { ok: true, subscribed: reported.subscribed }
}

/** One bit per directly held role; `compileTable` already folds inherited grants into `table.allow`. */
function maskFromRoles(table: CompiledTable, roles: readonly string[]): number {
  let mask = 0
  for (const roleName of roles) {
    const idx = table.roleId.get(roleName)
    if (idx !== undefined) mask |= 1 << idx
  }
  return mask
}

/**
 * Evaluates access requests against RBAC roles and ABAC policies loaded and cached from its adapter.
 * Decisions combine across policies per `policyCombine` (default `'and'`; see {@link AccessControl.PolicyCombine}).
 *
 * @template TAction   - Union of valid action strings.
 * @template TResource - Union of valid resource strings.
 * @template TRole     - Union of valid role IDs.
 * @template TScope    - Union of valid scope strings.
 * @template TMode     - `'production'` returns `boolean`; `'development'` returns `IDecision`.
 *
 * @example
 * ```ts
 * const engine = new IamEngine({ adapter, defaultEffect: 'deny' })
 *
 * const allowed = await engine.can('user-1', 'read', { type: 'post', attributes: {} })
 * const decision = await engine.check('user-1', 'update', post)
 * const trace = await engine.explain('user-1', 'delete', post)
 * ```
 */
export class IamEngine<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
  TMode extends AccessControl.Mode = 'production',
> {
  private _adapter: IamAdapter.IAdapter<TAction, TResource, TRole, TScope>
  private _defaultEffect: AccessControl.Effect
  private _mode: AccessControl.Mode
  private _policyCombine: AccessControl.PolicyCombine
  private _scopeMode: 'flat' | 'hierarchical'
  private _scopeCombine: 'union' | 'override'
  /** The verdict source in both modes. Built on first use; rebuilt after a policy/role invalidation or `cacheTTL`. */
  private _compiledTable: CompiledTable | null = null
  /** `Date.now()` when `_compiledTable` was committed - the TTL clock, mirroring the LRU caches'. */
  private _compiledTableBuiltAt = 0
  private _hooks: IamEngineTypes.IHooks<TAction, TResource, TScope>
  private _maxPolicies: number
  private _maxRoles: number
  private _adapterTimeoutMs: number
  private _hookTimeoutMs: number
  private _maxConcurrentSubjectLoads: number
  private _invalidator?: IamEngineTypes.IInvalidator<TRole>
  /** Retained whole so {@link IamEngine.withTransaction} can re-make this engine with only the adapter swapped. */
  private readonly _config: IamEngineTypes.IConfig<TAction, TResource, TRole, TScope, TMode>
  private _invalidatorUnsub: (() => void) | null = null
  /** One-shot: a broken `status()` is warned about once, not once per probe. */
  private _invalidatorStatusWarned = false
  private _policyCache: IamLRUCache<AccessControl.IPolicy[]>
  private _roleCache: IamLRUCache<AccessControl.IRole[]>
  private _rbacPolicyCache: IamLRUCache<AccessControl.IPolicy>
  private _mergedPolicyCache: IamLRUCache<AccessControl.IPolicy[]>
  private _subjectCache: IamLRUCache<IamRequest.ISubject>
  // Single-flight slots, so concurrent cache misses share one adapter call. Cleared once the promise settles.
  private _inFlight: IEngineInFlightBag = {
    policies: { value: null },
    roles: { value: null },
    rbac: { value: null },
    merged: { value: null },
    subjects: new Map(),
  }
  /** SECURITY: per-instance regex and path caches, so one tenant's engine cannot flood another's. */
  private _caches: { regex: Map<string, RegExp>; path: Map<string, string[] | null> } = {
    regex: new Map(),
    path: new Map(),
  }

  /**
   * Cache invalidation, for writes made outside `engine.admin`.
   * Pass `{ broadcast: false }` when applying an event received from another instance.
   *
   * @since 3.0.0
   */
  readonly cache = {
    /** Clear every cache + in-flight resolver. */
    invalidate: (opts: { broadcast?: boolean } = {}): void => this._invalidateAll(opts),
    /** Clear one subject's cached resolved roles + attributes. */
    invalidateSubject: (subjectId: string, opts: { broadcast?: boolean } = {}): void =>
      this._invalidateSubject(subjectId, opts),
    /** Clear cached policies (after policy CRUD). */
    invalidatePolicies: (opts: { broadcast?: boolean } = {}): void => this._invalidatePolicies(opts),
    /** Clear cached roles + RBAC policy; selectively drops affected subjects. */
    invalidateRoles: (roleId?: TRole, opts: { broadcast?: boolean } = {}): void => this._invalidateRoles(roleId, opts),
  }

  /**
   * Per-cache hit, miss and size counters.
   *
   * @since 3.0.0
   */
  readonly stats = {
    /** Snapshot per-cache counters. Counters accumulate from construction. */
    get: (): {
      policies: { hits: number; misses: number; size: number }
      roles: { hits: number; misses: number; size: number }
      rbacPolicy: { hits: number; misses: number; size: number }
      mergedPolicies: { hits: number; misses: number; size: number }
      subjects: { hits: number; misses: number; size: number }
    } => this._statsSnapshot(),
    /** Zero the counters returned by `stats.get`. */
    reset: (): void => this._resetStats(),
  }

  /** Throws on an invalid config, such as an unknown `policyCombine` or `defaultEffect: 'allow'` without opt-in. */
  constructor(config: IamEngineTypes.IConfig<TAction, TResource, TRole, TScope, TMode>) {
    this._config = config
    this._adapter = config.adapter
    this._defaultEffect = config.defaultEffect ?? 'deny'
    this._mode = config.mode ?? 'production'
    this._policyCombine = config.policyCombine ?? 'and'
    this._scopeMode = config.scopeMode ?? 'flat'
    this._scopeCombine = config.scopeCombine ?? 'union'
    this._hooks = config.hooks ?? {}

    // SECURITY: both evaluators treat an unknown value as first-applicable, the most permissive combine.
    if (!VALID_POLICY_COMBINES.includes(this._policyCombine)) {
      throw new Error(
        `[@gentleduck/iam:engine] unknown policyCombine ${JSON.stringify(this._policyCombine)}. Must be one of: ${VALID_POLICY_COMBINES.join(', ')}.`,
      )
    }

    // evaluateFast can't represent first-applicable; fail at construction.
    if (this._mode === 'production' && this._policyCombine === 'first-applicable') {
      throw new Error(
        "[@gentleduck/iam:engine] policyCombine 'first-applicable' requires mode 'development'; the production fast path cannot represent it correctly.",
      )
    }

    // `defaultEffect: 'allow'` is a fail-open footgun; require explicit opt-in.
    if (this._defaultEffect === 'allow' && !config.allowFailOpen) {
      throw new Error(
        "[@gentleduck/iam:engine] defaultEffect 'allow' is a fail-open footgun. Pass `allowFailOpen: true` to confirm intent.",
      )
    }
    // Warn even with the opt-in, so a log search for fail-open configs finds it.
    if (this._defaultEffect === 'allow') {
      console.warn(
        "[@gentleduck/iam:engine] engine configured with defaultEffect: 'allow' (fail-open). Every request with no applicable policy will be allowed.",
      )
    }

    this._maxPolicies = config.maxPolicies ?? 10_000
    this._maxRoles = config.maxRoles ?? 10_000
    this._adapterTimeoutMs = config.adapterTimeoutMs ?? 5_000
    this._hookTimeoutMs = config.hookTimeoutMs ?? DEFAULT_HOOK_TIMEOUT_MS
    this._maxConcurrentSubjectLoads = config.maxConcurrentSubjectLoads ?? DEFAULT_MAX_CONCURRENT_SUBJECT_LOADS

    // SECURITY: reject non-finite caps; `NaN > x` is always false, so a NaN limit disables the bound.
    if (!Number.isFinite(this._maxPolicies) || this._maxPolicies < 1) {
      throw new RangeError('[@gentleduck/iam:engine] maxPolicies must be a finite number >= 1')
    }
    if (!Number.isFinite(this._maxRoles) || this._maxRoles < 1) {
      throw new RangeError('[@gentleduck/iam:engine] maxRoles must be a finite number >= 1')
    }
    if (!Number.isFinite(this._adapterTimeoutMs) || this._adapterTimeoutMs < 0) {
      throw new RangeError('[@gentleduck/iam:engine] adapterTimeoutMs must be a finite number >= 0')
    }
    if (!Number.isFinite(this._hookTimeoutMs) || this._hookTimeoutMs < 0) {
      throw new RangeError('[@gentleduck/iam:engine] hookTimeoutMs must be a finite number >= 0')
    }
    // 0 means unbounded (same convention as adapterTimeoutMs); anything else must be a real cap.
    if (
      !Number.isFinite(this._maxConcurrentSubjectLoads) ||
      (this._maxConcurrentSubjectLoads !== 0 && this._maxConcurrentSubjectLoads < 1)
    ) {
      throw new RangeError(
        '[@gentleduck/iam:engine] maxConcurrentSubjectLoads must be 0 (unbounded) or a finite number >= 1',
      )
    }

    const ttl = (config.cacheTTL ?? 60) * 1000
    const maxSize = config.maxCacheSize ?? 1000
    this._cacheTTL = ttl

    this._policyCache = new IamLRUCache(1, ttl) // single entry
    this._roleCache = new IamLRUCache(1, ttl)
    this._rbacPolicyCache = new IamLRUCache(1, ttl)
    this._mergedPolicyCache = new IamLRUCache(1, ttl)
    this._subjectCache = new IamLRUCache(maxSize, ttl)

    // Through the setter, so construction and late attach validate and subscribe the same way.
    if (config.invalidator) this.setInvalidator(config.invalidator)
  }

  /**
   * Runs an adapter call under `adapterTimeoutMs`, aborting its signal and throwing on expiry.
   * SECURITY: the timeout error reaches the entry point's catch, which denies.
   */
  private _withTimeout<T>(fn: (opts: { signal: AbortSignal }) => Promise<T>, label: string): Promise<T> {
    if (this._adapterTimeoutMs <= 0) {
      return fn({ signal: new AbortController().signal })
    }
    const ctrl = new AbortController()
    let timer: ReturnType<typeof setTimeout> | null = null
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        ctrl.abort()
        reject(new Error(`[@gentleduck/iam:engine] ${label} timed out after ${this._adapterTimeoutMs}ms`))
      }, this._adapterTimeoutMs)
    })
    return Promise.race<T>([fn({ signal: ctrl.signal }), timeout]).finally(() => {
      if (timer) clearTimeout(timer)
    })
  }

  /** @internal Build the cache-bag the helper modules use to mutate state. */
  private _cacheBag(): IEngineCacheBag<TRole> {
    return {
      policyCache: this._policyCache,
      roleCache: this._roleCache,
      rbacPolicyCache: this._rbacPolicyCache,
      mergedPolicyCache: this._mergedPolicyCache,
      subjectCache: this._subjectCache,
      inFlight: this._inFlight,
      ...(this._invalidator !== undefined && { invalidator: this._invalidator }),
    }
  }

  /** Apply a cross-instance invalidate event to local caches. */
  private _applyInvalidateEvent(event: IamEngineTypes.IInvalidateEvent<TRole>): void {
    applyInvalidateEvent(this._cacheBag(), event)
    if (event.kind === 'all' || event.kind === 'policies' || event.kind === 'roles') {
      this._compiledTable = null
      this._compiledTableGen++
    }
    // Replicas drop the role-limit latch too, or only the instance that deleted roles would recover.
    if (event.kind === 'all' || event.kind === 'roles') this._clearRoleLimitLatch()
  }

  /**
   * Attaches, replaces or detaches the invalidator after construction, for a client built after the engine.
   * The previous one is unsubscribed first. Transaction views flush through whatever is attached at flush time.
   *
   * @param invalidator - The broadcaster to attach, or `null` to detach.
   * @throws When `invalidator` is neither `null` nor an object with `publish` and `subscribe` methods.
   */
  setInvalidator(invalidator: IamEngineTypes.IInvalidator<TRole> | null): void {
    if (invalidator !== null && !isInvalidatorLike(invalidator)) {
      throw new TypeError(
        '[@gentleduck/iam:engine] setInvalidator: expected null or an object with `publish` and `subscribe` methods',
      )
    }
    // Unsubscribe first, so a throwing `subscribe` cannot leave the old subscription attached.
    this._invalidatorUnsub = disposeInvalidator(this._invalidatorUnsub).unsub
    if (invalidator === null) {
      this._invalidator = undefined
      return
    }
    this._invalidator = invalidator
    this._invalidatorUnsub = invalidator.subscribe((event) => this._applyInvalidateEvent(event))
  }

  /** Release the invalidator subscription. Call when discarding the engine. */
  dispose(): void {
    this._invalidatorUnsub = disposeInvalidator(this._invalidatorUnsub).unsub
  }

  /** @internal Build the loader deps. */
  private _loaderDeps(): IIamLoaderDeps<TAction, TResource, TRole, TScope> {
    return {
      adapter: this._adapter,
      policyCache: this._policyCache,
      roleCache: this._roleCache,
      rbacPolicyCache: this._rbacPolicyCache,
      mergedPolicyCache: this._mergedPolicyCache,
      subjectCache: this._subjectCache,
      inFlight: this._inFlight,
      maxPolicies: this._maxPolicies,
      maxRoles: this._maxRoles,
      maxConcurrentSubjectLoads: this._maxConcurrentSubjectLoads,
      scopeMode: this._scopeMode,
      withTimeout: (fn, label) => this._withTimeout(fn, label),
    }
  }

  private _resolveSubject(subjectId: string): Promise<IamRequest.ISubject> {
    return resolveSubject(this._loaderDeps(), subjectId)
  }

  private _loadAllPolicies(): Promise<AccessControl.IPolicy[]> {
    return loadAllPolicies(this._loaderDeps())
  }

  private _loadRoles(): Promise<AccessControl.IRole[]> {
    return loadRoles(this._loaderDeps())
  }

  /** `cacheTTL` in ms, kept for the compiled table - the LRU caches hold their own copy. */
  private _cacheTTL: number

  /** In-flight rebuild, so concurrent cold callers share one compile. */
  private _compiledTableBuild: Promise<CompiledTable> | null = null
  /** The generation `_compiledTableBuild` was started under - see `_rebuildCompiledTable`. */
  private _compiledTableBuildGen = -1
  /** Bumped by every invalidation, so a build started earlier cannot overwrite the cleared table with stale data. */
  private _compiledTableGen = 0

  /**
   * The current compiled table, rebuilt when missing or past `cacheTTL`; `null` routes the caller to the interpreter.
   * `null` means over 32 roles or `'first-applicable'`. SECURITY: any other compile failure throws, and so denies.
   */
  private async _getCompiledTable(): Promise<CompiledTable | null> {
    if (this._roleLimitExceeded) return null
    // `lookup()` would fold 'first-applicable' as 'and', and development takes the table as authoritative,
    // so the interpreter takes the whole combine.
    if (this._policyCombine === 'first-applicable') return null
    const table = this._compiledTable
    if (table !== null && !this._compiledTableExpired()) return table
    try {
      return await this._rebuildCompiledTable()
    } catch (err) {
      if (!(err instanceof IamRoleLimitExceededError)) throw err
      this._roleLimitExceeded = true
      this._roleLimitDetail = { limit: err.limit, roleCount: err.roleCount }
      if (!this._roleLimitReported) {
        this._roleLimitReported = true
        // Once, not per request, so the slower path is never silent.
        console.warn(err.message)
      }
      return null
    }
  }

  /**
   * One evaluation. The compiled table gives the verdict in both modes; development also runs the interpreter
   * for `reason`/`policy`/`rule`, and throws if they disagree. With no table, both modes use the interpreter alone.
   */
  private async _evaluateOnce(
    req: IamRequest.IAccessRequest<TAction, TResource, TScope>,
    onPolicyError: ((err: Error, policy: AccessControl.IPolicy) => void) | undefined,
    signals: { failOpen?: boolean },
  ): Promise<{ allowed: boolean; decision?: AccessControl.IDecision }> {
    const table = await this._getCompiledTable()

    if (table === null) {
      const decision = await this._interpret(req, onPolicyError, signals)
      return this._mode === 'production' ? { allowed: decision.allowed } : { allowed: decision.allowed, decision }
    }

    const compiled = lookup(
      table,
      maskFromRoles(table, req.subject.roles),
      req.action,
      req.resource.type,
      req,
      this._defaultEffect,
      onPolicyError,
      signals,
      this._caches,
    )

    if (this._mode === 'production') return { allowed: compiled }

    // The explanatory run is silent: no `onPolicyError` (the table run already reported; the handler never changes
    // the verdict) and its own `signals`.
    const interpreterSignals: { failOpen?: boolean } = {}
    const decision = await this._interpret(req, undefined, interpreterSignals)

    if (decision.allowed !== compiled) {
      const message =
        `[@gentleduck/iam:engine] compiled table and interpreter disagree on ` +
        `${req.action} ${req.resource.type}${req.resource.id === undefined ? '' : `:${req.resource.id}`}` +
        `${req.scope === undefined ? '' : ` @${req.scope}`} for roles [${req.subject.roles.join(', ')}]: ` +
        `table=${compiled ? 'allow' : 'deny'}, interpreter=${decision.allowed ? 'allow' : 'deny'} ` +
        `(interpreter reason: ${decision.reason}). This is a duck-iam bug - production would have ` +
        `answered "${compiled ? 'allow' : 'deny'}" while this development run says ` +
        `"${decision.allowed ? 'allow' : 'deny'}". Please report it with the policy set that reproduces it.`
      // Printed as well as thrown: `authorize()` turns the throw into a generic deny. Not rate-limited, since
      // it fires only on a duck-iam bug.
      console.error(message)
      throw new Error(message)
    }

    // Report the interpreter's decision for its provenance; a fail-open seen by either run counts.
    if (interpreterSignals.failOpen === true) signals.failOpen = true
    return { allowed: compiled, decision }
  }

  /** The interpreter path, shared by every caller so the two can never drift. */
  private async _interpret(
    req: IamRequest.IAccessRequest<TAction, TResource, TScope>,
    onPolicyError: ((err: Error, policy: AccessControl.IPolicy) => void) | undefined,
    signals: { failOpen?: boolean },
  ): Promise<AccessControl.IDecision> {
    const allPolicies = await this._loadAllPolicies()
    return evaluate(allPolicies, req, this._defaultEffect, this._policyCombine, onPolicyError, signals, this._caches)
  }

  /** Set once the role count has outrun the compiled table; see {@link IamEngine._getCompiledTable}. */
  private _roleLimitExceeded = false
  private _roleLimitReported = false
  private _roleLimitDetail: { roleCount: number; limit: number } | null = null

  /** `cacheTTL: 0` means "do not cache", the same reading `IamLRUCache` gives it. */
  private _compiledTableExpired(): boolean {
    return Date.now() - this._compiledTableBuiltAt >= this._cacheTTL
  }

  /** Set once a compile failure has been reported, so the log carries one line, not one per request. */
  private _compileFailureReported = false

  /**
   * Compiles, logging the first failure once, since every request then denies. Every failure is rethrown.
   * Not logged: {@link IamRoleLimitExceededError} (it falls back) and {@link IamPolicyCompileError} (`onPolicyError`).
   */
  private _compileOrReport(
    compileTable: (
      roles: readonly AccessControl.IRole[],
      policies: readonly AccessControl.IPolicy[],
      policyCombine: AccessControl.PolicyCombine,
      scopeMode: 'flat' | 'hierarchical',
    ) => CompiledTable,
    roles: AccessControl.IRole[],
    policies: AccessControl.IPolicy[],
  ): CompiledTable {
    try {
      return compileTable(roles, policies, this._policyCombine, this._scopeMode)
    } catch (err) {
      if (err instanceof IamRoleLimitExceededError) throw err
      if (err instanceof IamPolicyCompileError) {
        // Sync, so not `_safeHookCall`; a throwing hook must not replace the compile error.
        try {
          this._hooks.onPolicyError?.(err, err.policyId)
        } catch {}
        throw err
      }
      if (!this._compileFailureReported) {
        this._compileFailureReported = true
        console.error(
          `[@gentleduck/iam:engine] the compiled table could not be built; every request will be denied until this is fixed. ${err instanceof Error ? err.message : String(err)}`,
        )
      }
      throw err
    }
  }

  /**
   * The build time to record: now, or when the oldest cached input was read, whichever is earlier.
   * SECURITY: stamping `Date.now()` would give a table built from nearly expired roles a second full `cacheTTL`.
   */
  private _derivedBuiltAt(deps: {
    roleCache: IamLRUCache<AccessControl.IRole[]>
    policyCache: IamLRUCache<AccessControl.IPolicy[]>
  }): number {
    const now = Date.now()
    const oldestExpiry = Math.min(
      deps.roleCache.expiresAt('all') ?? Number.POSITIVE_INFINITY,
      deps.policyCache.expiresAt('all') ?? Number.POSITIVE_INFINITY,
    )
    if (!Number.isFinite(oldestExpiry)) return now
    // An entry expiring at E was read at E - cacheTTL; a capped entry reads older still, the safe direction.
    return Math.min(now, oldestExpiry - this._cacheTTL)
  }

  /**
   * Builds the table from roles and raw policies (not the RBAC-merged view, which would double-count `__rbac__`).
   * NOTE: an in-flight build is reused only within its generation, so no caller gets pre-invalidation data.
   */
  private _rebuildCompiledTable(): Promise<CompiledTable> {
    if (this._compiledTableBuild && this._compiledTableBuildGen === this._compiledTableGen) {
      return this._compiledTableBuild
    }
    const gen = this._compiledTableGen
    const deps = this._loaderDeps()
    const build = (async () => {
      const [roles, policies] = await Promise.all([this._loadRoles(), loadPolicies(deps)])
      const { compileTable } = await import('./compiled/compiled.compile')
      const table = this._compileOrReport(compileTable, roles, policies)
      // An invalidation that landed mid-build wins; do not store this table.
      if (this._compiledTableGen === gen) {
        this._compiledTable = table
        this._compiledTableBuiltAt = this._derivedBuiltAt(deps)
      }
      return table
    })()
    this._compiledTableBuild = build
    this._compiledTableBuildGen = gen
    // INFO: an unawaited `.finally()` chain re-reports the rejection as unhandled, so catch it here.
    build
      .finally(() => {
        if (this._compiledTableBuild === build) this._compiledTableBuild = null
      })
      .catch(() => {})
    return build
  }

  /** Bridges the runtime `this._mode` branch to `AccessControl.ModeResult<TMode>`; the one place that asserts it. */
  private _asResult(value: boolean | AccessControl.IDecision): AccessControl.ModeResult<TMode> {
    return value as AccessControl.ModeResult<TMode>
  }

  /**
   * Checks a complete {@link IamRequest.IAccessRequest}: a `boolean` in production, an `IDecision` in development.
   * SECURITY: any evaluation error is reported to `onError` and denies.
   */
  async authorize(
    request: IamRequest.IAccessRequest<TAction, TResource, TScope>,
  ): Promise<AccessControl.ModeResult<TMode>> {
    let req = request
    // Also for `afterEvaluate`/`onDeny`, whose production decision needs a real `duration`.
    const t0 = this._hooks.onMetrics || this._hooks.afterEvaluate || this._hooks.onDeny ? performance.now() : 0

    // Trailing hooks run outside the evaluation try; a thrown hook must not
    // rewrite an allow into deny via the catch.
    let result: AccessControl.ModeResult<TMode>
    let decisionForHooks: AccessControl.IDecision | null = null
    let allowedForMetrics = false
    let failOpenForMetrics = false
    try {
      // Normalise non-array roles; string would substring-match `contains <role>`.
      if (req.subject && !Array.isArray(req.subject.roles)) {
        req = { ...req, subject: { ...req.subject, roles: [] } }
      }
      if (req.scope && req.subject.scopedRoles?.length) {
        const enriched = enrichSubjectWithScopedRoles(req.subject, req.scope, this._scopeMode, this._scopeCombine)
        if (enriched !== req.subject) req = { ...req, subject: enriched }
      }

      if (this._hooks.beforeEvaluate) {
        req = await this._runBeforeEvaluate(req)
      }

      // Default the clock after the hook, so a hook-pinned `now` wins.
      req = ensureEnvNow(req)

      const onPolicyErrorHook = this._hooks.onPolicyError
      const onPolicyError = onPolicyErrorHook
        ? (err: Error, policy: AccessControl.IPolicy) => onPolicyErrorHook(err, policy.id)
        : undefined

      // SECURITY: the reserved refusal token (an unmappable method or path) denies before any policy, since a `'*'`
      // rule would match it. Inside the try so the hooks see this denial like any other.
      if (iamIsReservedRefusal(req.action) || iamIsReservedRefusal(req.resource?.type)) {
        const refusal = this._reservedRefusalDecision()
        decisionForHooks = refusal
        result = this._asResult(this._mode === 'production' ? false : refusal)
        allowedForMetrics = false
        failOpenForMetrics = false
        if (this._hooks.afterEvaluate || this._hooks.onDeny) {
          await this._safeHookCall(() => this._hooks.afterEvaluate?.(req, refusal), 'afterEvaluate')
          await this._safeHookCall(() => this._hooks.onDeny?.(req, refusal), 'onDeny')
        }
        this._emitMetrics(req, false, t0, false)
        return result
      }

      const signals: { failOpen?: boolean } = {}
      const verdict = await this._evaluateOnce(req, onPolicyError, signals)
      if (verdict.decision !== undefined) {
        decisionForHooks = verdict.decision
        result = this._asResult(verdict.decision)
      } else {
        result = this._asResult(verdict.allowed)
      }
      allowedForMetrics = verdict.allowed
      failOpenForMetrics = signals.failOpen === true
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error))
      // Wrapped, so a throwing `onError` cannot escape the fail-closed deny.
      await this._safeHookCall(() => this._hooks.onError?.(err, req), 'onError')
      this._emitMetrics(req, false, t0, false)
      // NOTE: `afterEvaluate`/`onDeny` do not fire on the error path; `onError` reports it.
      if (this._mode === 'production') return this._asResult(false)
      return this._asResult({
        allowed: false,
        effect: 'deny',
        failure: 'evaluation',
        reason: 'Evaluation error',
        duration: 0,
        timestamp: Date.now(),
      })
    }

    // Outside the evaluation try, each hook wrapped, so a hook throw cannot rewrite the decision or skip the others.
    // Production has no `IDecision`, so one is built from the verdict.
    if (this._hooks.afterEvaluate || this._hooks.onDeny) {
      const d = decisionForHooks ?? this._verdictOnlyDecision(allowedForMetrics, t0)
      await this._safeHookCall(() => this._hooks.afterEvaluate?.(req, d), 'afterEvaluate')
      if (!d.allowed) {
        await this._safeHookCall(() => this._hooks.onDeny?.(req, d), 'onDeny')
      }
    }
    this._emitMetrics(req, allowedForMetrics, t0, failOpenForMetrics)
    return result
  }

  /** The denial for the reserved refusal token, shared by `authorize` and `permissions`; an input failure. */
  private _reservedRefusalDecision(): AccessControl.IDecision {
    return {
      allowed: false,
      effect: 'deny',
      failure: 'input',
      reason: 'Denied: the request names the reserved refusal token, which no policy can grant',
      duration: 0,
      timestamp: Date.now(),
    }
  }

  /**
   * The verdict-only decision production passes to `afterEvaluate`/`onDeny`, built only when one is wired.
   * No `policy` or `rule`: see {@link IamEngineTypes.IHooks.afterEvaluate}.
   */
  private _verdictOnlyDecision(allowed: boolean, t0: number): AccessControl.IDecision {
    return {
      allowed,
      effect: allowed ? 'allow' : 'deny',
      reason: allowed
        ? 'Allowed (production mode; compiled table does not retain policy identity)'
        : 'Denied (production mode; compiled table does not retain policy identity)',
      duration: performance.now() - t0,
      timestamp: Date.now(),
    }
  }

  /** {@link safeHookCall} with this engine's `hookTimeoutMs`. */
  private async _safeHookCall(fn: () => unknown, hookName: string): Promise<void> {
    await safeHookCall(fn, hookName, this._hookTimeoutMs)
  }

  /** Runs `beforeEvaluate` bounded by `hookTimeoutMs`; a timeout rejects into the caller's fail-closed catch. */
  private async _runBeforeEvaluate(
    req: IamRequest.IAccessRequest<TAction, TResource, TScope>,
  ): Promise<IamRequest.IAccessRequest<TAction, TResource, TScope>> {
    const hooks = this._hooks
    if (hooks.beforeEvaluate === undefined) return req
    const next = hooks.beforeEvaluate(req)
    if (this._hookTimeoutMs <= 0 || !isThenable(next)) return next
    const timeoutMs = this._hookTimeoutMs
    let timer: ReturnType<typeof setTimeout> | undefined
    const expired = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        reject(
          new Error(
            `[@gentleduck/iam:engine] beforeEvaluate hook did not settle within ${timeoutMs}ms (hookTimeoutMs)`,
          ),
        )
      }, timeoutMs)
    })
    try {
      return await Promise.race([next, expired])
    } finally {
      clearTimeout(timer)
    }
  }

  /** Fires `onMetrics`, if set, with the caller's `t0` (`0` when no hook needed `performance.now()`). */
  private _emitMetrics(
    req: IamRequest.IAccessRequest<TAction, TResource, TScope>,
    allowed: boolean,
    t0: number,
    failOpen: boolean,
  ): void {
    emitMetrics(this._hooks, req, allowed, t0, failOpen, this._mode)
  }

  /**
   * Whether the subject may perform `action` on `resource`, as a `boolean` in every mode.
   * SECURITY: an invalid `subjectId` or a failed subject load returns `false`, never a rejection.
   */
  async can(
    subjectId: string,
    action: TAction,
    resource: IamRequest.IResource<TResource>,
    environment?: IamRequest.IAccessRequest<TAction, TResource, TScope>['environment'],
    scope?: TScope,
  ): Promise<boolean> {
    if (typeof subjectId !== 'string' || subjectId.length === 0 || subjectId.length > 1024) return false
    try {
      const subject = await this._resolveSubject(subjectId)
      const result = await this.authorize({ subject, action, resource, environment, scope })
      return typeof result === 'boolean' ? result : result.allowed
    } catch (error) {
      // Subject resolution runs outside authorize()'s catch, so deny here too.
      const err = error instanceof Error ? error : new Error(String(error))
      // Wrapped, so a throwing onError cannot bypass `return false`.
      const errReq: IamRequest.IAccessRequest<TAction, TResource, TScope> = {
        subject: { id: subjectId, roles: [], attributes: {} },
        action,
        resource,
        environment,
        scope,
      }
      await this._safeHookCall(() => this._hooks.onError?.(err, errReq), 'onError')
      return false
    }
  }

  /**
   * The subject's roles closed over `inherits`, plus scoped roles matching `scope`, as `can`/`check` see them.
   * Uses the subject cache; returns `[]` for an invalid `subjectId`.
   */
  async getEffectiveRoles(subjectId: string, scope?: TScope): Promise<readonly TRole[]> {
    if (typeof subjectId !== 'string' || subjectId.length === 0 || subjectId.length > 1024) return []
    const subject = await this._resolveSubject(subjectId)
    const enriched = enrichSubjectWithScopedRoles(subject, scope, this._scopeMode, this._scopeCombine)
    return enriched.roles.map((r) => iamAsRoleLiteral<TRole>(r))
  }

  /** {@link IamEngine.can}, returning an {@link AccessControl.IDecision} in development mode and a `boolean` in production. */
  async check(
    subjectId: string,
    action: TAction,
    resource: IamRequest.IResource<TResource>,
    environment?: IamRequest.IAccessRequest<TAction, TResource, TScope>['environment'],
    scope?: TScope,
  ): Promise<AccessControl.ModeResult<TMode>> {
    if (typeof subjectId !== 'string' || subjectId.length === 0 || subjectId.length > 1024) {
      // Fail-closed: in production mode return false; otherwise a synthesized deny.
      if (this._mode === 'production') return this._asResult(false)
      return this._asResult({
        allowed: false,
        effect: 'deny',
        failure: 'input',
        reason: 'invalid subjectId',
        duration: 0,
        timestamp: Date.now(),
      })
    }
    try {
      const subject = await this._resolveSubject(subjectId)
      return await this.authorize({ subject, action, resource, environment, scope })
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error))
      const req: IamRequest.IAccessRequest<TAction, TResource, TScope> = {
        subject: { id: subjectId, roles: [], attributes: {} },
        action,
        resource,
        environment,
        scope,
      }
      // Wrapped, so a throwing onError cannot escape the deny.
      await this._safeHookCall(() => this._hooks.onError?.(err, req), 'onError')
      if (this._mode === 'production') return this._asResult(false)
      return this._asResult({
        allowed: false,
        effect: 'deny',
        failure: 'resolution',
        reason: 'Subject resolution error',
        duration: 0,
        timestamp: Date.now(),
      })
    }
  }

  /**
   * A development-mode trace of why a check was allowed or denied: matched policies, fired rules, condition values.
   * Runs `beforeEvaluate` but no other hook.
   *
   * @throws In production mode, or when `subjectId` is not a non-empty string of at most 1024 chars.
   */
  async explain(
    this: IamEngine<TAction, TResource, TRole, TScope, 'development'>,
    subjectId: string,
    action: TAction,
    resource: IamRequest.IResource<TResource>,
    environment?: IamRequest.IAccessRequest<TAction, TResource, TScope>['environment'],
    scope?: TScope,
  ): Promise<Explain.IResult> {
    if (this._mode === 'production') {
      throw new Error('explain() is not available in production mode')
    }
    if (typeof subjectId !== 'string' || subjectId.length === 0 || subjectId.length > 1024) {
      throw new Error('[@gentleduck/iam:engine] explain(): subjectId must be a non-empty string <=1024 chars')
    }
    const subject = await this._resolveSubject(subjectId)
    const originalRoles = [...subject.roles]

    let enrichedSubject = subject
    if (scope && subject.scopedRoles?.length) {
      enrichedSubject = enrichSubjectWithScopedRoles(subject, scope, this._scopeMode, this._scopeCombine)
    }

    const scopedRolesApplied = enrichedSubject.roles.filter((r) => !originalRoles.includes(r))

    let req: IamRequest.IAccessRequest<TAction, TResource, TScope> = {
      subject: enrichedSubject,
      action,
      resource,
      environment,
      scope,
    }

    if (this._hooks.beforeEvaluate) {
      req = await this._runBeforeEvaluate(req)
    }

    // Default the evaluation clock (after the hook, so a pinned `now` wins).
    req = ensureEnvNow(req)

    const allPolicies = await this._loadAllPolicies()

    // PERF: imported lazily so production bundles can split the explain chunk out.
    const { explainEvaluation } = await import('../explain')

    return explainEvaluation(
      allPolicies,
      req,
      this._defaultEffect,
      { subjectId, originalRoles, scopedRolesApplied },
      this._policyCombine,
    )
  }

  /**
   * Evaluates many checks for one subject, loading its data once; each check gets the same hooks as `authorize()`.
   * Keyed by `[@scope:]action:resource[:resourceId]` (see `iamBuildPermissionKey`); a load failure denies them all.
   *
   * @throws When `subjectId` is invalid or `checks` exceeds 1024: a caller bug, not a deny.
   */
  async permissions(
    subjectId: string,
    checks: readonly IamClient.IPermissionCheck<TAction, TResource, TScope>[],
    environment?: IamRequest.IAccessRequest<TAction, TResource, TScope>['environment'],
    opts: { telemetry?: boolean } = {},
  ): Promise<AccessControl.ModePermissionMap<TMode, TAction, TResource, TScope>> {
    if (typeof subjectId !== 'string' || subjectId.length === 0 || subjectId.length > 1024) {
      throw new Error('[@gentleduck/iam:engine] permissions(): subjectId must be a non-empty string <=1024 chars')
    }
    // SECURITY: capped so an attacker-driven batch cannot force thousands of evaluations.
    if (checks.length > 1024) {
      throw new Error('[@gentleduck/iam:engine] permissions() refuses batches >1024 checks')
    }
    // PERF: `telemetry: false` skips per-check `onMetrics`, only ~3% on a batch of 20 (ARCHITECTURE-PERF.md).
    // Use it to keep a hot UI gate out of telemetry, not for speed.
    const telemetry = opts.telemetry !== false
    // Outer try synthesises all-deny on subject/policy load failure.
    let subject: IamRequest.ISubject
    try {
      // Load policies up front so a failure denies the whole batch; `_evaluateOnce` reads the warmed cache.
      ;[subject] = await Promise.all([this._resolveSubject(subjectId), this._loadAllPolicies()])
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error))
      const failClosed: Record<string, boolean> = {}
      for (const c of checks) {
        failClosed[iamBuildPermissionKey(c.action, c.resource, c.resourceId, c.scope)] = false
      }
      const errReq: IamRequest.IAccessRequest<TAction, TResource, TScope> = {
        subject: { id: subjectId, roles: [], attributes: {} },
        action: checks[0]?.action ?? ('' as TAction),
        resource: { type: checks[0]?.resource ?? ('' as TResource), attributes: {} },
        environment,
      }
      await this._safeHookCall(() => this._hooks.onError?.(err, errReq), 'onError')
      return failClosed as AccessControl.ModePermissionMap<TMode, TAction, TResource, TScope>
    }

    const map: Record<string, boolean> = {}
    // Memo per scope: N checks sharing a scope must not rebuild the merged role list N times.
    const enrichedByScope = new Map<TScope, IamRequest.ISubject>()

    // Forward onPolicyError so batch checks report per-policy throws too.
    const onPolicyErrorHook = this._hooks.onPolicyError
    const onPolicyError = onPolicyErrorHook
      ? (err: Error, policy: AccessControl.IPolicy) => onPolicyErrorHook(err, policy.id)
      : undefined

    for (const c of checks) {
      const key = iamBuildPermissionKey(c.action, c.resource, c.resourceId, c.scope)
      const t0 =
        (telemetry && this._hooks.onMetrics) || this._hooks.afterEvaluate || this._hooks.onDeny ? performance.now() : 0

      let decisionForHooks: AccessControl.IDecision | null = null
      let allowedForCheck = false
      let failOpenForCheck = false
      let evalReq: IamRequest.IAccessRequest<TAction, TResource, TScope> | null = null

      try {
        let enrichedSubject = subject
        if (c.scope && subject.scopedRoles?.length) {
          const cached = enrichedByScope.get(c.scope)
          if (cached) {
            enrichedSubject = cached
          } else {
            enrichedSubject = enrichSubjectWithScopedRoles(subject, c.scope, this._scopeMode, this._scopeCombine)
            enrichedByScope.set(c.scope, enrichedSubject)
          }
        }

        let req: IamRequest.IAccessRequest<TAction, TResource, TScope> = {
          subject: enrichedSubject,
          action: c.action,
          resource: { type: c.resource, id: c.resourceId, attributes: c.attributes ?? {} },
          environment,
          scope: c.scope,
        }

        if (this._hooks.beforeEvaluate) {
          req = await this._runBeforeEvaluate(req)
        }

        // Default the evaluation clock per check (after the hook).
        req = ensureEnvNow(req)

        const signals: { failOpen?: boolean } = {}

        // SECURITY: same path as `authorize()`, including the reserved-refusal check, repeated since this skips it.
        const verdict =
          iamIsReservedRefusal(req.action) || iamIsReservedRefusal(req.resource?.type)
            ? { allowed: false, decision: this._reservedRefusalDecision() }
            : await this._evaluateOnce(req, onPolicyError, signals)
        map[key] = verdict.allowed
        if (verdict.decision !== undefined) decisionForHooks = verdict.decision
        allowedForCheck = verdict.allowed
        failOpenForCheck = signals.failOpen === true
        evalReq = req
      } catch (error) {
        const err = error instanceof Error ? error : new Error(String(error))
        const errReq: IamRequest.IAccessRequest<TAction, TResource, TScope> = {
          subject,
          action: c.action,
          resource: { type: c.resource, id: c.resourceId, attributes: c.attributes ?? {} },
          environment,
          scope: c.scope,
        }
        await this._safeHookCall(() => this._hooks.onError?.(err, errReq), 'onError')
        if (telemetry) this._emitMetrics(errReq, false, t0, false)
        map[key] = false
        continue
      }

      // Outside the try, as in authorize(), so a hook throw cannot rewrite the verdict.
      if (evalReq !== null && (this._hooks.afterEvaluate || this._hooks.onDeny)) {
        const d = decisionForHooks ?? this._verdictOnlyDecision(allowedForCheck, t0)
        const r = evalReq
        await this._safeHookCall(() => this._hooks.afterEvaluate?.(r, d), 'afterEvaluate')
        if (!d.allowed) {
          await this._safeHookCall(() => this._hooks.onDeny?.(r, d), 'onDeny')
        }
      }
      if (telemetry && evalReq !== null) this._emitMetrics(evalReq, allowedForCheck, t0, failOpenForCheck)
    }

    return map as AccessControl.ModePermissionMap<TMode, TAction, TResource, TScope>
  }

  private _admin?: IamEngineTypes.IAdmin<TAction, TResource, TRole, TScope>

  /** Lazily-built admin interface for CRUD operations on policies, roles, subjects. */
  get admin(): IamEngineTypes.IAdmin<TAction, TResource, TRole, TScope> {
    this._admin ??= createAdmin<TAction, TResource, TRole, TScope>(this._adapter, {
      cache: this.cache,
      withTimeout: (fn, label) => this._withTimeout(fn, label),
      // PERF: omitted without `onMutation`, so no events are built.
      ...(this._hooks.onMutation !== undefined && {
        mutations: {
          emit: (event: IamEngineTypes.IMutationEvent<TRole, TScope>) =>
            this._safeHookCall(() => this._hooks.onMutation?.(event), 'onMutation'),
        },
      }),
    })
    return this._admin
  }

  /**
   * A view whose adapter runs on the transaction handle `client` and whose invalidations buffer into `pending`.
   * Reads use empty caches, so they see the transaction's own writes.
   *
   * ```ts
   * let pending
   * await db.transaction(async (tx) => {
   *   const perms = iam.withTransaction(tx)
   *   await perms.admin.assignRole(userId, 'admin', orgId)
   *   await tx.insert(members).values({ userId, orgId })
   *   pending = perms.pending
   * })
   * await pending.flush() // invalidate and broadcast only after the commit
   * ```
   *
   * A rollback needs no cleanup; `pending.discard()` says so explicitly.
   *
   * @param client - Opaque driver handle, passed straight to the adapter.
   * @throws When the adapter has no `withClient`, rather than writing outside the transaction.
   */
  withTransaction(client: unknown): Bound.IamEngine<TAction, TResource, TRole, TScope, TMode> {
    const bind = this._adapter.withClient
    if (!bind) {
      throw new Error(
        '[@gentleduck/iam:engine] withTransaction: the configured adapter cannot join a transaction ' +
          '(no withClient). Use the drizzle or prisma adapter, or perform this write outside the transaction.',
      )
    }
    return buildBoundEngine(this, bind.call(this._adapter, client), this._config, (cfg) => new IamEngine(cfg))
  }

  /** @internal Cache references for the stats helper. */
  private _cachesForStats() {
    return {
      policyCache: this._policyCache,
      roleCache: this._roleCache,
      rbacPolicyCache: this._rbacPolicyCache,
      mergedPolicyCache: this._mergedPolicyCache,
      subjectCache: this._subjectCache,
    }
  }

  /** @internal Snapshot per-cache counters. Reached via `stats.get`. */
  private _statsSnapshot(): {
    policies: { hits: number; misses: number; size: number }
    roles: { hits: number; misses: number; size: number }
    rbacPolicy: { hits: number; misses: number; size: number }
    mergedPolicies: { hits: number; misses: number; size: number }
    subjects: { hits: number; misses: number; size: number }
  } {
    return statsSnapshotHelper(this._cachesForStats())
  }

  /** @internal Zero per-cache counters. Reached via `stats.reset`. */
  private _resetStats(): void {
    resetStatsHelper(this._cachesForStats())
  }

  /** @internal Clear all caches + in-flight resolvers. Reached via `cache.invalidate`. */
  private _invalidateAll(opts: { broadcast?: boolean } = {}): void {
    invalidateAll(this._cacheBag(), opts)
    this._compiledTable = null
    this._compiledTableGen++
    this._clearRoleLimitLatch()
  }

  /** @internal Clear one subject's cached data. Reached via `cache.invalidateSubject`. */
  private _invalidateSubject(subjectId: string, opts: { broadcast?: boolean } = {}): void {
    invalidateSubject(this._cacheBag(), subjectId, opts)
  }

  /** @internal Clear cached policies. Reached via `cache.invalidatePolicies`. */
  private _invalidatePolicies(opts: { broadcast?: boolean } = {}): void {
    invalidatePolicies(this._cacheBag(), opts)
    this._compiledTable = null
    this._compiledTableGen++
  }

  /**
   * Lets the compiled table be retried, and a new excursion warned about, once the role set may have changed.
   * NOTE: only role invalidations call this; otherwise the fallback outlives the role count that caused it.
   */
  private _clearRoleLimitLatch(): void {
    this._roleLimitExceeded = false
    this._roleLimitReported = false
    this._roleLimitDetail = null
  }

  /** @internal Clear cached roles + selectively drop affected subjects. Reached via `cache.invalidateRoles`. */
  private _invalidateRoles(roleId?: TRole, opts: { broadcast?: boolean } = {}): void {
    invalidateRoles(this._cacheBag(), roleId, opts)
    this._compiledTable = null
    this._compiledTableGen++
    this._clearRoleLimitLatch()
  }

  /**
   * Warms policies and the compiled permission table (read in both modes) at startup; call once.
   * A malformed policy throws here, at boot; over 32 roles warns and falls back. `validator: true` loads validators.
   */
  async preload(opts: { validator?: boolean } = {}): Promise<void> {
    await preloadEngine({
      buildCompiledTable: () => this._getCompiledTable(),
      loadAllPolicies: () => this._loadAllPolicies(),
      loadValidator: opts.validator === true,
    })
  }

  /**
   * Health probe for `/healthz`: one timed `listPolicies` plus a table build; `ok: false` when either fails.
   * `compiledTable` and `invalidator` report degradations without failing it, and are absent when healthy.
   */
  async healthCheck(): Promise<IamEngineTypes.IHealth> {
    const health = await runHealthCheck(this._cachesForStats(), async () => {
      await this._withTimeout((opts) => this._adapter.listPolicies(opts), 'healthCheck.listPolicies')
      // A table that cannot build denies every check, so it fails the probe. The role-limit fallback returns null.
      await this._getCompiledTable()
    })
    const detail = this._roleLimitDetail
    // Annotated, so `available: false` is not widened to `boolean` in the ternary.
    const withTable: IamEngineTypes.IHealth =
      detail === null
        ? health
        : {
            ...health,
            compiledTable: {
              available: false,
              limit: detail.limit,
              reason: 'role-limit-exceeded',
              roleCount: detail.roleCount,
            },
          }
    // The adapter probe cannot see a failed subscription; `ok` is left alone, see `IHealth.invalidator`.
    const status = readInvalidatorSubscribed(this._invalidator)
    if (!status.ok) {
      if (status.broken && !this._invalidatorStatusWarned) {
        this._invalidatorStatusWarned = true
        console.warn(
          '[@gentleduck/iam:engine] healthCheck: the attached invalidator has a `status` that is not a function returning `{ subscribed: boolean }`. Its subscription state is omitted from the health report, so a node that stops receiving invalidations will look healthy.',
        )
      }
      return withTable
    }
    if (status.subscribed) return withTable
    return { ...withTable, invalidator: { subscribed: false } }
  }
}

/**
 * Factory for {@link IamEngine} that keeps every type parameter, so `mode: 'production'` makes `explain` a type error.
 */
export function iamEngine<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
  TMode extends AccessControl.Mode = 'production',
>(
  config: IamEngineTypes.IConfig<TAction, TResource, TRole, TScope, TMode>,
): IamEngine<TAction, TResource, TRole, TScope, TMode> {
  return new IamEngine<TAction, TResource, TRole, TScope, TMode>(config)
}
