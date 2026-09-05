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
import { emitMetrics, safeHookCall } from './engine.hooks'
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
 * Default ceiling on concurrent distinct-subject adapter loads.
 *
 * The cap used to default to `0` (unbounded), which made it a safety limit that
 * protected nobody: the cold-cache thundering herd its own documentation
 * describes was permitted by default, and only an operator who had already read
 * that paragraph was protected from it.
 *
 * `512` is chosen to sit far above legitimate steady-state concurrency and well
 * below runaway growth. Only a *distinct, never-before-cached* subject counts:
 * a cache hit does not, and a request joining an already-in-flight load for the
 * same subject does not. A node with 512 different cold subjects resolving
 * simultaneously is in a herd, not serving traffic normally.
 *
 * Shedding is a denial of legitimate traffic, so the number is deliberately
 * generous. Set `maxConcurrentSubjectLoads: 0` to restore the old unbounded
 * behaviour explicitly.
 */
const DEFAULT_MAX_CONCURRENT_SUBJECT_LOADS = 512

/**
 * Clears the process-global regex and dot-path caches - the fallbacks used by
 * direct `evaluate()` / operator calls and by `explain()`. Every `can()` path
 * uses the engine's own per-instance caches, which this does not touch, so it
 * is not a multi-tenancy mitigation and needs no periodic schedule.
 */
export function iamFlushSharedCaches(): void {
  clearRegexCache()
  clearPathCache()
}

/**
 * Runtime shape check for {@link IamEngine.setInvalidator}. An invalidator
 * arriving after construction comes from wherever the caller's Redis client was
 * built, so it is checked rather than trusted: a missing `subscribe` would
 * otherwise surface much later as invalidations that silently never arrive.
 */
function isInvalidatorLike<TRole extends string>(value: unknown): value is IamEngineTypes.IInvalidator<TRole> {
  if (value === null || typeof value !== 'object') return false
  if (!('publish' in value) || !('subscribe' in value)) return false
  return typeof value.publish === 'function' && typeof value.subscribe === 'function'
}

/** Bit per directly-held role name; `compileTable`'s inheritance closure already bakes inherited grants into `table.allow`, so no re-expansion is needed here. */
function maskFromRoles(table: CompiledTable, roles: readonly string[]): number {
  let mask = 0
  for (const roleName of roles) {
    const idx = table.roleId.get(roleName)
    if (idx !== undefined) mask |= 1 << idx
  }
  return mask
}

/**
 * One single-flight slot: the in-progress promise for a cache key, or `null`
 * when nothing is in flight. Declared rather than inferred so the initialiser
 * can write a bare `null` — inferring from `{ value: null }` would fix the
 * slot type at `null` and force a widening cast at every assignment.
 */
/**
 * Central runtime that evaluates access requests against RBAC roles and ABAC
 * policies.
 *
 * Loads roles + policies from its adapter, caches them with configurable TTL,
 * converts RBAC roles into ABAC rules via {@link rolesToPolicy}, and merges
 * decisions across all policies according to its `policyCombine` setting
 * (default `'and'`; see {@link AccessControl.PolicyCombine}).
 *
 * @template TAction   - Union of valid action strings.
 * @template TResource - Union of valid resource strings.
 * @template TRole     - Union of valid role IDs.
 * @template TScope    - Union of valid scope strings.
 * @template TMode     - Engine mode (`'development'` or `'production'`) that
 *   determines whether return types are `IDecision` or plain `boolean`.
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
  /** Production mode's evaluator. Lazily built on first `authorize()`/`permissions()` call, rebuilt after any policy/role invalidation or once `cacheTTL` has elapsed. */
  private _compiledTable: CompiledTable | null = null
  /** `Date.now()` when `_compiledTable` was committed - the TTL clock, mirroring the LRU caches'. */
  private _compiledTableBuiltAt = 0
  private _hooks: IamEngineTypes.IHooks<TAction, TResource, TScope>
  private _maxPolicies: number
  private _maxRoles: number
  private _adapterTimeoutMs: number
  private _maxConcurrentSubjectLoads: number
  private _invalidator?: IamEngineTypes.IInvalidator<TRole>
  /** Retained whole so {@link withTransaction} can re-make this engine with only the adapter swapped. */
  private readonly _config: IamEngineTypes.IConfig<TAction, TResource, TRole, TScope, TMode>
  private _invalidatorUnsub: (() => void) | null = null
  private _policyCache: IamLRUCache<AccessControl.IPolicy[]>
  private _roleCache: IamLRUCache<AccessControl.IRole[]>
  private _rbacPolicyCache: IamLRUCache<AccessControl.IPolicy>
  private _mergedPolicyCache: IamLRUCache<AccessControl.IPolicy[]>
  private _subjectCache: IamLRUCache<IamRequest.ISubject>
  // Single-flight: coalesce concurrent cache-misses so a cold start under load
  // doesn't fan out N identical adapter calls. Cleared once the promise settles.
  private _inFlight: IEngineInFlightBag = {
    policies: { value: null },
    roles: { value: null },
    rbac: { value: null },
    merged: { value: null },
    subjects: new Map(),
  }
  /**
   * Per-instance evaluation caches. Multi-tenant deployments instantiate
   * one Engine per tenant; each owns its own regex + path caches and
   * cannot be evicted by hostile-tenant pattern flooding.
   */
  private _caches: { regex: Map<string, RegExp>; path: Map<string, string[] | null> } = {
    regex: new Map(),
    path: new Map(),
  }

  /**
   * Cache invalidation facet. Groups the five cache-management calls so the
   * Engine API surface stays focused on evaluation. Use after policy/role/
   * subject mutations to drop stale entries; pass `{ broadcast: false }`
   * when applying an event received from another instance.
   *
   * @since 3.0.0 - replaces the flat `engine.invalidate*` methods.
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
   * Observability facet. Cache hit/miss/size counters plus a zero op.
   *
   * @since 3.0.0 - replaces the flat `engine.stats()` / `engine.resetStats()`.
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
    /** Zero the counters returned by {@link stats.get}. */
    reset: (): void => this._resetStats(),
  }

  /**
   * Constructs a new engine wired to the given adapter and configuration.
   *
   * @param config - Engine configuration (adapter, mode, caches, hooks).
   */
  constructor(config: IamEngineTypes.IConfig<TAction, TResource, TRole, TScope, TMode>) {
    this._config = config
    this._adapter = config.adapter
    this._defaultEffect = config.defaultEffect ?? 'deny'
    this._mode = config.mode ?? 'production'
    this._policyCombine = config.policyCombine ?? 'and'
    this._scopeMode = config.scopeMode ?? 'flat'
    this._scopeCombine = config.scopeCombine ?? 'union'
    this._hooks = config.hooks ?? {}

    // Both engines branch on 'and' and 'allow-overrides' and fall through to
    // `first-applicable` for anything else - the most permissive of the three.
    // A typo, or a value read from a config file rather than written in TS,
    // therefore lost deny-overrides semantics with no signal at all.
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
    // Even with the opt-in, emit a loud startup warning so an operator
    // grep'ing logs for fail-open configurations always finds it.
    if (this._defaultEffect === 'allow') {
      console.warn(
        "[@gentleduck/iam:engine] engine configured with defaultEffect: 'allow' (fail-open). Every request with no applicable policy will be allowed.",
      )
    }

    this._maxPolicies = config.maxPolicies ?? 10_000
    this._maxRoles = config.maxRoles ?? 10_000
    this._adapterTimeoutMs = config.adapterTimeoutMs ?? 5_000
    this._maxConcurrentSubjectLoads = config.maxConcurrentSubjectLoads ?? DEFAULT_MAX_CONCURRENT_SUBJECT_LOADS

    // Reject non-finite caps; `NaN > x` is always false so a NaN limit
    // silently disables the bound.
    if (!Number.isFinite(this._maxPolicies) || this._maxPolicies < 1) {
      throw new RangeError('[@gentleduck/iam:engine] maxPolicies must be a finite number >= 1')
    }
    if (!Number.isFinite(this._maxRoles) || this._maxRoles < 1) {
      throw new RangeError('[@gentleduck/iam:engine] maxRoles must be a finite number >= 1')
    }
    if (!Number.isFinite(this._adapterTimeoutMs) || this._adapterTimeoutMs < 0) {
      throw new RangeError('[@gentleduck/iam:engine] adapterTimeoutMs must be a finite number >= 0')
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

    // Through the setter, so the constructor path and the late-attach path
    // validate and subscribe identically.
    if (config.invalidator) this.setInvalidator(config.invalidator)
  }

  /**
   * Wrap an adapter read with the engine's configured timeout. Creates a
   * fresh `AbortController` per call so a slow upstream gets hard-cancelled
   * once `adapterTimeoutMs` elapses; the timeout error routes through
   * `authorize`'s catch and produces a fail-closed deny.
   *
   * Returns the adapter call result. Throws on timeout. Adapters that don't
   * honor `signal` still get their result discarded - the engine just
   * doesn't wait for them.
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
  }

  /**
   * Attach, replace, or detach the cross-instance invalidator after
   * construction.
   *
   * `IConfig.invalidator` is constructor-only, but engines are commonly built
   * at module import time - before any request-scoped or replica-specific
   * Redis client exists. Without this, the only way to wire invalidation late
   * was to hand-roll the pub/sub that `createIamRedisInvalidator` already
   * implements, and hand-rolled copies drift from the event union they have to
   * match.
   *
   * Replacing unsubscribes the previous invalidator first, so an engine holds
   * at most one subscription however many times this is called. Pass `null` to
   * detach and go back to local-only invalidation.
   *
   * A transaction-bound view built by {@link withTransaction} deliberately has
   * no invalidator of its own and is unaffected; its buffered invalidations
   * broadcast through this engine on `pending.flush()`, so they pick up
   * whatever is attached here at flush time.
   *
   * @param invalidator - The broadcaster to attach, or `null` to detach.
   * @throws When `invalidator` is neither `null` nor an object with `publish`
   *   and `subscribe` methods - a malformed one would otherwise fail later, at
   *   the first mutation, as a lost broadcast rather than a bad argument.
   */
  setInvalidator(invalidator: IamEngineTypes.IInvalidator<TRole> | null): void {
    if (invalidator !== null && !isInvalidatorLike(invalidator)) {
      throw new TypeError(
        '[@gentleduck/iam:engine] setInvalidator: expected null or an object with `publish` and `subscribe` methods',
      )
    }
    // Unsubscribe first and unconditionally: an exception from the new
    // `subscribe` must not leave the old subscription attached to an
    // invalidator this engine no longer considers current.
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

  /** In-flight rebuild, so concurrent cold callers await the same compile instead of racing/duplicating it. */
  private _compiledTableBuild: Promise<CompiledTable> | null = null
  /** The generation `_compiledTableBuild` was started under - see `_rebuildCompiledTable`. */
  private _compiledTableBuildGen = -1
  /** Bumped by every invalidation; a build that started under an older generation must not overwrite a newer invalidation's null with stale data. */
  private _compiledTableGen = 0

  /**
   * Cached table, or a build if none is current. The single read path for every caller.
   *
   * The table expires on `cacheTTL` like every other cache. Without that it was cleared
   * only by an explicit invalidation, so a production engine with no `invalidator` wired -
   * the default - served a grant revoked by another process forever, while the same
   * adapter in development converged within `cacheTTL`. The two modes are meant to differ
   * in speed, not in consistency.
   */
  /**
   * The compiled table, or `null` when this config cannot have one.
   *
   * `null` means exactly one thing: the role count exceeds what the 32-bit
   * grant mask can address, so the caller must use the interpreter. Every other
   * compile failure still throws and still denies - a malformed policy is a bug,
   * and answering it with a slower correct path would hide it.
   */
  private async _getCompiledTable(): Promise<CompiledTable | null> {
    if (this._roleLimitExceeded) return null
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
        // Loud once, not per request. A silent fall to a slower path is a
        // performance cliff with no diagnostic - the same shape of defect as
        // the dev/prod divergence this fallback exists to remove.
        console.warn(err.message)
      }
      return null
    }
  }

  /**
   * One evaluation, through the same verdict path in every mode.
   *
   * This is the fix for the largest recurring defect family in the round-3
   * audit. Production evaluated through the compiled table and development
   * through the interpreter, so any disagreement between the two was invisible
   * until it reached production - and it reached production as an *allow*
   * against a dev run that denied (A/W-1, B/S-1, B/S-2, B/S-3, B/W-1 were all
   * this shape). Patching each instance never addressed why they kept arriving.
   *
   * Now the compiled table produces the verdict in both modes. Development
   * additionally runs the interpreter, because the table cannot explain itself:
   * `CONST_ALLOW`/`CONST_DENY` cells are a single `kind` byte and `allow` is a
   * raw bitmask, so policy identity is erased at compile time - that erasure is
   * the optimisation. The interpreter supplies `reason`/`policy`/`rule`, the
   * table supplies the verdict, and the two are checked against each other.
   *
   * A disagreement throws. It means the table and the interpreter answer the
   * same question differently, which is a duck-iam bug, and the whole point is
   * that it now surfaces on the developer's machine instead of in production.
   *
   * `table === null` (more roles than the 32-bit mask can address) drops both
   * modes to the interpreter alone. Correct, just slower, and reported once.
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

    // Development: same verdict path as production, plus the explanation the
    // table cannot produce.
    //
    // The explanatory run must be observationally silent, or running two
    // evaluators doubles every operator-visible side effect: `onPolicyError`
    // fired twice per rotten policy, so a handler wired to an alerting pipeline
    // would page twice for one bad policy, in development only. It is passed
    // `undefined` here because the authoritative run above already reported.
    // Safe precisely because the handler is notification-only - `safeEval`'s
    // control flow (deny-rule present -> Indeterminate deny, else the
    // `defaultEffect` vote) is identical whether or not one is attached, so the
    // decision this returns is unchanged.
    //
    // It also gets its own `signals`, so a `failOpen` seen only by the
    // explanatory run cannot rewrite what the authoritative path reported.
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
      // Printed as well as thrown. `authorize()` catches everything and returns
      // a fail-closed deny with `reason: 'Evaluation error'`, which is right for
      // the verdict and useless as a diagnostic - a developer with no `onError`
      // wired would see a generic deny and never learn that production would
      // have answered the other way. That is the same invisibility this whole
      // path exists to remove, so the message goes to the console too.
      //
      // Unbounded on purpose: this cannot fire unless duck-iam has a bug, and
      // when it does the developer needs to stop, not to have it rate-limited
      // into the background.
      console.error(message)
      throw new Error(message)
    }

    // Verdicts agree, so the reported decision is the interpreter's - it is the
    // one carrying provenance - and `signals` takes the union: a fail-open seen
    // by either path is a fail-open.
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

  /** Set once the role count has outrun the compiled table; see {@link _getCompiledTable}. */
  private _roleLimitExceeded = false
  private _roleLimitReported = false
  private _roleLimitDetail: { roleCount: number; limit: number } | null = null

  /** `cacheTTL: 0` means "do not cache", the same reading `IamLRUCache` gives it. */
  private _compiledTableExpired(): boolean {
    return Date.now() - this._compiledTableBuiltAt >= this._cacheTTL
  }

  /**
   * Rebuilds production mode's compiled table from the current roles + raw adapter
   * policies (NOT `_loadAllPolicies()`'s RBAC-merged view - `compileTable` derives its
   * own RBAC representation from `roles` and would double-count a pre-merged `__rbac__`
   * policy). Returns the table directly so a caller never has to re-read `_compiledTable`
   * after an `await` a concurrent invalidation could have raced.
   *
   * Single-flighting is scoped to one generation: an in-flight build is only reused while
   * `_compiledTableGen` hasn't moved since it started. A caller arriving after an
   * invalidation bumps the generation must never be handed a promise that resolves to
   * pre-invalidation data - it starts (or joins) a fresh build against the post-invalidation
   * generation instead, matching what a caller would get with no single-flighting at all.
   */
  /** Set once a compile failure has been reported, so the log carries one line, not one per request. */
  private _compileFailureReported = false

  /**
   * Compile, and report a failure the first time it happens.
   *
   * A throw here reaches `authorize()`'s catch and denies, so without this the
   * whole deployment goes to total-deny silently - the operator sees an
   * authorization outage and no message. The error is still rethrown: the deny
   * is the correct behaviour, the silence was not.
   *
   * Two failures are not that, and are excluded:
   *
   * - {@link IamRoleLimitExceededError} denies nothing. `_getCompiledTable`
   *   catches it and falls back to the interpreter, so the total-deny wording
   *   here would be a lie, and it carries its own one-time warning.
   * - {@link IamPolicyCompileError} names the policy at fault, which is what
   *   `onPolicyError` exists to deliver. Forwarding it there keeps the
   *   diagnostic the interpreter used to give before both modes moved onto the
   *   table.
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
        // Sync, so `_safeHookCall` (async) is not usable here; the try/catch
        // does the same job - a buggy operator hook must not replace the
        // compile error with its own.
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
   * The instant this table should be treated as having been built at: now, or
   * the moment its oldest input was read, whichever is earlier.
   *
   * `cacheTTL` is documented as the convergence window for a write made
   * outside this engine, and with no invalidator wired - the default - it is
   * the only one. The table is not compiled from the adapter, though; it is
   * compiled from `roleCache` and `policyCache`. Stamping it `Date.now()`
   * therefore gave a table built from nearly-expired roles a second, complete
   * TTL, and the two clocks only separate when something nulls the table
   * *without* clearing `roleCache` - which is exactly what `savePolicy`,
   * `deletePolicy` and an inbound `{kind: 'policies'}` event all do. Measured
   * at `cacheTTL: 60`: a revoke written at t=1s still answered allow at
   * t=111s, converging at t=119s.
   *
   * An input with no cache entry imposes no cap: it was read live, so it is as
   * fresh as now.
   *
   * @param deps - The loader bag whose caches fed this build.
   * @returns Epoch ms to record as the build time.
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
    // An entry expiring at E was read at E - cacheTTL, unless a `notAfter` cap
    // shortened it - in which case this reads older still, which is the safe
    // direction. Never later than now.
    return Math.min(now, oldestExpiry - this._cacheTTL)
  }

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
      // An invalidation that landed mid-build must win: don't resurrect a table
      // built from data that invalidation has already superseded.
      if (this._compiledTableGen === gen) {
        this._compiledTable = table
        this._compiledTableBuiltAt = this._derivedBuiltAt(deps)
      }
      return table
    })()
    this._compiledTableBuild = build
    this._compiledTableBuildGen = gen
    // A separate .finally() chain that nobody awaits still reports the original
    // rejection as "unhandled" to Node/V8 even though the real caller below
    // properly awaits `build` itself - swallow that side-chain explicitly.
    build
      .finally(() => {
        if (this._compiledTableBuild === build) this._compiledTableBuild = null
      })
      .catch(() => {})
    return build
  }

  /**
   * Bridges the runtime `this._mode` branch to the static `AccessControl.ModeResult<TMode>`
   * conditional type. Centralized so the assertion is named and grep-able
   * instead of scattered across each return statement.
   */
  private _asResult(value: boolean | AccessControl.IDecision): AccessControl.ModeResult<TMode> {
    return value as AccessControl.ModeResult<TMode>
  }

  /**
   * Full authorization check with a complete {@link IamRequest.IAccessRequest}.
   *
   * In `'production'` mode, returns a plain `boolean`.
   * In `'development'` mode, returns a full {@link AccessControl.IDecision}.
   *
   * @param request - The access request to evaluate.
   * @returns The decision shape determined by the engine's mode.
   */
  async authorize(
    request: IamRequest.IAccessRequest<TAction, TResource, TScope>,
  ): Promise<AccessControl.ModeResult<TMode>> {
    let req = request
    // Also captured for `afterEvaluate` / `onDeny`, which now fire in production
    // and need a real `duration` on the decision synthesised for them.
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
        req = await this._hooks.beforeEvaluate(req)
      }

      // Default the evaluation clock after the hook so a hook-pinned `now`
      // (tests, replay) is preserved and a normal request still gets one.
      req = ensureEnvNow(req)

      const onPolicyErrorHook = this._hooks.onPolicyError
      const onPolicyError = onPolicyErrorHook
        ? (err: Error, policy: AccessControl.IPolicy) => onPolicyErrorHook(err, policy.id)
        : undefined

      // A request naming the reserved refusal token is refused before any
      // policy is consulted. The framework adapters produce it for a method
      // they cannot map and a path they cannot safely resolve, and it used to
      // travel as an ordinary string - which a `'*'` rule matches, so the
      // refusal became an allow on exactly the requests built to be denied.
      // Placed inside the try so `onDeny` / `afterEvaluate` / `onMetrics` see
      // this denial like any other.
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
      // onError can itself throw. Don't let an operator's onError bug
      // propagate over the engine's fail-closed behaviour.
      await this._safeHookCall(() => this._hooks.onError?.(err, req), 'onError')
      this._emitMetrics(req, false, t0, false)
      // NOTE: `afterEvaluate` / `onDeny` deliberately do NOT fire here. They did
      // not fire on this path in development either, so routing them through it
      // now would be a second behaviour change wearing the first one's clothes.
      // The error-path denial is reported by `onError`, as it always was.
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

    // Trailing hook block - runs OUTSIDE the evaluation try so a hook throw
    // cannot rewrite the decision. Each hook is individually wrapped so a
    // bug in one doesn't suppress the others.
    //
    // Both hooks fire in production too. They used to be development-only,
    // which put a denial log - a production concern if there is one - out of
    // reach exactly where operators need it. Production has no `IDecision` to
    // hand over, because the compiled table erases policy identity by design,
    // so one is synthesised from the verdict: right `allowed`/`effect`, honest
    // generic `reason`, no `policy`/`rule` provenance. Development still passes
    // the interpreter's decision, which carries all three.
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

  /**
   * Build the {@link AccessControl.IDecision} production hands to
   * `afterEvaluate` / `onDeny`.
   *
   * Production evaluates through the compiled table, whose `CONST_ALLOW` /
   * `CONST_DENY` cells are a single `kind` byte and whose `allow` is a raw
   * bitmask - policy identity is erased at compile time, and that erasure is
   * the optimisation. So there is no `policy` or `rule` to report and the
   * `reason` is generic. Reconstructing them would mean running the interpreter
   * alongside the table on every production request, which is what development
   * mode already does and what production exists not to do.
   *
   * Called only when one of the two hooks is wired, so the allocation lands on
   * installs that asked for it and nobody else.
   */
  /**
   * The denial for a request naming the reserved refusal token.
   *
   * Shared by `authorize` and `permissions` so the two entry points cannot
   * report the same refusal differently - `failure: 'input'` because the
   * request named something that is not an action or a resource, not because
   * evaluating it went wrong.
   */
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

  /**
   * Invoke a hook safely. Sync or async throws are caught and routed to
   * console.error so a buggy operator hook cannot escape into the caller's
   * path or rewrite a finalised decision. Returning void is intentional -
   * the engine never surfaces hook bugs as authz failures.
   */
  private async _safeHookCall(fn: () => unknown, hookName: string): Promise<void> {
    await safeHookCall(fn, hookName)
  }

  /**
   * Fires the `onMetrics` hook if configured. Synchronous; takes the start
   * timestamp captured at the top of `authorize` so the caller doesn't pay
   * `performance.now()` cost when no hook is wired.
   */
  private _emitMetrics(
    req: IamRequest.IAccessRequest<TAction, TResource, TScope>,
    allowed: boolean,
    t0: number,
    failOpen: boolean,
  ): void {
    emitMetrics(this._hooks, req, allowed, t0, failOpen, this._mode)
  }

  /**
   * Simple boolean check: can this user do this action on this resource?
   * Always returns a plain `boolean` regardless of engine mode.
   *
   * @param subjectId   - Subject ID to resolve via the adapter.
   * @param action      - Action the subject wants to perform.
   * @param resource    - Target resource.
   * @param environment - Optional request-time environment.
   * @param scope       - Optional scope for multi-tenant checks.
   * @returns `true` when the subject is authorized to perform the action.
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
      // Subject-resolution errors (adapter down, listRoles limit hit) escape
      // authorize()'s try/catch. Translate to a fail-closed deny so callers
      // never see an unhandled rejection from the entry-point methods.
      const err = error instanceof Error ? error : new Error(String(error))
      // _safeHookCall so a throwing onError cannot bypass fail-closed `return false`.
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
   * Resolve the roles a subject effectively holds: assigned roles closed over
   * `inherits`, plus scoped role assignments matching `scope` when given —
   * same merge `can`/`check` do internally. Uses the same subject cache, so
   * repeated calls pay the cache TTL instead of a bare adapter round trip.
   *
   * @param subjectId - Subject ID to resolve via the adapter.
   * @param scope     - Optional scope to merge matching scoped roles in.
   * @returns The subject's effective roles. Empty array for an invalid `subjectId`.
   */
  async getEffectiveRoles(subjectId: string, scope?: TScope): Promise<readonly TRole[]> {
    if (typeof subjectId !== 'string' || subjectId.length === 0 || subjectId.length > 1024) return []
    const subject = await this._resolveSubject(subjectId)
    const enriched = enrichSubjectWithScopedRoles(subject, scope, this._scopeMode, this._scopeCombine)
    return enriched.roles.map((r) => iamAsRoleLiteral<TRole>(r))
  }

  /**
   * Same as `can` but returns the full {@link AccessControl.IDecision} in development mode,
   * or a plain boolean in production mode.
   *
   * @param subjectId   - Subject ID to resolve via the adapter.
   * @param action      - Action the subject wants to perform.
   * @param resource    - Target resource.
   * @param environment - Optional request-time environment.
   * @param scope       - Optional scope for multi-tenant checks.
   * @returns Mode-dependent result: `boolean` in production, `IDecision` in development.
   */
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
      // Wrap so a throwing operator onError cannot escape the documented
      // fail-closed behaviour.
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
   * Returns a full evaluation trace showing why a permission was granted or
   * denied. Shows which policies matched, which rules fired, which conditions
   * passed/failed with actual vs expected values, and a human-readable summary.
   *
   * Only available in `'development'` mode. Throws in `'production'` mode.
   *
   * Does NOT trigger afterEvaluate/onDeny/onError hooks (read-only).
   * Does apply beforeEvaluate hook since it affects the evaluation.
   *
   * @param subjectId   - Subject ID to resolve via the adapter.
   * @param action      - Action the subject wants to perform.
   * @param resource    - Target resource.
   * @param environment - Optional request-time environment.
   * @param scope       - Optional scope for multi-tenant checks.
   * @returns A full {@link Explain.IResult} describing the evaluation.
   * @throws When the engine is in production mode, or `subjectId` is not a
   *   non-empty string of at most 1024 chars.
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
      req = await this._hooks.beforeEvaluate(req)
    }

    // Default the evaluation clock (after the hook, so a pinned `now` wins).
    req = ensureEnvNow(req)

    const allPolicies = await this._loadAllPolicies()

    // Lazy import: production mode users (which throw before this point)
    // pay zero bytes for the explain chunk. Bundlers split this into its
    // own chunk.
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
   * Batch check: evaluate many permissions at once for a single subject.
   * Returns a map keyed by `[@scope:]action:resource[:resourceId]` (see `iamBuildPermissionKey`).
   * Loads adapter data once, then evaluates each check.
   * Each check goes through scoped role enrichment and hooks, consistent with authorize().
   *
   * In `'production'` mode, returns `Record<string, boolean>`.
   * In `'development'` mode, returns the full typed {@link IamClient.PermissionMap}.
   *
   * @param subjectId   - Subject ID to resolve via the adapter.
   * @param checks      - Array of {@link IamClient.IPermissionCheck} descriptors.
   * @param environment - Optional request-time environment shared by all checks.
   * @returns Mode-dependent permission map.
   * @throws When `subjectId` is not a non-empty string of at most 1024 chars,
   *   or `checks` holds more than 1024 entries. Unlike `can`/`check`, an
   *   invalid batch is a caller bug, not a fail-closed deny.
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
    // Defensive cap: prevents an unbounded batch (e.g. attacker-driven UI gate
    // that floods checks) from running into thousands of per-check evaluations.
    // 1024 covers any plausible legitimate batch.
    if (checks.length > 1024) {
      throw new Error('[@gentleduck/iam:engine] permissions() refuses batches >1024 checks')
    }
    // `telemetry: false` skips per-check onMetrics for hot UI gates (~2x throughput).
    const telemetry = opts.telemetry !== false
    // Outer try synthesises all-deny on subject/policy load failure.
    let subject: IamRequest.ISubject
    try {
      // The policy load is awaited here rather than per check so a load failure
      // fails the whole batch closed, instead of surfacing on whichever check
      // happened to run first. Nothing binds the result: `_evaluateOnce` reads
      // it back from the merged cache this call just warmed.
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

    // Forward onPolicyError to evaluate* so batch checks surface per-policy
    // throws instead of silently dropping them.
    const onPolicyErrorHook = this._hooks.onPolicyError
    const onPolicyError = onPolicyErrorHook
      ? (err: Error, policy: AccessControl.IPolicy) => onPolicyErrorHook(err, policy.id)
      : undefined

    for (const c of checks) {
      const key = iamBuildPermissionKey(c.action, c.resource, c.resourceId, c.scope)
      // Per-check metrics: onMetrics fires once per check with failOpen signal
      // (unless `telemetry: false`).
      const t0 = telemetry && this._hooks.onMetrics ? performance.now() : 0

      // Trailing-hooks block runs OUTSIDE the evaluation try so a throwing
      // afterEvaluate/onDeny cannot rewrite the per-check verdict.
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
          resource: { type: c.resource, id: c.resourceId, attributes: {} },
          environment,
          scope: c.scope,
        }

        if (this._hooks.beforeEvaluate) {
          req = await this._hooks.beforeEvaluate(req)
        }

        // Default the evaluation clock per check (after the hook).
        req = ensureEnvNow(req)

        const signals: { failOpen?: boolean } = {}

        // Same path as `authorize()` - a batch check must never be able to
        // answer differently from the single check it batches. That includes
        // the reserved-refusal token: `permissions()` does not route through
        // `authorize()`, so the refusal has to be repeated here or one entry
        // point would grant what the other denies.
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
          resource: { type: c.resource, id: c.resourceId, attributes: {} },
          environment,
          scope: c.scope,
        }
        await this._safeHookCall(() => this._hooks.onError?.(err, errReq), 'onError')
        if (telemetry) this._emitMetrics(errReq, false, t0, false)
        map[key] = false
        continue
      }

      // Trailing-hooks block (outside try) - keeps hook throws from
      // rewriting the per-check verdict; mirrors authorize().
      if (decisionForHooks !== null && evalReq !== null) {
        const d = decisionForHooks
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
      // Left off entirely when no `onMutation` is wired, so an install that
      // does not want the audit bus builds no events and pays nothing for it.
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
   * Returns a view of this engine whose adapter runs on `client` - a driver
   * transaction handle - and whose cache invalidations buffer into `pending`
   * instead of applying and broadcasting immediately.
   *
   * Writes go through `.admin`, the same interface as {@link admin}. Reads run
   * on the returned view's own engine, which carries empty caches and so sees
   * the transaction's own uncommitted writes.
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
   * A rollback needs no cleanup: drop the facade and the buffered
   * invalidations go with it, or call `pending.discard()` to say so explicitly.
   *
   * @param client - Opaque driver handle, passed straight to the adapter.
   * @throws When the configured adapter has no `withClient`, rather than
   *   silently leaving the writes outside the caller's transaction.
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

  /** @internal Snapshot per-cache counters. Reached via {@link stats.get}. */
  private _statsSnapshot(): {
    policies: { hits: number; misses: number; size: number }
    roles: { hits: number; misses: number; size: number }
    rbacPolicy: { hits: number; misses: number; size: number }
    mergedPolicies: { hits: number; misses: number; size: number }
    subjects: { hits: number; misses: number; size: number }
  } {
    return statsSnapshotHelper(this._cachesForStats())
  }

  /** @internal Zero per-cache counters. Reached via {@link stats.reset}. */
  private _resetStats(): void {
    resetStatsHelper(this._cachesForStats())
  }

  /** @internal Clear all caches + in-flight resolvers. Reached via {@link cache.invalidate}. */
  private _invalidateAll(opts: { broadcast?: boolean } = {}): void {
    invalidateAll(this._cacheBag(), opts)
    this._compiledTable = null
    this._compiledTableGen++
  }

  /** @internal Clear one subject's cached data. Reached via {@link cache.invalidateSubject}. */
  private _invalidateSubject(subjectId: string, opts: { broadcast?: boolean } = {}): void {
    invalidateSubject(this._cacheBag(), subjectId, opts)
  }

  /** @internal Clear cached policies. Reached via {@link cache.invalidatePolicies}. */
  private _invalidatePolicies(opts: { broadcast?: boolean } = {}): void {
    invalidatePolicies(this._cacheBag(), opts)
    this._compiledTable = null
    this._compiledTableGen++
  }

  /** @internal Clear cached roles + selectively drop affected subjects. Reached via {@link cache.invalidateRoles}. */
  private _invalidateRoles(roleId?: TRole, opts: { broadcast?: boolean } = {}): void {
    invalidateRoles(this._cacheBag(), roleId, opts)
    this._compiledTable = null
    this._compiledTableGen++
  }

  /**
   * Warm `mergedPolicyCache` so the first request after boot doesn't pay the
   * full load + index cost. Bench shows ~15x speedup on the first call vs
   * cold. Recommended to call once at app startup.
   *
   * **In `'production'` mode it also builds the compiled permission table** -
   * the structure every production check reads. That is not just warm-up: a
   * config the table cannot represent (more than 32 roles) throws *here*, at
   * boot, where an orchestrator sees a failed start, rather than inside the
   * first authorization request. Development mode has no table and skips it.
   *
   * Pass `{ validator: true }` to also eagerly load the lazy validator
   * chunk (12 KB gzipped). Useful for operators who want to front-load
   * every cost at boot instead of paying it on first admin write. Read-only
   * services can leave it off.
   */
  async preload(opts: { validator?: boolean } = {}): Promise<void> {
    await preloadEngine({
      // In production the compiled table is what every check reads. Building it
      // here surfaces a config it cannot represent (over 32 roles) at boot,
      // instead of throwing inside the first authorization request.
      // Both modes now evaluate through the table, so both warm it at boot.
      buildCompiledTable: () => this._getCompiledTable(),
      loadAllPolicies: () => this._loadAllPolicies(),
      loadValidator: opts.validator === true,
    })
  }

  /**
   * Liveness + readiness probe. Performs one timed-out adapter round-trip
   * (`listPolicies`) and snapshots cache hit rates. Cheap enough to wire to
   * a `/healthz` route at the configured interval; returns `ok: false` if the
   * adapter is unreachable so an orchestrator can pull the instance out of
   * rotation.
   *
   * @returns A {@link IamEngineTypes.IHealth} snapshot.
   */
  async healthCheck(): Promise<IamEngineTypes.IHealth> {
    const health = await runHealthCheck(this._cachesForStats(), async () => {
      await this._withTimeout((opts) => this._adapter.listPolicies(opts), 'healthCheck.listPolicies')
      // An engine whose table cannot be built answers no check, so a green probe
      // would be a lie. Uses the cached table when there is one. A role-limit
      // fallback is not a failure - `_getCompiledTable` returns null for it and
      // it is reported below instead.
      await this._getCompiledTable()
    })
    const detail = this._roleLimitDetail
    if (detail === null) return health
    return {
      ...health,
      compiledTable: {
        available: false,
        limit: detail.limit,
        reason: 'role-limit-exceeded',
        roleCount: detail.roleCount,
      },
    }
  }
}

/**
 * Factory around {@link IamEngine}, for callers who prefer functions to `new`.
 *
 * Generic over the same parameters as the class so the caller's action,
 * resource, role, scope and mode types survive the call. In particular a config
 * carrying `mode: 'production'` produces a production-typed engine, on which
 * {@link IamEngine.explain} - development-only, and a runtime throw in
 * production - no longer typechecks.
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
