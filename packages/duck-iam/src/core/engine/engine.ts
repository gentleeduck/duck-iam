import { IamLRUCache } from '../../shared/cache'
import { iamBuildPermissionKey } from '../../shared/keys'
import { clearRegexCache } from '../conditions/conditions.libs'
import { evaluate, evaluateFast } from '../evaluate'
import type { Explain } from '../explain'
import { clearPathCache } from '../resolve/resolve'
import type { AccessControl, IamAdapter, IamClient, IamRequest } from '../types'
import { emitMetrics, safeHookCall } from './engine.hooks'
import {
  applyInvalidateEvent,
  type IEngineCacheBag,
  invalidateAll,
  invalidatePolicies,
  invalidateRoles,
  invalidateSubject,
} from './engine.invalidation'
import { createAdmin, enrichSubjectWithScopedRoles, ensureEnvNow } from './engine.libs'
import { disposeInvalidator, preloadEngine, runHealthCheck } from './engine.lifecycle'
import { type IIamLoaderDeps, loadAllPolicies, resolveSubject } from './engine.loaders'
import { resetStats as resetStatsHelper, statsSnapshot as statsSnapshotHelper } from './engine.stats'
import type { IamEngineTypes } from './engine.types'

/** Flush process-wide regex + dot-path caches; schedule periodically in multi-tenant deployments. */
export function iamFlushSharedCaches(): void {
  clearRegexCache()
  clearPathCache()
}
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
  TMode extends AccessControl.Mode = 'development',
> {
  private _adapter: IamAdapter.IAdapter<TAction, TResource, TRole, TScope>
  private _defaultEffect: AccessControl.Effect
  private _mode: AccessControl.Mode
  private _policyCombine: AccessControl.PolicyCombine
  private _scopeMode: 'flat' | 'hierarchical'
  private _scopeCombine: 'union' | 'override'
  private _hooks: IamEngineTypes.IHooks<TAction, TResource, TScope>
  private _maxPolicies: number
  private _maxRoles: number
  private _adapterTimeoutMs: number
  private _invalidator?: IamEngineTypes.IInvalidator<TRole>
  private _invalidatorUnsub: (() => void) | null = null
  private _policyCache: IamLRUCache<AccessControl.IPolicy[]>
  private _roleCache: IamLRUCache<AccessControl.IRole[]>
  private _rbacPolicyCache: IamLRUCache<AccessControl.IPolicy>
  private _mergedPolicyCache: IamLRUCache<AccessControl.IPolicy[]>
  private _subjectCache: IamLRUCache<IamRequest.ISubject>
  // Single-flight: coalesce concurrent cache-misses so a cold start under load
  // doesn't fan out N identical adapter calls. Cleared once the promise settles.
  private _inFlight = {
    policies: { value: null as Promise<AccessControl.IPolicy[]> | null },
    roles: { value: null as Promise<AccessControl.IRole[]> | null },
    rbac: { value: null as Promise<AccessControl.IPolicy> | null },
    merged: { value: null as Promise<AccessControl.IPolicy[]> | null },
    subjects: new Map<string, Promise<IamRequest.ISubject>>(),
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
    this._adapter = config.adapter
    this._defaultEffect = config.defaultEffect ?? 'deny'
    this._mode = config.mode ?? 'development'
    this._policyCombine = config.policyCombine ?? 'and'
    this._scopeMode = config.scopeMode ?? 'flat'
    this._scopeCombine = config.scopeCombine ?? 'union'
    this._hooks = config.hooks ?? {}

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
      // eslint-disable-next-line no-console
      console.warn(
        "[@gentleduck/iam:engine] engine configured with defaultEffect: 'allow' (fail-open). Every request with no applicable policy will be allowed.",
      )
    }

    this._maxPolicies = config.maxPolicies ?? 10_000
    this._maxRoles = config.maxRoles ?? 10_000
    this._adapterTimeoutMs = config.adapterTimeoutMs ?? 5_000

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

    const ttl = (config.cacheTTL ?? 60) * 1000
    const maxSize = config.maxCacheSize ?? 1000

    this._policyCache = new IamLRUCache(1, ttl) // single entry
    this._roleCache = new IamLRUCache(1, ttl)
    this._rbacPolicyCache = new IamLRUCache(1, ttl)
    this._mergedPolicyCache = new IamLRUCache(1, ttl)
    this._subjectCache = new IamLRUCache(maxSize, ttl)

    if (config.invalidator) {
      this._invalidator = config.invalidator
      this._invalidatorUnsub = config.invalidator.subscribe((event) => this._applyInvalidateEvent(event))
    }
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
  }

  /** Release the invalidator subscription. Call when discarding the engine. */
  dispose(): void {
    this._invalidatorUnsub = disposeInvalidator(this._invalidatorUnsub).unsub
  }

  /** Load all policies from the adapter, using the cache if available. */
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
      withTimeout: (fn, label) => this._withTimeout(fn, label),
    }
  }

  private _resolveSubject(subjectId: string): Promise<IamRequest.ISubject> {
    return resolveSubject(this._loaderDeps(), subjectId)
  }

  private _loadAllPolicies(): Promise<AccessControl.IPolicy[]> {
    return loadAllPolicies(this._loaderDeps())
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
    const t0 = this._hooks.onMetrics ? performance.now() : 0

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

      const allPolicies = await this._loadAllPolicies()

      const onPolicyErrorHook = this._hooks.onPolicyError
      const onPolicyError = onPolicyErrorHook
        ? (err: Error, policy: AccessControl.IPolicy) => onPolicyErrorHook(err, policy.id)
        : undefined

      const signals: { failOpen?: boolean } = {}
      if (this._mode === 'production') {
        const allowed = evaluateFast(
          allPolicies,
          req,
          this._defaultEffect,
          this._policyCombine,
          onPolicyError,
          signals,
          this._caches,
        )
        allowedForMetrics = allowed
        failOpenForMetrics = signals.failOpen === true
        result = this._asResult(allowed)
      } else {
        const decision = evaluate(
          allPolicies,
          req,
          this._defaultEffect,
          this._policyCombine,
          onPolicyError,
          signals,
          this._caches,
        )
        decisionForHooks = decision
        allowedForMetrics = decision.allowed
        failOpenForMetrics = signals.failOpen === true
        result = this._asResult(decision)
      }
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error))
      // onError can itself throw. Don't let an operator's onError bug
      // propagate over the engine's fail-closed behaviour.
      await this._safeHookCall(() => this._hooks.onError?.(err, req), 'onError')
      this._emitMetrics(req, false, t0, false)
      if (this._mode === 'production') return this._asResult(false)
      return this._asResult({
        allowed: false,
        effect: 'deny',
        reason: 'Evaluation error',
        duration: 0,
        timestamp: Date.now(),
      })
    }

    // Trailing hook block - runs OUTSIDE the evaluation try so a hook throw
    // cannot rewrite the decision. Each hook is individually wrapped so a
    // bug in one doesn't suppress the others.
    if (decisionForHooks !== null) {
      const d = decisionForHooks
      await this._safeHookCall(() => this._hooks.afterEvaluate?.(req, d), 'afterEvaluate')
      if (!d.allowed) {
        await this._safeHookCall(() => this._hooks.onDeny?.(req, d), 'onDeny')
      }
    }
    this._emitMetrics(req, allowedForMetrics, t0, failOpenForMetrics)
    return result
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
    return enriched.roles.map((r) => r as TRole)
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
      return (
        this._mode === 'production' ? false : { allowed: false, reason: 'invalid subjectId' }
      ) as AccessControl.ModeResult<TMode>
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

    // Apply beforeEvaluate hook (it may modify the request)
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
   * Returns a map keyed by "action:resource" or "scope:action:resource".
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
    let allPolicies: AccessControl.IPolicy[]
    try {
      ;[subject, allPolicies] = await Promise.all([this._resolveSubject(subjectId), this._loadAllPolicies()])
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

        if (this._mode === 'production') {
          const allowed = evaluateFast(
            allPolicies,
            req,
            this._defaultEffect,
            this._policyCombine,
            onPolicyError,
            signals,
            this._caches,
          )
          map[key] = allowed
          allowedForCheck = allowed
          failOpenForCheck = signals.failOpen === true
          evalReq = req
        } else {
          const decision = evaluate(
            allPolicies,
            req,
            this._defaultEffect,
            this._policyCombine,
            onPolicyError,
            signals,
            this._caches,
          )
          map[key] = decision.allowed
          decisionForHooks = decision
          allowedForCheck = decision.allowed
          failOpenForCheck = signals.failOpen === true
          evalReq = req
        }
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
    this._admin ??= createAdmin<TAction, TResource, TRole, TScope>(this._adapter, this)
    return this._admin
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
  }

  /** @internal Clear one subject's cached data. Reached via {@link cache.invalidateSubject}. */
  private _invalidateSubject(subjectId: string, opts: { broadcast?: boolean } = {}): void {
    invalidateSubject(this._cacheBag(), subjectId, opts)
  }

  /** @internal Clear cached policies. Reached via {@link cache.invalidatePolicies}. */
  private _invalidatePolicies(opts: { broadcast?: boolean } = {}): void {
    invalidatePolicies(this._cacheBag(), opts)
  }

  /** @internal Clear cached roles + selectively drop affected subjects. Reached via {@link cache.invalidateRoles}. */
  private _invalidateRoles(roleId?: TRole, opts: { broadcast?: boolean } = {}): void {
    invalidateRoles(this._cacheBag(), roleId, opts)
  }

  /**
   * Warm `mergedPolicyCache` so the first request after boot doesn't pay the
   * full load + index cost. Bench shows ~15x speedup on the first call vs
   * cold. Recommended to call once at app startup.
   *
   * Pass `{ validator: true }` to also eagerly load the lazy validator
   * chunk (12 KB gzipped). Useful for operators who want to front-load
   * every cost at boot instead of paying it on first admin write. Read-only
   * services can leave it off.
   */
  async preload(opts: { validator?: boolean } = {}): Promise<void> {
    await preloadEngine({
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
    return runHealthCheck(this._cachesForStats(), async () => {
      await this._withTimeout((opts) => this._adapter.listPolicies(opts), 'healthCheck.listPolicies')
    })
  }
}

/** Factory around {@link IamEngine}, for callers who prefer functions to `new`. */
export function iamEngine(...args: ConstructorParameters<typeof IamEngine>): IamEngine {
  return new IamEngine(...args)
}
