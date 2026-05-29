import { LRUCache } from '../../shared/cache'
import { buildPermissionKey } from '../../shared/keys'
import { clearRegexCache } from '../conditions/conditions.libs'
import { evaluate, evaluateFast } from '../evaluate'
import type { Explain } from '../explain'
import { explainEvaluation } from '../explain'
import { resolveEffectiveRoles, rolesToPolicy } from '../rbac'
import { clearPathCache } from '../resolve/resolve'
import type { AccessControl, Adapter, Client, Request } from '../types'
import {
  createAdmin,
  deepFreezePolicy,
  enrichSubjectWithScopedRoles,
  runSingleFlight,
  runSingleFlightKeyed,
} from './engine.libs'
import type { EngineTypes } from './engine.types'

/**
 * Module-level flush of process-wide compiled-regex and resolved-path caches
 * (the `matches`-operator regex cache and dot-path segment cache).
 *
 * These caches are globals - every Engine in the process shares them. Multi-
 * tenant operators schedule this periodically to bound any single tenant's
 * eviction influence. Costs: the next request pays one compile per
 * matches-pattern and one segment-split per dot-path.
 *
 * @example
 * ```ts
 * import { flushSharedCaches } from '@gentleduck/iam'
 * setInterval(flushSharedCaches, 5 * 60 * 1000)
 * ```
 */
export function flushSharedCaches(): void {
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
 * const engine = new Engine({ adapter, defaultEffect: 'deny' })
 *
 * const allowed = await engine.can('user-1', 'read', { type: 'post', attributes: {} })
 * const decision = await engine.check('user-1', 'update', post)
 * const trace = await engine.explain('user-1', 'delete', post)
 * ```
 */
export class Engine<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
  TMode extends AccessControl.Mode = 'development',
> {
  private _adapter: Adapter.IAdapter<TAction, TResource, TRole, TScope>
  private _defaultEffect: AccessControl.Effect
  private _mode: AccessControl.Mode
  private _policyCombine: AccessControl.PolicyCombine
  private _hooks: EngineTypes.IHooks<TAction, TResource, TScope>
  private _maxPolicies: number
  private _maxRoles: number
  private _adapterTimeoutMs: number
  private _invalidator?: EngineTypes.IInvalidator<TRole>
  private _invalidatorUnsub: (() => void) | null = null
  private _policyCache: LRUCache<AccessControl.IPolicy[]>
  private _roleCache: LRUCache<AccessControl.IRole[]>
  private _rbacPolicyCache: LRUCache<AccessControl.IPolicy>
  private _mergedPolicyCache: LRUCache<AccessControl.IPolicy[]>
  private _subjectCache: LRUCache<Request.ISubject>
  // Single-flight: coalesce concurrent cache-misses so a cold start under load
  // doesn't fan out N identical adapter calls. Cleared once the promise settles.
  private _policiesInFlight: Promise<AccessControl.IPolicy[]> | null = null
  private _rolesInFlight: Promise<AccessControl.IRole[]> | null = null
  private _rbacInFlight: Promise<AccessControl.IPolicy> | null = null
  private _mergedInFlight: Promise<AccessControl.IPolicy[]> | null = null
  private _subjectsInFlight = new Map<string, Promise<Request.ISubject>>()
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
  constructor(config: EngineTypes.IConfig<TAction, TResource, TRole, TScope, TMode>) {
    this._adapter = config.adapter
    this._defaultEffect = config.defaultEffect ?? 'deny'
    this._mode = config.mode ?? 'development'
    this._policyCombine = config.policyCombine ?? 'and'
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

    this._policyCache = new LRUCache(1, ttl) // single entry
    this._roleCache = new LRUCache(1, ttl)
    this._rbacPolicyCache = new LRUCache(1, ttl)
    this._mergedPolicyCache = new LRUCache(1, ttl)
    this._subjectCache = new LRUCache(maxSize, ttl)

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

  /** Apply a cross-instance invalidate event to local caches. */
  private _applyInvalidateEvent(event: EngineTypes.IInvalidateEvent<TRole>): void {
    switch (event.kind) {
      case 'all':
        this._invalidateAll({ broadcast: false })
        return
      case 'policies':
        this._invalidatePolicies({ broadcast: false })
        return
      case 'roles':
        this._invalidateRoles(event.roleId, { broadcast: false })
        return
      case 'subject':
        this._invalidateSubject(event.subjectId, { broadcast: false })
    }
  }

  /**
   * Release the invalidator subscription. Call when discarding the engine.
   */
  dispose(): void {
    this._invalidatorUnsub?.()
    this._invalidatorUnsub = null
  }

  /** Load all policies from the adapter, using the cache if available. */
  private async _loadPolicies(): Promise<AccessControl.IPolicy[]> {
    const cached = this._policyCache.get('all')
    if (cached) return cached
    if (this._policiesInFlight) return this._policiesInFlight
    return runSingleFlight(
      () => this._policiesInFlight,
      (p) => {
        this._policiesInFlight = p
      },
      async () => {
        const policies = await this._withTimeout((opts) => this._adapter.listPolicies(opts), 'listPolicies')
        if (policies.length > this._maxPolicies) {
          throw new Error(
            `[@gentleduck/iam:engine] adapter returned ${policies.length} policies; maxPolicies is ${this._maxPolicies}. Raise the limit or fix the adapter.`,
          )
        }
        return policies
      },
      (policies) => {
        this._policyCache.set('all', policies)
      },
    )
  }

  /** Load all roles from the adapter, using the cache if available. */
  private async _loadRoles(): Promise<AccessControl.IRole[]> {
    const cached = this._roleCache.get('all')
    if (cached) return cached
    if (this._rolesInFlight) return this._rolesInFlight
    return runSingleFlight(
      () => this._rolesInFlight,
      (p) => {
        this._rolesInFlight = p
      },
      async () => {
        const roles = await this._withTimeout((opts) => this._adapter.listRoles(opts), 'listRoles')
        if (roles.length > this._maxRoles) {
          throw new Error(
            `[@gentleduck/iam:engine] adapter returned ${roles.length} roles; maxRoles is ${this._maxRoles}. Raise the limit or fix the adapter.`,
          )
        }
        return roles
      },
      (roles) => {
        this._roleCache.set('all', roles)
      },
    )
  }

  /** Resolve a subject's roles, scoped roles, and attributes, using the cache if available. */
  private async _resolveSubject(subjectId: string): Promise<Request.ISubject> {
    const cached = this._subjectCache.get(subjectId)
    if (cached) return cached
    const inFlight = this._subjectsInFlight.get(subjectId)
    if (inFlight) return inFlight
    return runSingleFlightKeyed(
      this._subjectsInFlight,
      subjectId,
      async () => {
        const [assignedRoles, attributes, allRoles] = await Promise.all([
          this._withTimeout((opts) => this._adapter.getSubjectRoles(subjectId, opts), 'getSubjectRoles'),
          this._withTimeout((opts) => this._adapter.getSubjectAttributes(subjectId, opts), 'getSubjectAttributes'),
          this._loadRoles(),
        ])
        const roles = resolveEffectiveRoles(assignedRoles, allRoles)
        const scopedRolesFn = this._adapter.getSubjectScopedRoles
        const scopedRoles = scopedRolesFn
          ? await this._withTimeout(
              (opts) => scopedRolesFn.call(this._adapter, subjectId, opts),
              'getSubjectScopedRoles',
            )
          : undefined
        const subject: Request.ISubject = { id: subjectId, roles, scopedRoles, attributes }
        return subject
      },
      (subject) => {
        this._subjectCache.set(subjectId, subject)
      },
    )
  }

  /**
   * Load RBAC + ABAC policies for evaluation.
   * Each user-defined policy keeps its own combining algorithm.
   * The RBAC-generated policy uses allow-overrides (set by rolesToPolicy).
   * The rolesToPolicy() conversion is cached to avoid recomputation.
   */
  private async _loadAllPolicies(): Promise<AccessControl.IPolicy[]> {
    const cached = this._mergedPolicyCache.get('merged')
    if (cached) return cached
    if (this._mergedInFlight) return this._mergedInFlight
    // runSingleFlight handles sentinel-compare so an invalidate() mid-await
    // cannot repopulate the merged cache with stale rules.
    return runSingleFlight(
      () => this._mergedInFlight,
      (p) => {
        this._mergedInFlight = p
      },
      async () => {
        const [policies, rbacPolicy] = await Promise.all([this._loadPolicies(), this._loadRbacPolicy()])
        // Skip the RBAC policy when it has no rules - including it would
        // contribute a default-effect deny under AND combine.
        return rbacPolicy.rules.length === 0 ? policies : [rbacPolicy, ...policies]
      },
      (merged) => {
        this._mergedPolicyCache.set('merged', merged)
      },
    )
  }

  /**
   * Build the auto-generated RBAC policy from the role graph.
   *
   * Single-flighted so concurrent callers after a TTL eviction share one
   * rebuild promise. The build itself is sync but `loadRoles()` is async on
   * cold-miss, so the await window is where double-compute would otherwise
   * happen.
   *
   * Cached output is **deep-frozen** - every consumer (`evaluate`, `explain`,
   * `evaluateFast`) reads the same reference, and a callee that mutates a
   * shared rule's `actions` array would corrupt every future request.
   */
  private async _loadRbacPolicy(): Promise<AccessControl.IPolicy> {
    const cached = this._rbacPolicyCache.get('rbac')
    if (cached) return cached
    if (this._rbacInFlight) return this._rbacInFlight
    return runSingleFlight(
      () => this._rbacInFlight,
      (p) => {
        this._rbacInFlight = p
      },
      async () => {
        const roles = await this._loadRoles()
        return deepFreezePolicy(rolesToPolicy(roles))
      },
      (built) => {
        this._rbacPolicyCache.set('rbac', built)
      },
    )
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
   * Full authorization check with a complete {@link Request.IAccessRequest}.
   *
   * In `'production'` mode, returns a plain `boolean`.
   * In `'development'` mode, returns a full {@link AccessControl.IDecision}.
   *
   * @param request - The access request to evaluate.
   * @returns The decision shape determined by the engine's mode.
   */
  async authorize(
    request: Request.IAccessRequest<TAction, TResource, TScope>,
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
        const enriched = enrichSubjectWithScopedRoles(req.subject, req.scope)
        if (enriched !== req.subject) req = { ...req, subject: enriched }
      }

      if (this._hooks.beforeEvaluate) {
        req = await this._hooks.beforeEvaluate(req)
      }

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
    try {
      await fn()
    } catch (err) {
      // console.error itself can throw (closed stdout in a daemon, broken
      // pipe, user-replaced Console with a buggy override). A throw here
      // would escape _safeHookCall and re-expose the original hook throw.
      try {
        // eslint-disable-next-line no-console
        console.error(`[@gentleduck/iam:engine] ${hookName} hook threw - swallowed to preserve decision`, err)
      } catch {
        /* last-resort: give up logging; decision is more important than diagnostics */
      }
    }
  }

  /**
   * Fires the `onMetrics` hook if configured. Synchronous; takes the start
   * timestamp captured at the top of `authorize` so the caller doesn't pay
   * `performance.now()` cost when no hook is wired.
   */
  private _emitMetrics(
    req: Request.IAccessRequest<TAction, TResource, TScope>,
    allowed: boolean,
    t0: number,
    failOpen: boolean,
  ): void {
    const hook = this._hooks.onMetrics
    if (!hook) return
    // Hook throws must not escape - _emitMetrics is called from catch arms
    // whose entire purpose is producing a fail-closed deny. A throwing
    // onMetrics there would replace the deny with a raw error.
    try {
      hook({
        subjectId: req.subject.id,
        action: req.action,
        resource: req.resource.type,
        allowed,
        durationMs: performance.now() - t0,
        mode: this._mode,
        failOpen,
      })
    } catch (err) {
      // Defensive - see _safeHookCall.
      try {
        // eslint-disable-next-line no-console
        console.error('[@gentleduck/iam:engine] onMetrics hook threw - swallowed to preserve decision', err)
      } catch {
        /* last-resort: give up logging */
      }
    }
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
    resource: Request.IResource<TResource>,
    environment?: Request.IAccessRequest<TAction, TResource, TScope>['environment'],
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
      const errReq: Request.IAccessRequest<TAction, TResource, TScope> = {
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
    resource: Request.IResource<TResource>,
    environment?: Request.IAccessRequest<TAction, TResource, TScope>['environment'],
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
      const req: Request.IAccessRequest<TAction, TResource, TScope> = {
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
    this: Engine<TAction, TResource, TRole, TScope, 'development'>,
    subjectId: string,
    action: TAction,
    resource: Request.IResource<TResource>,
    environment?: Request.IAccessRequest<TAction, TResource, TScope>['environment'],
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
      enrichedSubject = enrichSubjectWithScopedRoles(subject, scope)
    }

    const scopedRolesApplied = enrichedSubject.roles.filter((r) => !originalRoles.includes(r))

    let req: Request.IAccessRequest<TAction, TResource, TScope> = {
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

    const allPolicies = await this._loadAllPolicies()

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
   * In `'development'` mode, returns the full typed {@link Client.PermissionMap}.
   *
   * @param subjectId   - Subject ID to resolve via the adapter.
   * @param checks      - Array of {@link Client.IPermissionCheck} descriptors.
   * @param environment - Optional request-time environment shared by all checks.
   * @returns Mode-dependent permission map.
   */
  async permissions(
    subjectId: string,
    checks: readonly Client.IPermissionCheck<TAction, TResource, TScope>[],
    environment?: Request.IAccessRequest<TAction, TResource, TScope>['environment'],
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
    let subject: Request.ISubject
    let allPolicies: AccessControl.IPolicy[]
    try {
      ;[subject, allPolicies] = await Promise.all([this._resolveSubject(subjectId), this._loadAllPolicies()])
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error))
      const failClosed: Record<string, boolean> = {}
      for (const c of checks) {
        failClosed[buildPermissionKey(c.action, c.resource, c.resourceId, c.scope)] = false
      }
      const errReq: Request.IAccessRequest<TAction, TResource, TScope> = {
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
    const enrichedByScope = new Map<TScope, Request.ISubject>()

    // Forward onPolicyError to evaluate* so batch checks surface per-policy
    // throws instead of silently dropping them.
    const onPolicyErrorHook = this._hooks.onPolicyError
    const onPolicyError = onPolicyErrorHook
      ? (err: Error, policy: AccessControl.IPolicy) => onPolicyErrorHook(err, policy.id)
      : undefined

    for (const c of checks) {
      const key = buildPermissionKey(c.action, c.resource, c.resourceId, c.scope)
      // Per-check metrics: onMetrics fires once per check with failOpen signal
      // (unless `telemetry: false`).
      const t0 = telemetry && this._hooks.onMetrics ? performance.now() : 0

      // Trailing-hooks block runs OUTSIDE the evaluation try so a throwing
      // afterEvaluate/onDeny cannot rewrite the per-check verdict.
      let decisionForHooks: AccessControl.IDecision | null = null
      let allowedForCheck = false
      let failOpenForCheck = false
      let evalReq: Request.IAccessRequest<TAction, TResource, TScope> | null = null

      try {
        let enrichedSubject = subject
        if (c.scope && subject.scopedRoles?.length) {
          const cached = enrichedByScope.get(c.scope)
          if (cached) {
            enrichedSubject = cached
          } else {
            enrichedSubject = enrichSubjectWithScopedRoles(subject, c.scope)
            enrichedByScope.set(c.scope, enrichedSubject)
          }
        }

        let req: Request.IAccessRequest<TAction, TResource, TScope> = {
          subject: enrichedSubject,
          action: c.action,
          resource: { type: c.resource, id: c.resourceId, attributes: {} },
          environment,
          scope: c.scope,
        }

        if (this._hooks.beforeEvaluate) {
          req = await this._hooks.beforeEvaluate(req)
        }

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
        const errReq: Request.IAccessRequest<TAction, TResource, TScope> = {
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

  private _admin?: EngineTypes.IAdmin<TAction, TResource, TRole, TScope>

  /**
   * Lazily-built admin interface for CRUD operations on policies, roles, subjects.
   */
  get admin(): EngineTypes.IAdmin<TAction, TResource, TRole, TScope> {
    this._admin ??= createAdmin<TAction, TResource, TRole, TScope>(this._adapter, this)
    return this._admin
  }

  /** @internal Snapshot per-cache counters. Reached via {@link stats.get}. */
  private _statsSnapshot(): {
    policies: { hits: number; misses: number; size: number }
    roles: { hits: number; misses: number; size: number }
    rbacPolicy: { hits: number; misses: number; size: number }
    mergedPolicies: { hits: number; misses: number; size: number }
    subjects: { hits: number; misses: number; size: number }
  } {
    return {
      policies: this._policyCache.stats,
      roles: this._roleCache.stats,
      rbacPolicy: this._rbacPolicyCache.stats,
      mergedPolicies: this._mergedPolicyCache.stats,
      subjects: this._subjectCache.stats,
    }
  }

  /** @internal Zero per-cache counters. Reached via {@link stats.reset}. */
  private _resetStats(): void {
    this._policyCache.resetStats()
    this._roleCache.resetStats()
    this._rbacPolicyCache.resetStats()
    this._mergedPolicyCache.resetStats()
    this._subjectCache.resetStats()
  }

  /** @internal Clear all caches + in-flight resolvers. Reached via {@link cache.invalidate}. */
  private _invalidateAll(opts: { broadcast?: boolean } = {}): void {
    this._policyCache.clear()
    this._roleCache.clear()
    this._rbacPolicyCache.clear()
    this._subjectCache.clear()
    this._policiesInFlight = null
    this._rolesInFlight = null
    this._rbacInFlight = null
    this._mergedInFlight = null
    this._mergedPolicyCache.clear()
    this._subjectsInFlight.clear()
    if (opts.broadcast !== false && this._invalidator) {
      void this._invalidator.publish({ kind: 'all' })
    }
  }

  /** @internal Clear one subject's cached data. Reached via {@link cache.invalidateSubject}. */
  private _invalidateSubject(subjectId: string, opts: { broadcast?: boolean } = {}): void {
    if (typeof subjectId !== 'string' || subjectId.length === 0 || subjectId.length > 1024) return
    this._subjectCache.delete(subjectId)
    this._subjectsInFlight.delete(subjectId)
    if (opts.broadcast !== false && this._invalidator) {
      void this._invalidator.publish({ kind: 'subject', subjectId })
    }
  }

  /** @internal Clear cached policies. Reached via {@link cache.invalidatePolicies}. */
  private _invalidatePolicies(opts: { broadcast?: boolean } = {}): void {
    this._policyCache.clear()
    this._policiesInFlight = null
    this._mergedInFlight = null
    this._mergedPolicyCache.clear()
    if (opts.broadcast !== false && this._invalidator) {
      void this._invalidator.publish({ kind: 'policies' })
    }
  }

  /** @internal Clear cached roles + selectively drop affected subjects. Reached via {@link cache.invalidateRoles}. */
  private _invalidateRoles(roleId?: TRole, opts: { broadcast?: boolean } = {}): void {
    // Treat invalid roleId (non-string / oversize) as "clear all subjects"
    // (the safer, fail-closed branch) rather than silently no-oping.
    if (roleId !== undefined && (typeof roleId !== 'string' || roleId.length === 0 || roleId.length > 1024)) {
      roleId = undefined
    }
    this._roleCache.clear()
    this._rbacPolicyCache.clear()
    this._rolesInFlight = null
    this._rbacInFlight = null
    this._mergedInFlight = null
    this._mergedPolicyCache.clear()
    if (roleId === undefined) {
      this._subjectCache.clear()
      this._subjectsInFlight.clear()
    } else {
      for (const [subjectId, subject] of this._subjectCache.entries()) {
        const inRoles = subject.roles.includes(roleId)
        const inScoped = subject.scopedRoles?.some((sr) => sr.role === roleId) ?? false
        if (inRoles || inScoped) {
          this._subjectCache.delete(subjectId)
          this._subjectsInFlight.delete(subjectId)
        }
      }
    }
    if (opts.broadcast !== false && this._invalidator) {
      void this._invalidator.publish({ kind: 'roles', roleId })
    }
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
    const tasks: Array<Promise<unknown>> = [this._loadAllPolicies()]
    if (opts.validator) tasks.push(import('../validate'))
    await Promise.all(tasks)
  }

  /**
   * Liveness + readiness probe. Performs one timed-out adapter round-trip
   * (`listPolicies`) and snapshots cache hit rates. Cheap enough to wire to
   * a `/healthz` route at the configured interval; returns `ok: false` if the
   * adapter is unreachable so an orchestrator can pull the instance out of
   * rotation.
   *
   * @returns A {@link EngineTypes.IHealth} snapshot.
   */
  async healthCheck(): Promise<EngineTypes.IHealth> {
    const t0 = performance.now()
    let adapter: 'ok' | 'fail' = 'ok'
    let lastError: string | undefined
    try {
      await this._withTimeout((opts) => this._adapter.listPolicies(opts), 'healthCheck.listPolicies')
    } catch (err) {
      adapter = 'fail'
      lastError = err instanceof Error ? err.message : String(err)
    }
    const s = this._statsSnapshot()
    const total =
      s.policies.hits +
      s.policies.misses +
      s.roles.hits +
      s.roles.misses +
      s.rbacPolicy.hits +
      s.rbacPolicy.misses +
      s.mergedPolicies.hits +
      s.mergedPolicies.misses +
      s.subjects.hits +
      s.subjects.misses
    const hits = s.policies.hits + s.roles.hits + s.rbacPolicy.hits + s.mergedPolicies.hits + s.subjects.hits
    return {
      ok: adapter === 'ok',
      adapter,
      cacheHitRate: total === 0 ? 0 : hits / total,
      adapterLatencyMs: Math.round(performance.now() - t0),
      lastError,
    }
  }
}
