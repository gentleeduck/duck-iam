import type { AccessControl, IamAdapter, IamPrimitives, IamRequest } from '../types'
export namespace IamEngineTypes {
  /**
   * Administrative interface for managing policies, roles, and subject data.
   * Accessed via `engine.admin`. Mutation methods invalidate the relevant caches.
   *
   * @template TAction   - Union of valid action strings.
   * @template TResource - Union of valid resource strings.
   * @template TRole     - Union of valid role IDs.
   * @template TScope    - Union of valid scope strings.
   */
  export interface IAdmin<
    TAction extends string = string,
    TResource extends string = string,
    TRole extends string = string,
    TScope extends string = string,
  > {
    listPolicies(): Promise<AccessControl.IPolicy<TAction, TResource, TRole>[]>
    getPolicy(id: string): Promise<AccessControl.IPolicy<TAction, TResource, TRole> | null>
    /** Invalidates the policy cache. */
    savePolicy(policy: AccessControl.IPolicy<TAction, TResource, TRole>): Promise<void>
    /** Invalidates the policy cache. */
    deletePolicy(id: string): Promise<void>

    listRoles(): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope>[]>
    getRole(id: string): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope> | null>
    /** Invalidates role + subject caches keyed on `role.id`. */
    saveRole(role: AccessControl.IRole<TAction, TResource, TRole, TScope>): Promise<void>
    /** Invalidates role + subject caches keyed on `id`. */
    deleteRole(id: string): Promise<void>

    /** Invalidates the subject's cache entry. */
    assignRole(subjectId: string, roleId: TRole, scope?: TScope): Promise<void>
    /** Invalidates the subject's cache entry. */
    revokeRole(subjectId: string, roleId: TRole, scope?: TScope): Promise<void>
    /**
     * Moves a subject's role assignment from `fromScope` to `toScope` in place when the
     * adapter supports it (one write); falls back to revoke + assign otherwise. Invalidates
     * the subject's cache entry either way.
     */
    updateAssignmentScope(
      subjectId: string,
      roleId: TRole,
      fromScope: TScope | undefined,
      toScope: TScope | undefined,
      actor?: string,
    ): Promise<void>
    /** Merges into the subject's attribute bag; invalidates the subject's cache entry. */
    setAttributes(subjectId: string, attrs: IamPrimitives.Attributes): Promise<void>
    getAttributes(subjectId: string): Promise<IamPrimitives.Attributes>

    /**
     * Export a *configuration* snapshot - policies + roles. Subject/assignment
     * data is intentionally excluded: it's user data, varies per environment,
     * and most adapters can't enumerate subjects cheaply. Use for environment
     * promotion (staging -> prod), GitOps-style policy review, or backup.
     */
    export(): Promise<ISnapshot<TAction, TResource, TRole, TScope>>
    /**
     * Import a configuration snapshot.
     *
     * - `mode: 'merge'` (default) - `savePolicy` / `saveRole` each entry. Existing
     *   IDs are overwritten; absent IDs are untouched.
     * - `mode: 'replace'` - first deletes every existing policy / role not in
     *   the snapshot, then upserts. Use for full sync from a source of truth.
     *
     * Validates the snapshot's `schemaVersion` before applying. Schema
     * mismatches throw before any write.
     */
    import(snapshot: ISnapshot<TAction, TResource, TRole, TScope>, options?: IImportOptions): Promise<IImportResult>
  }

  /**
   * Schema-versioned configuration snapshot. Bumping `schemaVersion` is a
   * breaking change to the serialized shape; consumers refuse unknown
   * versions instead of silently doing the wrong thing.
   *
   * @template TAction   - Union of valid action strings.
   * @template TResource - Union of valid resource strings.
   * @template TRole     - Union of valid role IDs.
   * @template TScope    - Union of valid scope strings.
   */
  export interface ISnapshot<
    TAction extends string = string,
    TResource extends string = string,
    TRole extends string = string,
    TScope extends string = string,
  > {
    readonly schemaVersion: 1
    readonly exportedAt: string
    readonly policies: readonly AccessControl.IPolicy<TAction, TResource, TRole>[]
    readonly roles: readonly AccessControl.IRole<TAction, TResource, TRole, TScope>[]
  }

  /** Options for {@link IAdmin.import}. */
  export interface IImportOptions {
    readonly mode?: 'merge' | 'replace'
  }

  /**
   * Counts returned from {@link IAdmin.import} reporting how many policies and
   * roles were added or deleted.
   */
  export interface IImportResult {
    readonly policiesAdded: number
    readonly policiesDeleted: number
    readonly rolesAdded: number
    readonly rolesDeleted: number
  }

  /**
   * Lightweight metrics event emitted after every evaluation. Carries only
   * primitives so production-mode callers (which would otherwise skip
   * Decision allocation) can still observe latency and outcome.
   *
   * @template TAction   - Union of valid action strings.
   * @template TResource - Union of valid resource strings.
   */
  export interface IMetricsEvent<TAction extends string = string, TResource extends string = string> {
    /** The subject ID the check ran against. */
    readonly subjectId: string
    /** The action that was checked. */
    readonly action: TAction
    /** The resource type that was checked. */
    readonly resource: TResource
    /** Final allow / deny verdict. */
    readonly allowed: boolean
    /** Wall-clock duration of the evaluation in milliseconds. */
    readonly durationMs: number
    /** Engine mode in effect (`'production'` or `'development'`). */
    readonly mode: AccessControl.Mode
    /**
     * `true` when the verdict was `allow` solely because the engine's
     * `defaultEffect: 'allow'` fallback fired (no applicable policy). Always
     * `false` when an explicit allow rule matched, or when the verdict was
     * deny. Operators chart this to detect silent policy-set breakage
     * (broken adapter, mass deletion, ReDoS-dropped rules) that the boolean
     * verdict alone hides.
     */
    readonly failOpen: boolean
  }

  /**
   * Lifecycle hooks. Wire `beforeEvaluate` for request enrichment,
   * `afterEvaluate` / `onDeny` for audit + alerting, `onError` for failure
   * paths, and `onMetrics` for latency / hit-rate telemetry.
   *
   * @template TAction   - Union of valid action strings.
   * @template TResource - Union of valid resource strings.
   * @template TScope    - Union of valid scope strings.
   * @example
   * ```ts
   * const hooks: IamEngineTypes.IHooks = {
   *   beforeEvaluate: req => ({ ...req, environment: { ...req.environment, hour: new Date().getHours() } }),
   *   onDeny: (req, decision) => console.warn('denied', req, decision.reason),
   * }
   * ```
   */
  export interface IHooks<
    TAction extends string = string,
    TResource extends string = string,
    TScope extends string = string,
  > {
    /** Called before policy evaluation. May return a modified request. */
    beforeEvaluate?(
      request: IamRequest.IAccessRequest<TAction, TResource, TScope>,
    ):
      | IamRequest.IAccessRequest<TAction, TResource, TScope>
      | Promise<IamRequest.IAccessRequest<TAction, TResource, TScope>>
    /** Called after every evaluation with the final decision (development mode only). */
    afterEvaluate?(
      request: IamRequest.IAccessRequest<TAction, TResource, TScope>,
      decision: AccessControl.IDecision,
    ): void | Promise<void>
    /** Called only when a request is denied (development mode only). */
    onDeny?(
      request: IamRequest.IAccessRequest<TAction, TResource, TScope>,
      decision: AccessControl.IDecision,
    ): void | Promise<void>
    /** Called when an error occurs during evaluation. The engine then returns a deny. */
    onError?(error: Error, request: IamRequest.IAccessRequest<TAction, TResource, TScope>): void | Promise<void>
    /**
     * Called when evaluation of a single policy throws (malformed rule, bad
     * condition tree, adapter returning garbage). The policy is treated as
     * NotApplicable so the rest of the policy set continues to evaluate; the
     * hook is the only signal the operator gets that a stored row is broken.
     */
    onPolicyError?(error: Error, policyId: string): void
    /**
     * Called once per evaluation with a primitive-only event. Cheap in both
     * modes - production callers can wire this for latency / outcome telemetry
     * without paying the cost of a full {@link AccessControl.IDecision}.
     */
    onMetrics?(event: IMetricsEvent<TAction, TResource>): void
  }

  /**
   * Configuration for creating an {@link IamEngine} instance.
   *
   * @template TAction   - Union of valid action strings.
   * @template TResource - Union of valid resource strings.
   * @template TRole     - Union of valid role IDs.
   * @template TScope    - Union of valid scope strings.
   * @template TMode     - Engine mode (`'development'` or `'production'`).
   * @example
   * ```ts
   * const config: IamEngineTypes.IConfig = {
   *   adapter: new InMemoryAdapter(),
   *   defaultEffect: 'deny',
   *   mode: 'development',
   * }
   * ```
   */
  export interface IConfig<
    TAction extends string = string,
    TResource extends string = string,
    TRole extends string = string,
    TScope extends string = string,
    TMode extends AccessControl.Mode = 'development',
  > {
    /** The storage adapter that provides policies, roles, and subject data. */
    readonly adapter: IamAdapter.IAdapter<TAction, TResource, TRole, TScope>
    /** The default effect when no rule matches. Defaults to `'deny'`. */
    readonly defaultEffect?: 'allow' | 'deny'
    /** Cache time-to-live in seconds. Defaults to `60`. Set to `0` to disable caching. */
    readonly cacheTTL?: number
    /** Maximum number of entries in the subject cache. Defaults to `1000`. */
    readonly maxCacheSize?: number
    /** Lifecycle hooks for observing or transforming requests and decisions. */
    readonly hooks?: IHooks<TAction, TResource, TScope>
    /** Execution mode. `'development'` returns rich Decision objects; `'production'` returns plain booleans. */
    readonly mode?: TMode
    /**
     * Strategy for combining decisions across multiple policies. Defaults to
     * `'and'` (every policy must allow). See {@link AccessControl.PolicyCombine}.
     */
    readonly policyCombine?: AccessControl.PolicyCombine
    /**
     * Hard ceiling on how many policies the engine will load from its adapter.
     * An over-cap load throws when the policy cache is filled, so the cost is
     * paid once per cache fill, not per request. Defaults to `10_000`; tune up
     * if your fleet legitimately has more, tune down to fail loudly on adapter
     * corruption.
     */
    readonly maxPolicies?: number
    /** Hard ceiling on roles loaded from the adapter. Defaults to `10_000`. */
    readonly maxRoles?: number
    /**
     * Opt-in to `defaultEffect: 'allow'` in production mode.
     *
     * Fail-open semantics in a production authorization engine are a security
     * footgun - a buggy condition or an adapter blip can flip a decision from
     * deny to allow. The engine constructor refuses the combination unless
     * this flag is `true`. Development mode is unaffected.
     */
    readonly allowFailOpen?: boolean
    /**
     * Per-adapter-call timeout in milliseconds. The engine aborts the read
     * via an `AbortController` and rejects with a timeout error after this
     * window. Defaults to `5_000` (5 s). Set to `0` to disable.
     *
     * Adapters that honor `IReadOptions.signal` (HttpAdapter, Redis with
     * RESET, custom drivers) hard-cancel the in-flight call; adapters that
     * don't still release the request thread - the orphaned work just
     * runs to completion in the background.
     */
    readonly adapterTimeoutMs?: number
    /**
     * Hard ceiling on concurrent distinct-subject adapter loads. Defaults to
     * `0` (unbounded). A cold-flat thundering herd - a burst of never-before-
     * cached subjects arriving faster than the adapter resolves them - grows
     * `inFlight.subjects` (and the promise closures it holds) without limit;
     * setting this caps that growth. Once the cap is reached, a *new* subject
     * load rejects immediately with a `subject load shed` error instead of
     * calling the adapter; a call that hits the subject cache, or joins an
     * already-in-flight load for the same subject, never counts against it.
     * The rejection surfaces through `can`/`check`/`authorize`'s existing
     * fail-closed error handling - no separate wiring needed.
     */
    readonly maxConcurrentSubjectLoads?: number
    /**
     * Cross-instance cache invalidation broadcaster. Wire a pub/sub helper
     * (e.g. `createRedisInvalidator(redis, channel)`) here and every engine
     * instance subscribed to the same channel will drop its local caches
     * when any node mutates a policy / role / subject.
     */
    readonly invalidator?: IInvalidator<TRole>
    /**
     * How scoped role assignments match a request's `scope`. Defaults to
     * `'flat'`: exact match (`scopedRole.scope === request.scope`), as always.
     *
     * `'hierarchical'` treats a dot-delimited scope as a path and matches a
     * grant at any ancestor -- `'org-1'` applies to `'org-1.team-2.repo-3'`,
     * GitHub/Slack-shaped. Grants at every matching level are unioned in
     * (additive, no per-level revoke). Safe to enable even for apps that
     * don't use dotted scopes -- a plain scope degrades to exact match.
     */
    readonly scopeMode?: 'flat' | 'hierarchical'
    /**
     * How grants from multiple matching ancestor levels combine under
     * `scopeMode: 'hierarchical'`. Ignored under `'flat'` (at most one level
     * ever matches there).
     *
     * `'union'` (default): every matching level's roles are OR'd in - an
     * org-level grant and a team-level grant both apply.
     *
     * `'override'`: only the most specific matching level applies - a
     * narrower grant shadows a broader one instead of adding to it.
     */
    readonly scopeCombine?: 'union' | 'override'
  }

  /**
   * Cross-instance cache-invalidation contract.
   *
   * Engines call `publish` after a local mutation (savePolicy, saveRole,
   * assignRole, etc.). Every engine subscribed to the same channel receives
   * the event and applies the matching local invalidate. Implementations
   * provide their own delivery semantics - at-least-once is sufficient
   * (the engine's invalidate methods are idempotent).
   *
   * @template TRole - Union of valid role IDs.
   */
  export interface IInvalidator<TRole extends string = string> {
    /** Publish an invalidation event. Engine calls this after a local admin write. */
    publish(event: IInvalidateEvent<TRole>): void | Promise<void>
    /** Subscribe to invalidation events. Returns a teardown function. */
    subscribe(handler: (event: IInvalidateEvent<TRole>) => void): () => void
  }

  export interface IInvalidateAll {
    readonly kind: 'all'
  }

  export interface IInvalidatePolicies {
    readonly kind: 'policies'
  }

  export interface IInvalidateRoles<TRole extends string = string> {
    readonly kind: 'roles'
    readonly roleId?: TRole
  }

  export interface IInvalidateSubject {
    readonly kind: 'subject'
    readonly subjectId: string
  }

  /**
   * Discriminated union of invalidation event kinds, keyed on `kind`.
   *
   * @template TRole - Union of valid role IDs.
   */
  export type IInvalidateEvent<TRole extends string = string> =
    | IInvalidateAll
    | IInvalidatePolicies
    | IInvalidateRoles<TRole>
    | IInvalidateSubject

  /** Output of `engine.healthCheck()`. Wire to your `/healthz` route. */
  export interface IHealth {
    /** Overall result; `false` means the orchestrator should pull this instance. */
    readonly ok: boolean
    /** IamAdapter probe outcome. */
    readonly adapter: 'ok' | 'fail'
    /** Aggregate cache hit rate across all caches. `0` when no traffic yet. */
    readonly cacheHitRate: number
    /** Latency of the adapter probe in milliseconds (rounded). */
    readonly adapterLatencyMs: number
    /** IamAdapter error message when `adapter === 'fail'`. */
    readonly lastError?: string
  }
}
