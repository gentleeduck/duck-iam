import type { Batch } from '../batch'
import type { AccessControl, IamAdapter, IamPrimitives, IamRequest } from '../types'
/**
 * The engine's public options, hooks and invalidator contract, type-only.
 * Separate from `engine.ts` so a config, hook or invalidator can be typed without importing the engine.
 */
export namespace IamEngineTypes {
  /** Re-exported from {@link IamAdapter} so `engine.admin` callers need one import. */
  export type ITripleRow<TRole extends string = string, TScope extends string = string> = IamAdapter.ITripleRow<
    TRole,
    TScope
  >
  /** Re-exported from {@link IamAdapter}. See {@link ITripleRow}. */
  export type IAssignRow<TRole extends string = string, TScope extends string = string> = IamAdapter.IAssignRow<
    TRole,
    TScope
  >
  /** Re-exported from {@link IamAdapter}. See {@link ITripleRow}. */
  export type IRevokeRow<TRole extends string = string, TScope extends string = string> = IamAdapter.IRevokeRow<
    TRole,
    TScope
  >
  /** Re-exported from {@link IamAdapter}. Per-grant extras, including `actor`. */
  export type IAssignOptions = IamAdapter.IAssignOptions
  /** Re-exported from {@link IamAdapter}. Per-revoke extras, including `actor`. */
  export type IRevokeOptions = IamAdapter.IRevokeOptions

  /**
   * Actor for admin writes with no other per-call options: policy and role writes, attribute merges and `import`.
   * It reaches only {@link IHooks.onMutation}; these writes have no provenance column.
   */
  export interface IActorOptions {
    readonly actor?: string
  }

  /** One scope move: where the assignment is now, and where it should end up. */
  export interface IMoveRow<TRole extends string = string, TScope extends string = string> {
    readonly subjectId: string
    readonly roleId: TRole
    readonly fromScope?: TScope
    readonly toScope?: TScope
    readonly actor?: string
  }

  /**
   * `engine.admin`: manages policies, roles and subject data. Every write invalidates the caches it affects.
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
    /** Invalidates the policy cache; emits `policy.saved`. */
    savePolicy(policy: AccessControl.IPolicy<TAction, TResource, TRole>, opts?: IActorOptions): Promise<void>
    /** Invalidates the policy cache; emits `policy.deleted`. */
    deletePolicy(id: string, opts?: IActorOptions): Promise<void>

    listRoles(): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope>[]>
    getRole(id: string): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope> | null>
    /** Invalidates role + subject caches keyed on `role.id`; emits `role.saved`. */
    saveRole(role: AccessControl.IRole<TAction, TResource, TRole, TScope>, opts?: IActorOptions): Promise<void>
    /** Invalidates role + subject caches keyed on `id`; emits `role.deleted`. */
    deleteRole(id: string, opts?: IActorOptions): Promise<void>

    /**
     * Grants a role; invalidates the subject and emits `role.assigned`.
     * `opts` holds temporal bounds, attributes and `actor`, which reaches a provenance column (drizzle `created_by`).
     */
    assignRole(subjectId: string, roleId: TRole, scope?: TScope, opts?: IAssignOptions): Promise<void>
    /**
     * Revokes a role; invalidates the subject and emits `role.revoked`.
     * NOTE: the row is hard-deleted, so without {@link IHooks.onMutation} a revocation leaves no record.
     */
    revokeRole(subjectId: string, roleId: TRole, scope?: TScope, opts?: IRevokeOptions): Promise<void>
    /**
     * Moves an assignment from `fromScope` to `toScope`, in place when the adapter can, else by revoke + assign.
     * A grant not held at `fromScope` is left alone.
     */
    updateAssignmentScope(
      subjectId: string,
      roleId: TRole,
      fromScope: TScope | undefined,
      toScope: TScope | undefined,
      actor?: string,
    ): Promise<void>
    /**
     * Grants many triples: one statement via {@link IamAdapter.ISubjectStore.assignRoleMany}, else one call each.
     * All rows are validated before any write. Every row is `ok`; `value.changed` says whether it was new.
     */
    assignRoles(
      rows: readonly IAssignRow<TRole, TScope>[],
    ): Promise<Batch.Result<IAssignRow<TRole, TScope>, Batch.Change>>
    /** Revokes many triples, each with an optional `opts.actor`. See {@link IamEngineTypes.IAdmin.assignRoles}. */
    revokeRoles(
      rows: readonly IRevokeRow<TRole, TScope>[],
    ): Promise<Batch.Result<IRevokeRow<TRole, TScope>, Batch.Change>>
    /**
     * Moves many assignments, one {@link IamEngineTypes.IAdmin.updateAssignmentScope} per row.
     * A row fails only by throwing; every row that returns is reported applied.
     */
    moveRoleScopes(rows: readonly IMoveRow<TRole, TScope>[]): Promise<Batch.Result<IMoveRow<TRole, TScope>>>
    /** Invalidate several subjects at once. Duplicate ids are collapsed. */
    invalidateSubjects(subjectIds: readonly string[]): void

    /** Merges into the subject's attributes; invalidates the subject and emits `attributes.set` (keys only). */
    setAttributes(subjectId: string, attrs: IamPrimitives.Attributes, opts?: IActorOptions): Promise<void>
    getAttributes(subjectId: string): Promise<IamPrimitives.Attributes>

    /**
     * Exports policies and roles for promotion, review or backup.
     * Subjects and assignments are excluded: they are per-environment user data most adapters cannot enumerate cheaply.
     */
    export(): Promise<ISnapshot<TAction, TResource, TRole, TScope>>
    /**
     * Imports a snapshot: `'merge'` (default) upserts; `'replace'` also deletes policies and roles not in it.
     * The version and every row are validated before any write.
     */
    import(
      snapshot: ISnapshot<TAction, TResource, TRole, TScope>,
      options?: IImportOptions,
      opts?: IActorOptions,
    ): Promise<IImportResult>
  }

  /**
   * A configuration snapshot. WARN: bumping `schemaVersion` is breaking; importers refuse unknown versions.
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

  /** Policy and role counts added and deleted by {@link IAdmin.import}. */
  export interface IImportResult {
    readonly policiesAdded: number
    readonly policiesDeleted: number
    readonly rolesAdded: number
    readonly rolesDeleted: number
  }

  /**
   * Primitive-only event emitted after every evaluation, so production mode gets telemetry without a decision object.
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
     * `true` when an allow rests on the `defaultEffect: 'allow'` fallback rather than a rule; always `false` on deny.
     * Chart it to catch a broken policy set that the verdict alone hides.
     */
    readonly failOpen: boolean
  }

  /**
   * Fields common to every {@link IMutationEvent}.
   * The engine emits events but stores none; retention and redaction belong to the application.
   */
  export interface IMutationBase {
    /** `Date.now()` at the moment the write completed. */
    readonly at: number
    /** Who made the change, when the caller supplied it. */
    readonly actor?: string
  }

  /** A policy was created or overwritten. */
  export interface IPolicySavedEvent extends IMutationBase {
    readonly type: 'policy.saved'
    readonly policyId: string
  }

  /** A policy was deleted. */
  export interface IPolicyDeletedEvent extends IMutationBase {
    readonly type: 'policy.deleted'
    readonly policyId: string
  }

  /** A role definition was created or overwritten. */
  export interface IRoleSavedEvent<TRole extends string = string> extends IMutationBase {
    readonly type: 'role.saved'
    readonly roleId: TRole
  }

  /** A role definition was deleted. */
  export interface IRoleDeletedEvent<TRole extends string = string> extends IMutationBase {
    readonly type: 'role.deleted'
    readonly roleId: TRole
  }

  /** A role was granted to a subject. */
  export interface IRoleAssignedEvent<TRole extends string = string, TScope extends string = string>
    extends IMutationBase {
    readonly type: 'role.assigned'
    readonly subjectId: string
    readonly roleId: TRole
    readonly scope?: TScope
    /**
     * Whether this write created the grant; `false` if already held. See {@link Batch.Change}.
     * INFO: absent when unknown, e.g. MySQL insert-ignore has no `RETURNING` and the per-row loop returns void.
     */
    readonly changed?: boolean
  }

  /**
   * A role was revoked from a subject.
   * NOTE: the row is hard-deleted, so this event is the only record of the revocation.
   */
  export interface IRoleRevokedEvent<TRole extends string = string, TScope extends string = string>
    extends IMutationBase {
    readonly type: 'role.revoked'
    readonly subjectId: string
    readonly roleId: TRole
    readonly scope?: TScope
    /** See {@link IRoleAssignedEvent.changed}. */
    readonly changed?: boolean
  }

  /** An existing assignment moved between scopes. */
  export interface IRoleScopeChangedEvent<TRole extends string = string, TScope extends string = string>
    extends IMutationBase {
    readonly type: 'role.scope-changed'
    readonly subjectId: string
    readonly roleId: TRole
    readonly fromScope?: TScope
    readonly toScope?: TScope
  }

  /**
   * A subject's attributes were merged into.
   * SECURITY: key names only, since attributes often hold personal data; read values via `admin.getAttributes`.
   */
  export interface IAttributesSetEvent extends IMutationBase {
    readonly type: 'attributes.set'
    readonly subjectId: string
    readonly keys: readonly string[]
  }

  /**
   * Every write `engine.admin` performs, keyed on `type`.
   * Closed, so a `switch` on `type` stays exhaustive; application events belong on the application's own bus.
   *
   * @template TRole  - Union of valid role IDs.
   * @template TScope - Union of valid scope strings.
   */
  export type IMutationEvent<TRole extends string = string, TScope extends string = string> =
    | IPolicySavedEvent
    | IPolicyDeletedEvent
    | IRoleSavedEvent<TRole>
    | IRoleDeletedEvent<TRole>
    | IRoleAssignedEvent<TRole, TScope>
    | IRoleRevokedEvent<TRole, TScope>
    | IRoleScopeChangedEvent<TRole, TScope>
    | IAttributesSetEvent

  /**
   * Lifecycle hooks: request enrichment, audit, errors, telemetry and mutation events.
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
    TRole extends string = string,
  > {
    /** Called before policy evaluation. May return a modified request. */
    beforeEvaluate?(
      request: IamRequest.IAccessRequest<TAction, TResource, TScope>,
    ):
      | IamRequest.IAccessRequest<TAction, TResource, TScope>
      | Promise<IamRequest.IAccessRequest<TAction, TResource, TScope>>
    /**
     * Called after every evaluation, in both modes; the decision is built only when this or `onDeny` is wired.
     * NOTE: production decisions lack `policy`/`rule` and have a generic `reason`; the compiled table erases them.
     */
    afterEvaluate?(
      request: IamRequest.IAccessRequest<TAction, TResource, TScope>,
      decision: AccessControl.IDecision,
    ): void | Promise<void>
    /** Called only when a request is denied. Fires in both modes; see {@link IamEngineTypes.IHooks.afterEvaluate}. */
    onDeny?(
      request: IamRequest.IAccessRequest<TAction, TResource, TScope>,
      decision: AccessControl.IDecision,
    ): void | Promise<void>
    /** Called when an error occurs during evaluation. The engine then returns a deny. */
    onError?(error: Error, request: IamRequest.IAccessRequest<TAction, TResource, TScope>): void | Promise<void>
    /**
     * Called with the policy id (not the object) when one policy throws; the only signal a stored row is broken.
     * SECURITY: the policy still votes: deny if it has a deny rule, else `defaultEffect`.
     * See {@link AccessControl.PolicyErrorHandler}.
     */
    onPolicyError?(error: Error, policyId: string): void
    /** Called once per evaluation with a primitive-only event, cheap in both modes. */
    onMetrics?(event: IMetricsEvent<TAction, TResource>): void
    /**
     * The audit seam: called after each successful `engine.admin` write and its invalidation. A throw is logged.
     * Under `IamEngine.withTransaction` events wait for `pending.flush()`. PERF: batches emit one event per row.
     */
    onMutation?(event: IMutationEvent<TRole, TScope>): void | Promise<void>
  }

  /**
   * Configuration for creating an `IamEngine` instance.
   *
   * @template TAction   - Union of valid action strings.
   * @template TResource - Union of valid resource strings.
   * @template TRole     - Union of valid role IDs.
   * @template TScope    - Union of valid scope strings.
   * @template TMode     - Engine mode (`'development'` or `'production'`).
   * @example
   * ```ts
   * const config: IamEngineTypes.IConfig = {
   *   adapter: new IamMemoryAdapter(),
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
    TMode extends AccessControl.Mode = 'production',
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
    readonly hooks?: IHooks<TAction, TResource, TScope, TRole>
    /**
     * `'production'` (default) returns booleans; `'development'` returns `IDecision` and enables `explain()`.
     * WARN: a `TMode` type argument does not set this; without `mode` the engine runs production while typed otherwise.
     */
    readonly mode?: TMode
    /** How decisions combine across policies. Defaults to `'and'`. See {@link AccessControl.PolicyCombine}. */
    readonly policyCombine?: AccessControl.PolicyCombine
    /**
     * Cap on policies loaded from the adapter. Defaults to `10_000`.
     * An over-cap load throws on cache fill; lower it to fail loudly on a runaway adapter.
     */
    readonly maxPolicies?: number
    /** Hard ceiling on roles loaded from the adapter. Defaults to `10_000`. */
    readonly maxRoles?: number
    /**
     * Must be `true` to use `defaultEffect: 'allow'`, in either mode; the constructor refuses it otherwise.
     * SECURITY: fail-open lets a buggy condition or an adapter blip turn a deny into an allow.
     */
    readonly allowFailOpen?: boolean
    /**
     * Per-adapter-call timeout in ms, enforced by aborting `IReadOptions.signal`. Defaults to `5_000`; `0` disables.
     * An adapter that ignores the signal still frees the caller, but its call runs on in the background.
     * Covers `engine.admin` as well as the decision path. A write takes no signal, so there the timeout only frees
     * the caller; retries must stay idempotent. Inside a transaction the admin is unbounded on purpose.
     */
    readonly adapterTimeoutMs?: number
    /**
     * Ms to wait for a promise a hook returns. Defaults to `5_000`; `0` waits indefinitely.
     * On expiry `beforeEvaluate` fails the evaluation (`onError`, then deny); other hooks are logged and left running.
     */
    readonly hookTimeoutMs?: number
    /**
     * Cap on concurrent uncached subject loads. Defaults to `512`; `0` is unbounded. Cache hits and joins do not count.
     * Past the cap a new load throws `subject load shed`, which checks turn into a deny.
     */
    readonly maxConcurrentSubjectLoads?: number
    /**
     * Cross-instance invalidation (e.g. `createIamRedisInvalidator`): every subscribed engine drops caches on a write.
     * Read at construction; attach a later-built client with `engine.setInvalidator(...)`.
     */
    readonly invalidator?: IInvalidator<TRole>
    /**
     * `'flat'` (default) matches scopes exactly; `'hierarchical'` also lets `'org-1'` cover `'org-1.team-2'`.
     * Applies to assignment scopes and to scopes a role or permission declares. See `scopeCombine`.
     */
    readonly scopeMode?: 'flat' | 'hierarchical'
    /**
     * Under `'hierarchical'`, how matching levels combine: `'union'` (default) adds them all;
     * `'override'` keeps only the most specific. Ignored under `'flat'`.
     */
    readonly scopeCombine?: 'union' | 'override'
  }

  /**
   * Cross-instance invalidation: engines `publish` after a write and apply what they receive via `subscribe`.
   * At-least-once delivery is enough, since invalidation is idempotent.
   *
   * @template TRole - Union of valid role IDs.
   */
  export interface IInvalidator<TRole extends string = string> {
    /** Publish an invalidation event. Engine calls this after a local admin write. */
    publish(event: IInvalidateEvent<TRole>): void | Promise<void>
    /** Subscribe to invalidation events. Returns a teardown function. */
    subscribe(handler: (event: IInvalidateEvent<TRole>) => void): () => void
    /**
     * Whether events are arriving, for {@link IHealth.invalidator}; `false` until the first subscribe resolves.
     * NOTE: omit it rather than hard-code `true` when "attached" and "receiving" cannot be told apart.
     */
    status?(): { readonly subscribed: boolean }
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
    /**
     * Present when too many roles for the 32-bit grant mask forced the interpreter fallback.
     * `ok` stays `true`: answers are still correct, only throughput is lost.
     */
    readonly compiledTable?: {
      readonly available: false
      readonly reason: 'role-limit-exceeded'
      readonly roleCount: number
      readonly limit: number
    }
    /**
     * Present when the invalidator is not receiving, so peer revocations stay cached for up to `cacheTTL`.
     * NOTE: `ok` stays `true`, since failing every replica at once would be an outage. Misses a dropped subscription.
     */
    readonly invalidator?: {
      readonly subscribed: false
    }
  }
}
