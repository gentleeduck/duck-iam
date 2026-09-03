import type { AccessControl, IamPrimitives, IamRequest } from '.'
export namespace IamAdapter {
  /**
   * Optional read-time cancellation token. The engine creates a controller per
   * adapter call and triggers `abort()` on its `adapterTimeoutMs`.
   *
   * Of the six shipped adapters, **only `IamHttpAdapter` honors it** - it
   * merges this signal with its own timeout and hands the result to
   * `fetch(url, { signal })`. The other five accept the parameter and ignore
   * it; this doc used to name Redis as an implementer, which it is not.
   *
   * Ignoring it is not a leak: `Engine._withTimeout` races every adapter call
   * against `adapterTimeoutMs` and rejects, so the request thread is released
   * either way. What an ignoring adapter loses is the *upstream* cancellation -
   * the query keeps running and its result is discarded. A third-party adapter
   * that can cancel should plumb this through.
   */
  export interface IReadOptions {
    readonly signal?: AbortSignal
  }

  /**
   * Handler for a stored row an adapter could not deserialise, as **adapter
   * configs** call it: the second argument is a context object naming the
   * adapter and the row, because the row never became a policy.
   *
   * The third of the three `onPolicyError` shapes - see
   * {@link AccessControl.PolicyErrorHandler} for the table. `TAdapter` is the
   * adapter's own literal tag, so a handler narrowed to one adapter cannot be
   * wired into another by accident.
   */
  export type RowErrorHandler<TAdapter extends string> = (err: Error, ctx: { adapter: TAdapter; rowId: string }) => void

  /**
   * One `(subject, role, scope)` triple - the unit every batch role write takes.
   * Defined here, next to the store methods that consume it, so the store
   * interface and the admin interface cannot drift apart.
   */
  export interface ITripleRow<TRole extends string = string, TScope extends string = string> {
    readonly subjectId: string
    readonly roleId: TRole
    readonly scope?: TScope
  }

  /** A triple plus the per-grant extras {@link ISubjectStore.assignRole} accepts. */
  export interface IAssignRow<TRole extends string = string, TScope extends string = string>
    extends ITripleRow<TRole, TScope> {
    readonly opts?: IAssignOptions
  }

  /** A triple plus the per-revoke extras {@link ISubjectStore.revokeRole} accepts. */
  export interface IRevokeRow<TRole extends string = string, TScope extends string = string>
    extends ITripleRow<TRole, TScope> {
    readonly opts?: IRevokeOptions
  }

  /**
   * Optional extras for {@link ISubjectStore.assignRole}: temporal bounds,
   * per-grant attributes, and who is making the grant.
   */
  export interface IAssignOptions {
    readonly startsAt?: Date
    readonly expiresAt?: Date
    readonly attributes?: IamPrimitives.Attributes
    /**
     * Who is making this grant.
     *
     * Written to the assignment's provenance column where the schema has one -
     * `created_by` in the drizzle pg and mysql schemas, which declared the
     * column before there was any way to fill it - and carried on the
     * `role.assigned` mutation event regardless of whether any column exists.
     *
     * Unlike the other three fields, an adapter that cannot store this does
     * **not** throw: see the note on `ASSIGN_OPTION_FIELDS` in
     * `shared/assign-options.ts` for why the two cases differ.
     */
    readonly actor?: string
  }

  /**
   * Names who is performing a write.
   *
   * Every table in the drizzle schemas has carried `created_by` / `updated_by`
   * since it was written, and until this existed nothing could fill them: the
   * schema promised an audit trail the API could not produce. Adapters whose
   * storage has no such column ignore it - the mutation event carries the actor
   * regardless, which is why this is not covered by the `iamAssertNoAssignOptions`
   * allow-list the way `expiresAt` is. Dropping `expiresAt` changes what the
   * store answers; dropping `actor` does not.
   */
  export interface IActorOptions {
    readonly actor?: string
  }

  /**
   * Optional extras for {@link ISubjectStore.revokeRole}.
   *
   * A revoke hard-deletes the row, so there is nothing left to carry
   * provenance; `actor` exists so the `role.revoked` mutation event can name
   * who did it, and so an adapter that keeps its own tombstones has the value
   * available. Adapters are free to ignore it.
   */
  export interface IRevokeOptions extends IActorOptions {}

  /**
   * Storage interface for ABAC policies.
   *
   * @template TAction   - Union of valid action strings.
   * @template TResource - Union of valid resource strings.
   * @template TRole     - Union of valid role IDs (target roles).
   */
  export interface IPolicyStore<
    TAction extends string = string,
    TResource extends string = string,
    TRole extends string = string,
  > {
    /** Returns all stored policies. Called by the engine on cache miss. */
    listPolicies(opts?: IReadOptions): Promise<AccessControl.IPolicy<TAction, TResource, TRole>[]>
    /** Returns a single policy by ID, or `null` if not found. */
    getPolicy(id: string, opts?: IReadOptions): Promise<AccessControl.IPolicy<TAction, TResource, TRole> | null>
    /**
     * Engine invalidates its policy cache after this call. `opts.actor` fills
     * the row's `created_by` on first write and `updated_by` on every later
     * one, where the schema has those columns.
     */
    savePolicy(policy: AccessControl.IPolicy<TAction, TResource, TRole>, opts?: IActorOptions): Promise<void>
    /** Engine invalidates its policy cache after this call. */
    deletePolicy(id: string): Promise<void>
  }

  /**
   * Storage interface for RBAC roles.
   *
   * @template TAction   - Union of valid action strings.
   * @template TResource - Union of valid resource strings.
   * @template TRole     - Union of valid role IDs.
   * @template TScope    - Union of valid scope strings.
   */
  export interface IRoleStore<
    TAction extends string = string,
    TResource extends string = string,
    TRole extends string = string,
    TScope extends string = string,
  > {
    /** Returns all stored roles. Called by the engine on cache miss. */
    listRoles(opts?: IReadOptions): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope>[]>
    /** Returns a single role by ID, or `null` if not found. */
    getRole(id: string, opts?: IReadOptions): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope> | null>
    /** Engine invalidates its role cache after this call. */
    saveRole(role: AccessControl.IRole<TAction, TResource, TRole, TScope>, opts?: IActorOptions): Promise<void>
    /**
     * Removes the role and every grant that named it. Engine invalidates its
     * role cache after this call.
     *
     * The cascade is part of the contract, not an implementation detail: the
     * SQL schemas get it from `fk_iam_assignments_role ON DELETE CASCADE`,
     * memory/file/redis sweep their assignments, and an HTTP server is expected
     * to do the same. A grant left pointing at a deleted role still reads as a
     * grant, and a role recreated under the reused id hands it back to everyone
     * who once held it without an operator granting anything.
     */
    deleteRole(id: string): Promise<void>
  }

  /**
   * Storage interface for subject (user) data: role assignments and attributes.
   *
   * @template TRole  - Union of valid role IDs.
   * @template TScope - Union of valid scope strings.
   */
  export interface ISubjectStore<TRole extends string = string, TScope extends string = string> {
    /**
     * Returns the flat list of GLOBAL (unscoped) role IDs assigned to a
     * subject. Scoped role assignments must NOT be collapsed into this list
     * - surface those through {@link getSubjectScopedRoles}. The file,
     * memory, redis, drizzle, and prisma adapters all honour this contract;
     * the HTTP adapter delegates to the operator's server, which must also.
     */
    getSubjectRoles(subjectId: string, opts?: IReadOptions): Promise<TRole[]>
    /** Scoped role assignments. Optional - only when multi-tenant scoped roles are in use. */
    getSubjectScopedRoles?(subjectId: string, opts?: IReadOptions): Promise<IamRequest.IScopedRole<TRole, TScope>[]>
    /**
     * Assigns a role to a subject, optionally within a scope. An adapter that
     * cannot store `opts` **throws** rather than dropping it - a time-boxed grant
     * that silently became permanent is the failure this contract exists to
     * prevent. Only the drizzle schemas carry the columns today.
     *
     * The role must already exist: granting an id no role is stored under
     * **throws**. Drizzle and prisma get this from the assignments-to-roles
     * foreign key, the memory, file and redis adapters check before writing,
     * and the HTTP adapter delegates to the operator's server, which must also.
     * Accepting the write instead recorded a grant that `resolveSubject` then
     * dropped, so a typo'd role id read back as success and granted nothing.
     */
    assignRole(subjectId: string, roleId: TRole, scope?: TScope, opts?: IAssignOptions): Promise<void>
    /**
     * Revokes a role from a subject, optionally within a scope. `opts.actor`
     * is advisory - the row is deleted, so most adapters have nowhere to put
     * it; the `role.revoked` mutation event carries it either way.
     */
    revokeRole(subjectId: string, roleId: TRole, scope?: TScope, opts?: IRevokeOptions): Promise<void>
    /**
     * Moves an existing `(subjectId, roleId, fromScope)` assignment to `toScope` in
     * place - one write instead of revoke + assign. Returns `false` when no matching
     * assignment exists, so the engine can fall back to a plain {@link assignRole}.
     *
     * Optional: adapters whose storage has no meaningful "in place" update (e.g. scope
     * is encoded into a set member, as in the Redis adapter) omit this; the engine
     * falls back to revoke + assign automatically.
     */
    updateAssignmentScope?(
      subjectId: string,
      roleId: TRole,
      fromScope: TScope | undefined,
      toScope: TScope | undefined,
      actor?: string,
    ): Promise<boolean>
    /**
     * Set-based assign - one statement for the whole list. Optional; the admin
     * loops over {@link assignRole} when it is absent, so an adapter that omits
     * it is still complete.
     *
     * Returns the indices into `rows` of the rows the statement actually wrote
     * - the grants that were not already there - or `null` when the driver
     * cannot say. Both answers are honest and neither costs an extra round
     * trip: report the indices only where a `RETURNING` clause on the write
     * itself supplies them, and `null` everywhere else rather than paying for
     * a read to find out.
     *
     * Indices rather than a subset of `rows`, so that two rows asking for the
     * same write stay distinguishable, and so an implementation is not silently
     * required to return the very objects it was handed. Credit each write to
     * the first row that accounts for it - `creditWrites` in `core/batch`
     * implements the rule - so a write that happened once is never reported
     * twice.
     */
    assignRoleMany?(rows: readonly IAssignRow<TRole, TScope>[]): Promise<readonly number[] | null>
    /** Set-based revoke. See {@link assignRoleMany}. */
    revokeRoleMany?(rows: readonly IRevokeRow<TRole, TScope>[]): Promise<readonly number[] | null>
    /**
     * The next instant at which this subject's answers stop being true, when
     * the store knows one.
     *
     * An adapter that stores time-boxed grants answers `getSubjectRoles` as of
     * `Date.now()`, and the engine caches that answer for its whole `cacheTTL`.
     * The two disagree the moment a window opens or closes: a grant issued to
     * expire in 30 seconds kept granting for up to 90, and a grant scheduled to
     * start stayed denied for up to a minute after it opened. The adapter is
     * the only party that can see the bound, so it reports it and the engine
     * caps the cache entry there.
     *
     * Return the earliest **future** `startsAt` or `expiresAt` among the
     * subject's grants, or `null` when none of them has a bound - which is why
     * the five adapters with no temporal columns do not implement this at all,
     * rather than implementing it to return `null`: absent and "nothing to
     * report" are the same answer, and only drizzle has anything to say.
     *
     * @param subjectId - Identifies the subject whose grants are inspected.
     * @param opts - Read options, as for the other reads.
     * @returns Epoch ms of the next boundary, or `null` when there is none.
     */
    getSubjectGrantBoundary?(subjectId: string, opts?: IReadOptions): Promise<number | null>
    /** Returns the attribute bag for a subject. */
    getSubjectAttributes(subjectId: string, opts?: IReadOptions): Promise<IamPrimitives.Attributes>
    /**
     * Merges `attrs` into the subject's existing attribute bag (shallow per-key
     * overwrite). Set a key to `null` to clear it. Implementations must not drop
     * keys absent from `attrs`. `opts.actor` fills the row's provenance columns
     * where the schema has them.
     */
    setSubjectAttributes(subjectId: string, attrs: IamPrimitives.Attributes, opts?: IActorOptions): Promise<void>
  }

  /**
   * Combined storage interface: policies + roles + subjects.
   * Expected by the {@link IamEngine} constructor via `IamEngineTypes.IConfig.adapter`.
   *
   * @template TAction   - Union of valid action strings.
   * @template TResource - Union of valid resource strings.
   * @template TRole     - Union of valid role IDs.
   * @template TScope    - Union of valid scope strings.
   */
  export interface IAdapter<
    TAction extends string = string,
    TResource extends string = string,
    TRole extends string = string,
    TScope extends string = string,
  > extends IPolicyStore<TAction, TResource, TRole>,
      IRoleStore<TAction, TResource, TRole, TScope>,
      ISubjectStore<TRole, TScope> {
    /**
     * Re-binds this adapter to a caller-supplied driver client - typically a
     * transaction handle. The client is opaque to duck-iam and handed straight
     * back to the adapter, which is the only layer that knows the driver type.
     *
     * Omitting it means this adapter cannot join a transaction, and
     * `IamEngine.withTransaction` throws rather than silently leaving writes
     * outside the caller's transaction. The memory, file, redis and http
     * adapters all omit it - none has a transaction to join.
     */
    withClient?(client: unknown): IAdapter<TAction, TResource, TRole, TScope>
  }
}
