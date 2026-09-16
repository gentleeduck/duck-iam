import type { AccessControl, IamPrimitives, IamRequest } from '.'
/**
 * The storage contract every adapter implements, plus the types its methods exchange. Type-only.
 * Optional members are capabilities: the engine falls back when an adapter omits one.
 */
export namespace IamAdapter {
  /**
   * Read-time cancellation; the engine aborts it on `adapterTimeoutMs`.
   * INFO: only `IamHttpAdapter` honours it. The engine's timeout race releases the caller either way.
   */
  export interface IReadOptions {
    readonly signal?: AbortSignal
  }

  /**
   * `onPolicyError` shape for adapter configs: called with the adapter tag and the id of a row it could not read.
   * See {@link AccessControl.PolicyErrorHandler} for all three shapes.
   */
  export type RowErrorHandler<TAdapter extends string> = (err: Error, ctx: { adapter: TAdapter; rowId: string }) => void

  /** One `(subject, role, scope)` triple: the unit every batch role write takes. */
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
     * Who is making this grant: fills `created_by` where the schema has it, and rides on the `role.assigned` event.
     * NOTE: unlike the other fields, an adapter that cannot store it does not throw (see `ASSIGN_OPTION_FIELDS`).
     */
    readonly actor?: string
  }

  /**
   * Names who is performing a write; fills `created_by` / `updated_by` where the schema has them.
   * Adapters without those columns ignore it, since the mutation event carries the actor anyway.
   */
  export interface IActorOptions {
    readonly actor?: string
  }

  /** Extras for {@link ISubjectStore.revokeRole}; the row is deleted, so `actor` mainly feeds `role.revoked`. */
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
     * Engine invalidates its policy cache after this call.
     * `opts.actor` fills `created_by` on first write and `updated_by` after, where the schema has them.
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
     * Removes the role and every grant that named it. Engine invalidates its role cache after this call.
     * SECURITY: the cascade is contract; a leftover grant comes back to life if a role is recreated under the same id.
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
     * Returns the subject's GLOBAL (unscoped) role IDs.
     * SECURITY: never collapse scoped assignments into this list; surface them via {@link getSubjectScopedRoles}.
     */
    getSubjectRoles(subjectId: string, opts?: IReadOptions): Promise<TRole[]>
    /** Scoped role assignments. Optional - only when multi-tenant scoped roles are in use. */
    getSubjectScopedRoles?(subjectId: string, opts?: IReadOptions): Promise<IamRequest.IScopedRole<TRole, TScope>[]>
    /**
     * Assigns a role to a subject, optionally within a scope.
     * SECURITY: throws if `opts` cannot be stored (a bounded grant must not become permanent) or the role is unknown.
     */
    assignRole(subjectId: string, roleId: TRole, scope?: TScope, opts?: IAssignOptions): Promise<void>
    /** Revokes a role, optionally within a scope. `opts.actor` is advisory; see {@link IRevokeOptions}. */
    revokeRole(subjectId: string, roleId: TRole, scope?: TScope, opts?: IRevokeOptions): Promise<void>
    /**
     * Moves a `(subjectId, roleId, fromScope)` assignment to `toScope` in one write. Returns `false` when none matches,
     * and the engine falls back to {@link assignRole}. Adapters with no in-place update omit it (revoke + assign).
     */
    updateAssignmentScope?(
      subjectId: string,
      roleId: TRole,
      fromScope: TScope | undefined,
      toScope: TScope | undefined,
      actor?: string,
    ): Promise<boolean>
    /**
     * Set-based assign in one statement; the admin loops {@link assignRole} when absent.
     * Returns indices into `rows` of the rows actually written, or `null` when the driver cannot say.
     * NOTE: take indices from `RETURNING`, never an extra read; credit each write once, as `creditWrites` does.
     */
    assignRoleMany?(rows: readonly IAssignRow<TRole, TScope>[]): Promise<readonly number[] | null>
    /** Set-based revoke. See {@link assignRoleMany}. */
    revokeRoleMany?(rows: readonly IRevokeRow<TRole, TScope>[]): Promise<readonly number[] | null>
    /**
     * Epoch ms of the earliest future `startsAt` / `expiresAt` among the subject's grants, or `null` when none.
     * SECURITY: the engine caps the subject's cache entry there, so a grant stops granting when it expires.
     */
    getSubjectGrantBoundary?(subjectId: string, opts?: IReadOptions): Promise<number | null>
    /** Returns the attribute bag for a subject. */
    getSubjectAttributes(subjectId: string, opts?: IReadOptions): Promise<IamPrimitives.Attributes>
    /**
     * Shallow-merges `attrs` into the subject's bag: `null` clears a key, keys absent from `attrs` must be kept.
     * `opts.actor` fills the provenance columns where the schema has them.
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
     * Re-binds this adapter to a driver client, typically a transaction handle; the client is opaque to duck-iam.
     * When omitted, `IamEngine.withTransaction` throws rather than leave writes outside the caller's transaction.
     */
    withClient?(client: unknown): IAdapter<TAction, TResource, TRole, TScope>
  }
}
