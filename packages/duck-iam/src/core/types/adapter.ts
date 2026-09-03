import type { AccessControl, IamPrimitives, IamRequest } from '.'
export namespace IamAdapter {
  /**
   * Optional read-time cancellation token. The engine creates a controller per
   * adapter call and triggers `abort()` on its timeout. Adapters that can honor
   * cancellation (HttpAdapter via `fetch(url, {signal})`, Redis via `RESET`,
   * etc.) should plumb this through; adapters that can't (in-memory, file)
   * may ignore it - the engine still releases the request thread on timeout.
   */
  export interface IReadOptions {
    readonly signal?: AbortSignal
  }

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

  /** Optional extras for {@link ISubjectStore.assignRole}: temporal bounds and per-grant attributes. */
  export interface IAssignOptions {
    readonly startsAt?: Date
    readonly expiresAt?: Date
    readonly attributes?: IamPrimitives.Attributes
  }

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
    /** Engine invalidates its policy cache after this call. */
    savePolicy(policy: AccessControl.IPolicy<TAction, TResource, TRole>): Promise<void>
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
    saveRole(role: AccessControl.IRole<TAction, TResource, TRole, TScope>): Promise<void>
    /** Engine invalidates its role cache after this call. */
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
    /** Assigns a role to a subject, optionally within a scope. `opts` is honoured by adapters that support it. */
    assignRole(subjectId: string, roleId: TRole, scope?: TScope, opts?: IAssignOptions): Promise<void>
    /** Revokes a role from a subject, optionally within a scope. */
    revokeRole(subjectId: string, roleId: TRole, scope?: TScope): Promise<void>
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
     * it is still complete. Returns the triples it actually wrote, so the admin
     * can report honest per-row outcomes rather than assuming every row landed.
     */
    assignRoleMany?(rows: readonly IAssignRow<TRole, TScope>[]): Promise<readonly ITripleRow<TRole, TScope>[]>
    /** Set-based revoke. See {@link assignRoleMany}. */
    revokeRoleMany?(rows: readonly ITripleRow<TRole, TScope>[]): Promise<readonly ITripleRow<TRole, TScope>[]>
    /** Returns the attribute bag for a subject. */
    getSubjectAttributes(subjectId: string, opts?: IReadOptions): Promise<IamPrimitives.Attributes>
    /**
     * Merges `attrs` into the subject's existing attribute bag (shallow per-key
     * overwrite). Set a key to `null` to clear it. Implementations must not drop
     * keys absent from `attrs`.
     */
    setSubjectAttributes(subjectId: string, attrs: IamPrimitives.Attributes): Promise<void>
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
