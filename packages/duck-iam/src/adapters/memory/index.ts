import type { AccessControl, IamAdapter, IamPrimitives, IamRequest } from '../../core/types'

export namespace IamMemory {
  /**
   * Describes initial seed data for {@link IamMemoryAdapter}.
   *
   * @template TAction - Constrains valid action strings.
   * @template TResource - Constrains valid resource strings.
   * @template TRole - Constrains valid role strings.
   * @template TScope - Constrains valid scope strings.
   */
  export interface IInit<
    TAction extends string = string,
    TResource extends string = string,
    TRole extends string = string,
    TScope extends string = string,
  > {
    /** Seeds the adapter with these policies on construction. */
    policies?: AccessControl.IPolicy<TAction, TResource, TRole>[]
    /** Seeds the adapter with these roles on construction. */
    roles?: AccessControl.IRole<TAction, TResource, TRole, TScope>[]
    /** Maps subject IDs to their initial unscoped roles. */
    assignments?: Record<string, TRole[]>
    /** Maps subject IDs to their initial attribute bag. */
    attributes?: Record<string, IamPrimitives.Attributes>
  }
}

/**
 * In-memory {@link IamAdapter.IAdapter} backed by `Map` storage; tests + prototypes only.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 */
export class IamMemoryAdapter<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
> implements IamAdapter.IAdapter<TAction, TResource, TRole, TScope>
{
  private _policies = new Map<string, AccessControl.IPolicy<TAction, TResource, TRole>>()
  private _roles = new Map<string, AccessControl.IRole<TAction, TResource, TRole, TScope>>()
  private _assignments = new Map<string, Array<{ role: TRole; scope?: TScope }>>()
  private _attributes = new Map<string, IamPrimitives.Attributes>()

  /**
   * Creates a new in-memory adapter, optionally seeded with initial data.
   *
   * @param init - Provides optional seed policies, roles, assignments, and attributes.
   */
  constructor(init?: IamMemory.IInit<TAction, TResource, TRole, TScope>) {
    for (const p of init?.policies ?? []) this._policies.set(p.id, p)
    for (const r of init?.roles ?? []) this._roles.set(r.id, r)
    for (const [uid, roles] of Object.entries(init?.assignments ?? {})) {
      this._assignments.set(
        uid,
        roles.map((r) => ({ role: r })),
      )
    }
    for (const [uid, attrs] of Object.entries(init?.attributes ?? {})) {
      this._attributes.set(uid, attrs)
    }
  }

  /**
   * Lists every stored policy.
   *
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns All policies currently held in memory.
   */
  async listPolicies(_opts?: IamAdapter.IReadOptions): Promise<AccessControl.IPolicy<TAction, TResource, TRole>[]> {
    return [...this._policies.values()]
  }

  /**
   * Fetches a single policy by ID.
   *
   * @param id - Identifies the policy to look up.
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns The matching policy or `null` when absent.
   */
  async getPolicy(
    id: string,
    _opts?: IamAdapter.IReadOptions,
  ): Promise<AccessControl.IPolicy<TAction, TResource, TRole> | null> {
    return this._policies.get(id) ?? null
  }

  /**
   * Stores or overwrites a policy keyed by its ID.
   *
   * @param p - Provides the policy to persist.
   * @returns Resolves once the write completes.
   */
  async savePolicy(p: AccessControl.IPolicy<TAction, TResource, TRole>): Promise<void> {
    this._policies.set(p.id, p)
  }

  /**
   * Removes a policy by ID.
   *
   * @param id - Identifies the policy to delete.
   * @returns Resolves once the entry is removed (no-op when absent).
   */
  async deletePolicy(id: string): Promise<void> {
    this._policies.delete(id)
  }

  /**
   * Lists every stored role.
   *
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns All roles currently held in memory.
   */
  async listRoles(_opts?: IamAdapter.IReadOptions): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope>[]> {
    return [...this._roles.values()]
  }

  /**
   * Fetches a single role by ID.
   *
   * @param id - Identifies the role to look up.
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns The matching role or `null` when absent.
   */
  async getRole(
    id: string,
    _opts?: IamAdapter.IReadOptions,
  ): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope> | null> {
    return this._roles.get(id) ?? null
  }

  /**
   * Stores or overwrites a role keyed by its ID.
   *
   * @param r - Provides the role to persist.
   * @returns Resolves once the write completes.
   */
  async saveRole(r: AccessControl.IRole<TAction, TResource, TRole, TScope>): Promise<void> {
    this._roles.set(r.id, r)
  }

  /**
   * Removes a role by ID.
   *
   * @param id - Identifies the role to delete.
   * @returns Resolves once the entry is removed (no-op when absent).
   */
  async deleteRole(id: string): Promise<void> {
    this._roles.delete(id)
  }

  /**
   * Lists unscoped (global) roles assigned to a subject.
   *
   * @param id - Identifies the subject whose global roles are read.
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns Deduplicated array of role IDs without any scope binding.
   */
  async getSubjectRoles(id: string, _opts?: IamAdapter.IReadOptions): Promise<TRole[]> {
    const entries = this._assignments.get(id) ?? []
    return [...new Set(entries.filter((e) => e.scope == null).map((e) => e.role))]
  }

  /**
   * Lists the scoped role assignments for a subject.
   *
   * @param id - Identifies the subject whose scoped roles are read.
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns Array of `(role, scope)` pairs for scoped assignments only.
   */
  async getSubjectScopedRoles(
    id: string,
    _opts?: IamAdapter.IReadOptions,
  ): Promise<IamRequest.IScopedRole<TRole, TScope>[]> {
    const hasScope = (e: { role: TRole; scope?: TScope }): e is { role: TRole; scope: TScope } => e.scope != null
    return (this._assignments.get(id) ?? []).filter(hasScope).map((e) => ({ role: e.role, scope: e.scope }))
  }

  /**
   * Grants a role to a subject, optionally restricted to a scope.
   *
   * Duplicate `(role, scope)` pairs are silently ignored.
   *
   * @param id - Identifies the subject receiving the role.
   * @param roleId - Specifies the role being granted.
   * @param scope - Optional scope binding the assignment.
   * @returns Resolves once the assignment is recorded.
   */
  async assignRole(id: string, roleId: TRole, scope?: TScope): Promise<void> {
    let entries = this._assignments.get(id)
    if (!entries) {
      entries = []
      this._assignments.set(id, entries)
    }
    if (!entries.some((e) => e.role === roleId && e.scope === scope)) {
      entries.push({ role: roleId, scope })
    }
  }

  /**
   * Removes a role assignment from a subject.
   *
   * @param id - Identifies the subject losing the role.
   * @param roleId - Specifies the role being revoked.
   * @param scope - Optional scope to match; omit to revoke unscoped only.
   * @returns Resolves once the assignment is removed.
   */
  async revokeRole(id: string, roleId: TRole, scope?: TScope): Promise<void> {
    const entries = this._assignments.get(id)
    if (!entries) return
    // Omitting `scope` removes EVERY assignment for the role across all
    // scopes - matches the redis/drizzle/prisma contract.
    const filtered =
      scope === undefined
        ? entries.filter((e) => e.role !== roleId)
        : entries.filter((e) => !(e.role === roleId && e.scope === scope))
    this._assignments.set(id, filtered)
  }

  /**
   * Fetches the attribute bag stored for a subject.
   *
   * @param id - Identifies the subject whose attributes are read.
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns The subject's attributes or `{}` when none are recorded.
   */
  async getSubjectAttributes(id: string, _opts?: IamAdapter.IReadOptions): Promise<IamPrimitives.Attributes> {
    return this._attributes.get(id) ?? {}
  }

  /**
   * Shallow-merges new attributes into the subject's existing bag.
   *
   * @param id - Identifies the subject whose attributes are written.
   * @param attrs - Provides the partial attribute patch to merge in.
   * @returns Resolves once the merge completes.
   */
  async setSubjectAttributes(id: string, attrs: IamPrimitives.Attributes): Promise<void> {
    if (typeof attrs !== 'object' || attrs === null || Array.isArray(attrs)) {
      const got = attrs === null ? 'null' : Array.isArray(attrs) ? 'array' : typeof attrs
      throw new Error(`[@gentleduck/iam:memory] attributes for "${id}" must be a plain object (got ${got})`)
    }
    this._attributes.set(id, { ...(this._attributes.get(id) ?? {}), ...attrs })
  }
}
