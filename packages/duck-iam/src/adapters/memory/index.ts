import type { AccessControl, IamAdapter, IamPrimitives, IamRequest } from '../../core/types'
import { iamAssertNoAssignOptions } from '../../shared/assign-options'
import { iamAssertRoleExists } from '../../shared/assignment-target'
import { iamAssertAttributesParam } from '../../shared/attributes'
import { iamAssertSavablePolicy, iamAssertSavableRole, iamNormalizePolicy } from '../../shared/rows'
import { iamAssertAssignableScope } from '../../shared/scope'

/**
 * Types for the in-memory adapter. Type-only namespace - zero bundle cost.
 */
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
    // Seeded rows go through the same normaliser as `savePolicy`. Without
    // this, one adapter answered `getPolicy` two ways for the same policy
    // depending on whether it arrived via the constructor or a write - which
    // is how `export()` on a seeded store produced a snapshot that `import()`
    // then stored in a different shape.
    for (const p of init?.policies ?? []) this._policies.set(p.id, iamNormalizePolicy(p))
    for (const r of init?.roles ?? []) this._roles.set(r.id, r)
    // Seeded assignments go through the same refusal `assignRole` applies, for
    // the same reason the policies above go through `iamNormalizePolicy`: a
    // seed and a write must not disagree about what the store can hold. They
    // did. `assignRole` refuses a role that is not stored on all six adapters,
    // and the seed loop accepted one - `getSubjectRoles` then returned the id,
    // `resolveEffectiveRoles` kept it (it is a directly assigned role, not the
    // dangling `inherits` id that case already closes), and a hand-written ABAC
    // rule testing `subject.roles contains 'ghost'` fired on it. Measured: a
    // seed of `{ u1: ['ghost'] }` with no roles at all produced an ALLOW.
    //
    // This adapter is documented "tests + prototypes only", so this is not a
    // production grant path - which is the point. A fixture that can reach a
    // state `assignRole` forbids lets a suite certify behaviour the product
    // cannot actually produce.
    //
    // Roles are seeded above, so an init naming its own roles is unaffected.
    for (const [uid, roles] of Object.entries(init?.assignments ?? {})) {
      for (const r of roles) iamAssertRoleExists('memory', this._roles.has(r))
      this._assignments.set(
        uid,
        roles.map((r) => ({ role: r })),
      )
    }
    // Copied, not stored by reference: see `getSubjectAttributes`, which has
    // the other half of this. `setSubjectAttributes` already builds a fresh
    // object on every write, so this makes the seed agree with the write.
    for (const [uid, attrs] of Object.entries(init?.attributes ?? {})) {
      this._attributes.set(uid, { ...attrs })
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
    iamAssertSavablePolicy('memory', p)
    this._policies.set(p.id, iamNormalizePolicy(p))
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
    iamAssertSavableRole('memory', r)
    this._roles.set(r.id, r)
  }

  /**
   * Removes a role by ID, and with it every grant that named it.
   *
   * The grants go too because the SQL schemas take them: `fk_iam_assignments_role`
   * is `ON DELETE CASCADE`, so `deleteRole('editor')` left `getSubjectRoles`
   * returning `editor` here and `[]` on drizzle and prisma - one call, two
   * answers. Keeping the orphan is not the harmless option either: it reads as
   * a grant, `assignRole` now refuses to create one like it, and recreating a
   * role under the reused id hands it back to everyone who once held it,
   * without an operator granting anything.
   *
   * @param id - Identifies the role to delete.
   * @returns Resolves once the role and its grants are removed (no-op when absent).
   */
  async deleteRole(id: string): Promise<void> {
    this._roles.delete(id)
    for (const [subjectId, entries] of this._assignments) {
      const kept = entries.filter((e) => e.role !== id)
      if (kept.length === entries.length) continue
      if (kept.length === 0) this._assignments.delete(subjectId)
      else this._assignments.set(subjectId, kept)
    }
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
   * Duplicate `(role, scope)` pairs are silently ignored. A role that is not
   * stored is refused - see {@link iamAssertRoleExists}.
   *
   * @param id - Identifies the subject receiving the role.
   * @param roleId - Specifies the role being granted.
   * @param scope - Optional scope binding the assignment.
   * @returns Resolves once the assignment is recorded.
   */
  async assignRole(id: string, roleId: TRole, scope?: TScope, opts?: IamAdapter.IAssignOptions): Promise<void> {
    iamAssertAssignableScope('memory', scope)
    iamAssertNoAssignOptions('memory', opts)
    iamAssertRoleExists('memory', this._roles.has(roleId))
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
   * @param scope - Optional scope to match. Omitting it removes EVERY
   *                assignment for the role, scoped ones included - not just the
   *                unscoped grant. This doc used to say the opposite, on a
   *                destructive operation.
   * @returns Resolves once the assignment is removed.
   */
  async revokeRole(id: string, roleId: TRole, scope?: TScope): Promise<void> {
    iamAssertAssignableScope('memory', scope, 'lookup')
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
   * Moves an existing assignment to a different scope in place.
   *
   * @param id - Identifies the subject whose assignment is moving.
   * @param roleId - Specifies the role of the assignment being moved.
   * @param fromScope - The assignment's current scope.
   * @param toScope - The scope to move it to.
   * @returns `false` when no `(roleId, fromScope)` assignment exists for this subject.
   */
  async updateAssignmentScope(id: string, roleId: TRole, fromScope?: TScope, toScope?: TScope): Promise<boolean> {
    const entries = this._assignments.get(id)
    const entry = entries?.find((e) => e.role === roleId && e.scope === fromScope)
    if (!entry) return false
    // The target scope may already be granted; drop the source rather than duplicate it.
    if (entries?.some((e) => e !== entry && e.role === roleId && e.scope === toScope)) {
      this._assignments.set(
        id,
        (entries ?? []).filter((e) => e !== entry),
      )
      return true
    }
    entry.scope = toScope
    return true
  }

  /**
   * Fetches the attribute bag stored for a subject.
   *
   * @param id - Identifies the subject whose attributes are read.
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns The subject's attributes or `{}` when none are recorded.
   */
  async getSubjectAttributes(id: string, _opts?: IamAdapter.IReadOptions): Promise<IamPrimitives.Attributes> {
    // A copy. This used to hand back the live internal bag, so a caller who
    // read the attributes and then edited what they were given rewrote the
    // store - no `setSubjectAttributes`, no validation, and nothing to
    // invalidate a cache from. The other five adapters cannot do this: each
    // deserializes and rebuilds through `iamNarrowAttributes`, and prisma's
    // call site says so out loud ("builds a fresh Record, so this also avoids
    // sharing"). Memory alone aliased, because it has nothing to deserialize.
    const attrs = this._attributes.get(id)
    return attrs === undefined ? {} : { ...attrs }
  }

  /**
   * Shallow-merges new attributes into the subject's existing bag.
   *
   * @param id - Identifies the subject whose attributes are written.
   * @param attrs - Provides the partial attribute patch to merge in.
   * @returns Resolves once the merge completes.
   */
  async setSubjectAttributes(id: string, attrs: IamPrimitives.Attributes): Promise<void> {
    iamAssertAttributesParam('memory', id, attrs)
    this._attributes.set(id, { ...(this._attributes.get(id) ?? {}), ...attrs })
  }
}

/** Factory around {@link IamMemoryAdapter}, for callers who prefer functions to `new`. */
export function iamMemoryAdapter(...args: ConstructorParameters<typeof IamMemoryAdapter>): IamMemoryAdapter {
  return new IamMemoryAdapter(...args)
}
