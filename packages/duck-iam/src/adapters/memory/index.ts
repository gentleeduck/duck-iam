import type { AccessControl, IamAdapter, IamPrimitives, IamRequest } from '../../core/types'
import { iamAssertNoAssignOptions } from '../../shared/assign-options'
import { iamAssertRoleExists } from '../../shared/assignment-target'
import { iamAssertAttributesParam, iamCopyAttributes } from '../../shared/attributes'
import { iamAssertSavablePolicy, iamAssertSavableRole, iamCloneRow, iamNormalizePolicy } from '../../shared/rows'
import { iamAssertAssignableScope } from '../../shared/scope'

/** Types for the in-memory adapter. Type-only namespace - zero bundle cost. */
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

  /** Creates a new in-memory adapter, optionally seeded with initial data. */
  constructor(init?: IamMemory.IInit<TAction, TResource, TRole, TScope>) {
    // NOTE: seeds use the same normaliser as `savePolicy`, so a seeded and a saved policy read back identically.
    for (const p of init?.policies ?? []) this._policies.set(p.id, iamNormalizePolicy(p))
    for (const r of init?.roles ?? []) this._roles.set(r.id, iamCloneRow(r))
    // NOTE: seeds get the same unknown-role refusal as `assignRole`, so a fixture cannot reach a state the
    // product forbids. Roles are seeded first, so an init naming its own roles passes.
    for (const [uid, roles] of Object.entries(init?.assignments ?? {})) {
      for (const r of roles) iamAssertRoleExists('memory', this._roles.has(r))
      this._assignments.set(
        uid,
        roles.map((r) => ({ role: r })),
      )
    }
    // NOTE: copied one level deep (a spread would alias nested arrays), matching the read and write paths.
    for (const [uid, attrs] of Object.entries(init?.attributes ?? {})) {
      this._attributes.set(uid, iamCopyAttributes(attrs))
    }
  }

  /** Lists every stored policy. */
  async listPolicies(_opts?: IamAdapter.IReadOptions): Promise<AccessControl.IPolicy<TAction, TResource, TRole>[]> {
    return [...this._policies.values()].map(iamCloneRow)
  }

  /** Fetches a policy by ID, or `null` when absent. */
  async getPolicy(
    id: string,
    _opts?: IamAdapter.IReadOptions,
  ): Promise<AccessControl.IPolicy<TAction, TResource, TRole> | null> {
    const p = this._policies.get(id)
    return p === undefined ? null : iamCloneRow(p)
  }

  /** Stores or overwrites a policy keyed by its ID. */
  async savePolicy(p: AccessControl.IPolicy<TAction, TResource, TRole>): Promise<void> {
    iamAssertSavablePolicy('memory', p)
    this._policies.set(p.id, iamNormalizePolicy(p))
  }

  /** Removes a policy by ID; no-op when absent. */
  async deletePolicy(id: string): Promise<void> {
    this._policies.delete(id)
  }

  /** Lists every stored role. */
  async listRoles(_opts?: IamAdapter.IReadOptions): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope>[]> {
    return [...this._roles.values()].map(iamCloneRow)
  }

  /** Fetches a role by ID, or `null` when absent. */
  async getRole(
    id: string,
    _opts?: IamAdapter.IReadOptions,
  ): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope> | null> {
    const r = this._roles.get(id)
    return r === undefined ? null : iamCloneRow(r)
  }

  /** Stores or overwrites a role keyed by its ID. */
  async saveRole(r: AccessControl.IRole<TAction, TResource, TRole, TScope>): Promise<void> {
    iamAssertSavableRole('memory', r)
    this._roles.set(r.id, iamCloneRow(r))
  }

  /**
   * Removes a role by ID and every grant that named it; no-op when absent.
   * NOTE: mirrors the SQL `ON DELETE CASCADE`; a kept orphan would re-grant a role later recreated under that id.
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

  /** Lists a subject's unscoped (global) role IDs, deduplicated. */
  async getSubjectRoles(id: string, _opts?: IamAdapter.IReadOptions): Promise<TRole[]> {
    const entries = this._assignments.get(id) ?? []
    return [...new Set(entries.filter((e) => e.scope == null).map((e) => e.role))]
  }

  /** Lists a subject's scoped `(role, scope)` assignments only. */
  async getSubjectScopedRoles(
    id: string,
    _opts?: IamAdapter.IReadOptions,
  ): Promise<IamRequest.IScopedRole<TRole, TScope>[]> {
    const hasScope = (e: { role: TRole; scope?: TScope }): e is { role: TRole; scope: TScope } => e.scope != null
    return (this._assignments.get(id) ?? []).filter(hasScope).map((e) => ({ role: e.role, scope: e.scope }))
  }

  /**
   * Grants a role to a subject, optionally within a scope; duplicate `(role, scope)` pairs are ignored.
   * Refuses a role that is not stored - see {@link iamAssertRoleExists}.
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
   * WARN: omitting `scope` removes EVERY assignment for the role, scoped ones included (as redis/drizzle/prisma do).
   */
  async revokeRole(id: string, roleId: TRole, scope?: TScope): Promise<void> {
    iamAssertAssignableScope('memory', scope, 'lookup')
    const entries = this._assignments.get(id)
    if (!entries) return
    const filtered =
      scope === undefined
        ? entries.filter((e) => e.role !== roleId)
        : entries.filter((e) => !(e.role === roleId && e.scope === scope))
    this._assignments.set(id, filtered)
  }

  /**
   * Moves an existing assignment to a different scope in place.
   *
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

  /** Fetches a subject's attribute bag, or `{}` when none is recorded. */
  async getSubjectAttributes(id: string, _opts?: IamAdapter.IReadOptions): Promise<IamPrimitives.Attributes> {
    // NOTE: return a one-level copy (see `iamCopyAttributes`) so editing the result cannot rewrite the store.
    const attrs = this._attributes.get(id)
    return attrs === undefined ? {} : iamCopyAttributes(attrs)
  }

  /** Shallow-merges an attribute patch into the subject's existing bag. */
  async setSubjectAttributes(id: string, attrs: IamPrimitives.Attributes): Promise<void> {
    iamAssertAttributesParam('memory', id, attrs)
    // NOTE: copy the patch too, so mutating the caller's arrays after the write cannot change the store.
    this._attributes.set(id, { ...(this._attributes.get(id) ?? {}), ...iamCopyAttributes(attrs) })
  }
}

/** Factory around {@link IamMemoryAdapter}, for callers who prefer functions to `new`. */
export function iamMemoryAdapter(...args: ConstructorParameters<typeof IamMemoryAdapter>): IamMemoryAdapter {
  return new IamMemoryAdapter(...args)
}
