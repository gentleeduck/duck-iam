import type { Adapter, Attributes, Policy, Role, ScopedRole } from '../../core/types'

export interface MemoryAdapterInit<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
> {
  policies?: Policy<TAction, TResource, TRole>[]
  roles?: Role<TAction, TResource, TRole, TScope>[]
  assignments?: Record<string, TRole[]>
  attributes?: Record<string, Attributes>
}

export class MemoryAdapter<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
> implements Adapter<TAction, TResource, TRole, TScope>
{
  private policies = new Map<string, Policy<TAction, TResource, TRole>>()
  private roles = new Map<string, Role<TAction, TResource, TRole, TScope>>()
  private assignments = new Map<string, Array<{ role: TRole; scope?: TScope }>>()
  private attributes = new Map<string, Attributes>()

  constructor(init?: MemoryAdapterInit<TAction, TResource, TRole, TScope>) {
    for (const p of init?.policies ?? []) this.policies.set(p.id, p)
    for (const r of init?.roles ?? []) this.roles.set(r.id, r)
    for (const [uid, roles] of Object.entries(init?.assignments ?? {})) {
      this.assignments.set(
        uid,
        (roles as TRole[]).map((r) => ({ role: r })),
      )
    }
    for (const [uid, attrs] of Object.entries(init?.attributes ?? {})) {
      this.attributes.set(uid, attrs)
    }
  }

  // PolicyStore
  async listPolicies(): Promise<Policy<TAction, TResource, TRole>[]> {
    return [...this.policies.values()]
  }
  async getPolicy(id: string): Promise<Policy<TAction, TResource, TRole> | null> {
    return this.policies.get(id) ?? null
  }
  async savePolicy(p: Policy<TAction, TResource, TRole>): Promise<void> {
    this.policies.set(p.id, p)
  }
  async deletePolicy(id: string): Promise<void> {
    this.policies.delete(id)
  }

  // RoleStore
  async listRoles(): Promise<Role<TAction, TResource, TRole, TScope>[]> {
    return [...this.roles.values()]
  }
  async getRole(id: string): Promise<Role<TAction, TResource, TRole, TScope> | null> {
    return this.roles.get(id) ?? null
  }
  async saveRole(r: Role<TAction, TResource, TRole, TScope>): Promise<void> {
    this.roles.set(r.id, r)
  }
  async deleteRole(id: string): Promise<void> {
    this.roles.delete(id)
  }

  // SubjectStore
  async getSubjectRoles(id: string): Promise<TRole[]> {
    const entries = this.assignments.get(id) ?? []
    // Only return unscoped (global) role assignments
    return [...new Set(entries.filter((e) => e.scope == null).map((e) => e.role))]
  }
  async getSubjectScopedRoles(id: string): Promise<ScopedRole<TRole, TScope>[]> {
    return (this.assignments.get(id) ?? [])
      .filter((e) => e.scope != null)
      .map((e) => ({ role: e.role, scope: e.scope! }))
  }
  async assignRole(id: string, roleId: TRole, scope?: TScope): Promise<void> {
    if (!this.assignments.has(id)) this.assignments.set(id, [])
    const entries = this.assignments.get(id)!
    // Prevent duplicate assignments
    if (!entries.some((e) => e.role === roleId && e.scope === scope)) {
      entries.push({ role: roleId, scope })
    }
  }
  async revokeRole(id: string, roleId: TRole, scope?: TScope): Promise<void> {
    const entries = this.assignments.get(id)
    if (!entries) return
    const filtered = entries.filter((e) => !(e.role === roleId && e.scope === scope))
    this.assignments.set(id, filtered)
  }
  async getSubjectAttributes(id: string): Promise<Attributes> {
    return this.attributes.get(id) ?? {}
  }
  async setSubjectAttributes(id: string, attrs: Attributes): Promise<void> {
    this.attributes.set(id, { ...(this.attributes.get(id) ?? {}), ...attrs })
  }
}
