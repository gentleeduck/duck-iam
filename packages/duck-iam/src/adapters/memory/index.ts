import type { Adapter, Attributes, Policy, Role } from '../../core/types'

export interface MemoryAdapterInit {
  policies?: Policy[]
  roles?: Role[]
  assignments?: Record<string, string[]>
  attributes?: Record<string, Attributes>
}

export class MemoryAdapter implements Adapter {
  private policies = new Map<string, Policy>()
  private roles = new Map<string, Role>()
  private assignments = new Map<string, Set<string>>()
  private attributes = new Map<string, Attributes>()

  constructor(init?: MemoryAdapterInit) {
    for (const p of init?.policies ?? []) this.policies.set(p.id, p)
    for (const r of init?.roles ?? []) this.roles.set(r.id, r)
    for (const [uid, roles] of Object.entries(init?.assignments ?? {})) {
      this.assignments.set(uid, new Set(roles))
    }
    for (const [uid, attrs] of Object.entries(init?.attributes ?? {})) {
      this.attributes.set(uid, attrs)
    }
  }

  // PolicyStore
  async listPolicies(): Promise<Policy[]> {
    return [...this.policies.values()]
  }
  async getPolicy(id: string): Promise<Policy | null> {
    return this.policies.get(id) ?? null
  }
  async savePolicy(p: Policy): Promise<void> {
    this.policies.set(p.id, p)
  }
  async deletePolicy(id: string): Promise<void> {
    this.policies.delete(id)
  }

  // RoleStore
  async listRoles(): Promise<Role[]> {
    return [...this.roles.values()]
  }
  async getRole(id: string): Promise<Role | null> {
    return this.roles.get(id) ?? null
  }
  async saveRole(r: Role): Promise<void> {
    this.roles.set(r.id, r)
  }
  async deleteRole(id: string): Promise<void> {
    this.roles.delete(id)
  }

  // SubjectStore
  async getSubjectRoles(id: string): Promise<string[]> {
    return [...(this.assignments.get(id) ?? [])]
  }
  async assignRole(id: string, roleId: string): Promise<void> {
    if (!this.assignments.has(id)) this.assignments.set(id, new Set())
    this.assignments.get(id)!.add(roleId)
  }
  async revokeRole(id: string, roleId: string): Promise<void> {
    this.assignments.get(id)?.delete(roleId)
  }
  async getSubjectAttributes(id: string): Promise<Attributes> {
    return this.attributes.get(id) ?? {}
  }
  async setSubjectAttributes(id: string, attrs: Attributes): Promise<void> {
    this.attributes.set(id, { ...(this.attributes.get(id) ?? {}), ...attrs })
  }
}
