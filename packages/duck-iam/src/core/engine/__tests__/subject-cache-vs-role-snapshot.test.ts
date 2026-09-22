import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { AccessControl, IamAdapter } from '../../types'
import { IamEngine } from '../engine'

// A subject entry holds `resolveEffectiveRoles(assigned, snapshot)`, so it is derived from the role snapshot
// exactly as the RBAC policy, the merged policies and the compiled table are. Those three expire with their
// input; this pins that the subject entry does too, instead of buying a second full `cacheTTL` past it.

/** Roles are swappable mid-test, standing in for another process writing the store. */
class MutableRoleAdapter implements IamAdapter.IAdapter {
  roleReads = 0
  subjectReads = 0
  roles: AccessControl.IRole[]
  private _globalRoles: string[]

  constructor(roles: AccessControl.IRole[], globalRoles: string[] = ['staff']) {
    this.roles = roles
    this._globalRoles = globalRoles
  }

  async listPolicies(): Promise<AccessControl.IPolicy[]> {
    return []
  }
  async getPolicy(): Promise<AccessControl.IPolicy | null> {
    return null
  }
  async savePolicy(): Promise<void> {}
  async deletePolicy(): Promise<void> {}
  async listRoles(): Promise<AccessControl.IRole[]> {
    this.roleReads += 1
    return this.roles
  }
  async getRole(id: string): Promise<AccessControl.IRole | null> {
    return this.roles.find((r) => r.id === id) ?? null
  }
  async saveRole(): Promise<void> {}
  async deleteRole(): Promise<void> {}
  async getSubjectRoles(): Promise<string[]> {
    this.subjectReads += 1
    return this._globalRoles
  }
  async getSubjectScopedRoles(): Promise<{ role: string; scope: string }[]> {
    return [{ role: 'staff', scope: 'org-1' }]
  }
  async assignRole(): Promise<void> {}
  async revokeRole(): Promise<void> {}
  async getSubjectAttributes(): Promise<Record<string, never>> {
    return {}
  }
  async setSubjectAttributes(): Promise<void> {}
}

const ADMIN: AccessControl.IRole = { id: 'admin', name: 'Admin', permissions: [{ action: 'delete', resource: 'post' }] }
const WITH_EDGE: AccessControl.IRole[] = [ADMIN, { id: 'staff', inherits: ['admin'], name: 'Staff', permissions: [] }]
const WITHOUT_EDGE: AccessControl.IRole[] = [ADMIN, { id: 'staff', name: 'Staff', permissions: [] }]

const POST = { attributes: {}, type: 'post' } as const
const T0 = Date.UTC(2026, 0, 15, 12, 0, 0)
const TTL = 60_000

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(T0)
})
afterEach(() => {
  vi.useRealTimers()
})

describe('a subject entry does not outlive the role snapshot it was resolved against', () => {
  it('drops the inherited permission when the snapshot it came from expires', async () => {
    const adapter = new MutableRoleAdapter(WITH_EDGE)
    const engine = new IamEngine({ adapter })

    // Fills the role cache at T0; it expires at T0 + TTL.
    expect(await engine.can('alice', 'delete', POST)).toBe(true)

    // Bob resolves against that same snapshot with 10s left on it, so his entry may live 10s, not 60.
    vi.setSystemTime(T0 + 50_000)
    expect(await engine.can('bob', 'delete', POST)).toBe(true)

    // Another process removes the edge. Neither cache knows yet.
    adapter.roles = WITHOUT_EDGE
    vi.setSystemTime(T0 + 59_999)
    expect(await engine.can('bob', 'delete', POST)).toBe(true)
    expect(adapter.roleReads).toBe(1)

    // The snapshot lapses. Alice is the control: her own entry lapsed at the same instant.
    vi.setSystemTime(T0 + TTL)
    expect(await engine.can('alice', 'delete', POST)).toBe(false)
    expect(adapter.roleReads).toBe(2)
    expect(await engine.can('bob', 'delete', POST)).toBe(false)
  })

  it('caps the scoped half of the entry too', async () => {
    // No global grant, so the only route to `delete:post` is the scoped row resolved through `inherits`.
    const adapter = new MutableRoleAdapter(WITH_EDGE, [])
    const engine = new IamEngine({ adapter, scopeMode: 'flat' })

    expect(await engine.can('alice', 'delete', POST, undefined, 'org-1')).toBe(true)
    expect(await engine.can('alice', 'delete', POST)).toBe(false)

    vi.setSystemTime(T0 + 50_000)
    expect(await engine.can('bob', 'delete', POST, undefined, 'org-1')).toBe(true)

    adapter.roles = WITHOUT_EDGE
    vi.setSystemTime(T0 + TTL)
    expect(await engine.can('bob', 'delete', POST, undefined, 'org-1')).toBe(false)
  })

  it('still honours a grant boundary that closes before the snapshot does', async () => {
    const adapter = new MutableRoleAdapter(WITH_EDGE)
    const withBoundary = Object.assign(adapter, {
      getSubjectGrantBoundary: async (): Promise<number | null> => T0 + 5_000,
    })
    const engine = new IamEngine({ adapter: withBoundary })

    // The snapshot is the looser of the two caps here; taking the min must not lose the tighter one.
    expect(await engine.can('alice', 'delete', POST)).toBe(true)
    vi.setSystemTime(T0 + 4_999)
    expect(await engine.can('alice', 'delete', POST)).toBe(true)
    expect(adapter.subjectReads).toBe(1)
    vi.setSystemTime(T0 + 5_000)
    expect(await engine.can('alice', 'delete', POST)).toBe(true)
    expect(adapter.subjectReads).toBe(2)
    expect(adapter.roleReads).toBe(1)
  })

  it('a role cache that never caches does not pin a subject entry open', async () => {
    const adapter = new MutableRoleAdapter(WITH_EDGE)
    const engine = new IamEngine({ adapter, cacheTTL: 0 })

    expect(await engine.can('alice', 'delete', POST)).toBe(true)
    adapter.roles = WITHOUT_EDGE
    expect(await engine.can('alice', 'delete', POST)).toBe(false)
  })
})
