import { describe, expect, it, vi } from 'vitest'
import type { AccessControl, IamAdapter } from '../../types'
import { IamEngine } from '../engine'

// `resolveEffectiveRoles` keeps a directly assigned id no role defines, so an ABAC rule naming it still matches
// and the grant looks intact. What is gone is the `inherits` walk: every role that id conferred is absent, and a
// deny targeting one of those stops applying. Round 58's check cannot see it - the *targeted* role is stored.

/** Serves a catalog and a grant list independently, which is what an adapter that drops a role row produces. */
class SplitAdapter implements IamAdapter.IAdapter {
  constructor(
    private _roles: AccessControl.IRole[],
    private _grants: string[],
    private _scoped: { role: string; scope: string }[] = [],
  ) {}

  async listPolicies(): Promise<AccessControl.IPolicy[]> {
    return [GUARD]
  }
  async getPolicy(): Promise<AccessControl.IPolicy | null> {
    return null
  }
  async savePolicy(): Promise<void> {}
  async deletePolicy(): Promise<void> {}
  async listRoles(): Promise<AccessControl.IRole[]> {
    return this._roles
  }
  async getRole(id: string): Promise<AccessControl.IRole | null> {
    return this._roles.find((r) => r.id === id) ?? null
  }
  async saveRole(): Promise<void> {}
  async deleteRole(): Promise<void> {}
  async getSubjectRoles(): Promise<string[]> {
    return this._grants
  }
  async getSubjectScopedRoles(): Promise<{ role: string; scope: string }[]> {
    return this._scoped
  }
  async assignRole(): Promise<void> {}
  async revokeRole(): Promise<void> {}
  async getSubjectAttributes(): Promise<Record<string, never>> {
    return {}
  }
  async setSubjectAttributes(): Promise<void> {}
}

const POST = { attributes: {}, id: 'p1', type: 'post' } as const

const CONTRACTOR: AccessControl.IRole = { id: 'contractor', name: 'Contractor', permissions: [] }
const EDITOR: AccessControl.IRole = {
  id: 'editor',
  name: 'Editor',
  permissions: [{ action: 'delete', resource: 'post' }],
}
const STAFF: AccessControl.IRole = { id: 'staff', inherits: ['contractor'], name: 'Staff', permissions: [] }

const GUARD: AccessControl.IPolicy = {
  algorithm: 'deny-overrides',
  id: 'guard',
  name: 'Contractors may not delete',
  rules: [{ actions: ['delete'], conditions: { all: [] }, effect: 'deny', id: 'd', priority: 0, resources: ['post'] }],
  targets: { roles: ['contractor'] },
}

function build(roles: AccessControl.IRole[], grants: string[], scoped: { role: string; scope: string }[] = []) {
  const reported: string[] = []
  const engine = new IamEngine({
    adapter: new SplitAdapter(roles, grants, scoped),
    hooks: { onPolicyError: (e: Error, id: string) => reported.push(`${id}|${e.message}`) },
    mode: 'production',
  })
  return { engine, reported }
}

describe('a subject holding a role nothing defines is reported, not silent', () => {
  it('reports the grant whose inherits cannot be walked', async () => {
    const { engine, reported } = build([CONTRACTOR, EDITOR], ['staff', 'editor'])

    // The deny is gone: this is the behaviour the report exists to explain, not a verdict the report changes.
    expect(await engine.can('u1', 'delete', POST)).toBe(true)
    expect(reported).toHaveLength(1)
    expect(reported[0]).toContain('staff|')
    expect(reported[0]).toContain('"u1"')
    expect(reported[0]).toMatch(/no stored role defines/)
  })

  it('stays silent, and the deny fires, when the role is defined', async () => {
    const { engine, reported } = build([CONTRACTOR, EDITOR, STAFF], ['staff', 'editor'])
    expect(await engine.can('u1', 'delete', POST)).toBe(false)
    expect(reported).toEqual([])
  })

  it('CONTROL: holding the targeted role directly still denies, and holding neither still allows', async () => {
    // Without these the rows above prove nothing about the deny, only about the report.
    expect(await build([CONTRACTOR, EDITOR], ['contractor', 'editor']).engine.can('u1', 'delete', POST)).toBe(false)
    expect(await build([CONTRACTOR, EDITOR], ['editor']).engine.can('u1', 'delete', POST)).toBe(true)
  })

  it('the undefined id is still an effective role, so a rule naming it matches', async () => {
    // Round 58's check is the other direction and does not fire here: `contractor` is stored.
    const { engine, reported } = build([CONTRACTOR, EDITOR], ['staff', 'editor'])
    const explained = await engine.can('u1', 'delete', POST)
    expect(explained).toBe(true)
    expect(reported.some((r) => r.includes('targets role'))).toBe(false)
  })

  it('reports a scoped grant of an undefined role', async () => {
    const { engine, reported } = build([CONTRACTOR, EDITOR], ['editor'], [{ role: 'staff', scope: 'org-1' }])
    await engine.can('u1', 'delete', POST)
    expect(reported).toHaveLength(1)
    expect(reported[0]).toContain('staff|')
  })

  it('reports once per role id, not once per cache fill', async () => {
    const { engine, reported } = build([CONTRACTOR, EDITOR], ['staff', 'editor'])
    await engine.can('u1', 'delete', POST)
    engine.cache.invalidate()
    await engine.can('u1', 'delete', POST)
    await engine.can('u2', 'delete', POST)
    expect(reported).toHaveLength(1)
  })

  it('falls back to console.warn when no hook is wired', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      const engine = new IamEngine({
        adapter: new SplitAdapter([CONTRACTOR, EDITOR], ['staff', 'editor']),
        mode: 'production',
      })
      await engine.can('u1', 'delete', POST)
      expect(warn).toHaveBeenCalledTimes(1)
      expect(warn.mock.calls[0]?.[0]).toMatch(/holds role "staff"/)
    } finally {
      warn.mockRestore()
    }
  })

  it('a throwing hook does not become the verdict', async () => {
    const engine = new IamEngine({
      adapter: new SplitAdapter([CONTRACTOR, EDITOR], ['staff', 'editor']),
      hooks: {
        onPolicyError: () => {
          throw new Error('hook blew up')
        },
      },
      mode: 'production',
    })
    expect(await engine.can('u1', 'delete', POST)).toBe(true)
  })
})
