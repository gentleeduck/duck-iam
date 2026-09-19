import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl, IamPrimitives } from '../../types'
import { IamEngine } from '../engine'

// `IActorOptions` promises the actor reaches `created_by` / `updated_by`. Only the SQL adapters have those columns,
// so this records what every admin write hands the adapter instead.
type Action = 'read'
type ResourceType = 'post'
type RoleId = 'reader'
type Scope = 'org-1' | 'org-2'

const ROLE: AccessControl.IRole<Action, ResourceType, RoleId, Scope> = {
  id: 'reader',
  name: 'Reader',
  permissions: [{ action: 'read', resource: 'post' }],
}

const POLICY: AccessControl.IPolicy<Action, ResourceType, RoleId> = {
  algorithm: 'deny-overrides',
  id: 'p1',
  name: 'p1',
  rules: [{ actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'r1', priority: 1, resources: ['post'] }],
}

class Recorder extends IamMemoryAdapter<Action, ResourceType, RoleId, Scope> {
  seen: { method: string; actor: string | null }[] = []
  private _note(method: string, actor?: string) {
    this.seen.push({ actor: actor ?? null, method })
  }
  async savePolicy(p: AccessControl.IPolicy<Action, ResourceType, RoleId>, opts?: { actor?: string }) {
    this._note('savePolicy', opts?.actor)
    return super.savePolicy(p)
  }
  async saveRole(r: AccessControl.IRole<Action, ResourceType, RoleId, Scope>, opts?: { actor?: string }) {
    this._note('saveRole', opts?.actor)
    return super.saveRole(r)
  }
  async assignRole(id: string, roleId: RoleId, scope?: Scope, opts?: { actor?: string }) {
    this._note('assignRole', opts?.actor)
    return super.assignRole(id, roleId, scope, opts)
  }
  async revokeRole(id: string, roleId: RoleId, scope?: Scope, opts?: { actor?: string }) {
    this._note('revokeRole', opts?.actor)
    return super.revokeRole(id, roleId, scope)
  }
  async updateAssignmentScope(id: string, roleId: RoleId, fromScope?: Scope, toScope?: Scope, actor?: string) {
    this._note('updateAssignmentScope', actor)
    return super.updateAssignmentScope(id, roleId, fromScope, toScope)
  }
  async setSubjectAttributes(id: string, attrs: IamPrimitives.Attributes, opts?: { actor?: string }) {
    this._note('setSubjectAttributes', opts?.actor)
    return super.setSubjectAttributes(id, attrs)
  }
}

function makeEngine() {
  const adapter = new Recorder({ roles: [ROLE] })
  return { adapter, engine: new IamEngine<Action, ResourceType, RoleId, Scope>({ adapter, cacheTTL: 0 }) }
}

/** Every admin write that can name an actor, and the call that names `alice`. */
const WRITES: { name: string; run: (engine: IamEngine<Action, ResourceType, RoleId, Scope>) => Promise<unknown> }[] = [
  { name: 'savePolicy', run: (e) => e.admin.savePolicy(POLICY, { actor: 'alice' }) },
  { name: 'saveRole', run: (e) => e.admin.saveRole(ROLE, { actor: 'alice' }) },
  { name: 'assignRole', run: (e) => e.admin.assignRole('u1', 'reader', 'org-1', { actor: 'alice' }) },
  { name: 'setAttributes', run: (e) => e.admin.setAttributes('u1', { tier: 'gold' }, { actor: 'alice' }) },
  {
    name: 'assignRoles',
    run: (e) => e.admin.assignRoles([{ opts: { actor: 'alice' }, roleId: 'reader', subjectId: 'u1' }]),
  },
  {
    name: 'import',
    run: (e) =>
      e.admin.import(
        { exportedAt: new Date(0).toISOString(), policies: [POLICY], roles: [ROLE], schemaVersion: 1 },
        {},
        { actor: 'alice' },
      ),
  },
]

describe('every admin write tells the adapter who made it', () => {
  it.each(WRITES)('$name', async ({ run }) => {
    const { adapter, engine } = makeEngine()
    await run(engine)
    expect(adapter.seen.length).toBeGreaterThan(0)
    expect(adapter.seen.every((c) => c.actor === 'alice')).toBe(true)
  })

  it('revokeRole and revokeRoles name the actor too', async () => {
    const { adapter, engine } = makeEngine()
    await engine.admin.assignRole('u1', 'reader', 'org-1')
    adapter.seen = []
    await engine.admin.revokeRole('u1', 'reader', 'org-1', { actor: 'alice' })
    await engine.admin.assignRole('u1', 'reader', 'org-1')
    await engine.admin.revokeRoles([{ opts: { actor: 'alice' }, roleId: 'reader', scope: 'org-1', subjectId: 'u1' }])
    expect(adapter.seen.filter((c) => c.method === 'revokeRole').map((c) => c.actor)).toEqual(['alice', 'alice'])
  })

  // The memory adapter moves the row natively, so the actor rides the adapter's own `actor` argument.
  it('updateAssignmentScope names the actor', async () => {
    const { adapter, engine } = makeEngine()
    await engine.admin.assignRole('u1', 'reader', 'org-1')
    adapter.seen = []
    await engine.admin.updateAssignmentScope('u1', 'reader', 'org-1', 'org-2', 'alice')
    expect(adapter.seen).toEqual([{ actor: 'alice', method: 'updateAssignmentScope' }])
  })

  // Control: the recorder reports `null` when nothing names an actor, so the assertions above are not vacuous.
  it('a write with no actor records none', async () => {
    const { adapter, engine } = makeEngine()
    await engine.admin.savePolicy(POLICY)
    await engine.admin.import({
      exportedAt: new Date(0).toISOString(),
      policies: [POLICY],
      roles: [ROLE],
      schemaVersion: 1,
    })
    expect(adapter.seen.every((c) => c.actor === null)).toBe(true)
  })
})
