import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl, IamAdapter, IamPrimitives } from '../../types'
import { createAdmin } from '../engine.libs'
import { IamEngine } from '../index'

const POLICY: AccessControl.IPolicy = {
  algorithm: 'deny-overrides',
  description: '',
  id: 'p1',
  name: 'p1',
  rules: [],
  version: 1,
}
const ROLE: AccessControl.IRole = { description: '', id: 'r1', inherits: [], name: 'r1', permissions: [] }

/** A memory adapter whose named methods never settle, so a caller only returns if something bounds it. */
class Hung extends IamMemoryAdapter {
  readonly hang = new Set<string>()
  readonly signals: (AbortSignal | undefined)[] = []
  private stall<T>(name: string, run: () => Promise<T>): Promise<T> {
    return this.hang.has(name) ? new Promise<T>(() => {}) : run()
  }
  override listPolicies(opts?: IamAdapter.IReadOptions) {
    this.signals.push(opts?.signal)
    return this.stall('listPolicies', () => super.listPolicies(opts))
  }
  override getPolicy(id: string, opts?: IamAdapter.IReadOptions) {
    return this.stall('getPolicy', () => super.getPolicy(id, opts))
  }
  override savePolicy(p: AccessControl.IPolicy) {
    return this.stall('savePolicy', () => super.savePolicy(p))
  }
  override deletePolicy(id: string) {
    return this.stall('deletePolicy', () => super.deletePolicy(id))
  }
  override listRoles(opts?: IamAdapter.IReadOptions) {
    return this.stall('listRoles', () => super.listRoles(opts))
  }
  override getRole(id: string, opts?: IamAdapter.IReadOptions) {
    return this.stall('getRole', () => super.getRole(id, opts))
  }
  override saveRole(r: AccessControl.IRole) {
    return this.stall('saveRole', () => super.saveRole(r))
  }
  override deleteRole(id: string) {
    return this.stall('deleteRole', () => super.deleteRole(id))
  }
  override assignRole(id: string, roleId: string, scope?: string, opts?: IamAdapter.IAssignOptions) {
    return this.stall('assignRole', () => super.assignRole(id, roleId, scope, opts))
  }
  override revokeRole(id: string, roleId: string, scope?: string) {
    return this.stall('revokeRole', () => super.revokeRole(id, roleId, scope))
  }
  override updateAssignmentScope(id: string, roleId: string, from?: string, to?: string) {
    return this.stall('updateAssignmentScope', () => super.updateAssignmentScope(id, roleId, from, to))
  }
  override getSubjectAttributes(id: string, opts?: IamAdapter.IReadOptions) {
    return this.stall('getSubjectAttributes', () => super.getSubjectAttributes(id, opts))
  }
  override setSubjectAttributes(id: string, attrs: IamPrimitives.Attributes) {
    return this.stall('setSubjectAttributes', () => super.setSubjectAttributes(id, attrs))
  }
}

type Admin = IamEngine['admin']

/** Every admin operation, paired with the adapter method it must not outlive. */
const OPS: { name: string; hangs: string; call: (admin: Admin) => Promise<unknown> }[] = [
  { call: (a) => a.listPolicies(), hangs: 'listPolicies', name: 'listPolicies' },
  { call: (a) => a.getPolicy('p1'), hangs: 'getPolicy', name: 'getPolicy' },
  { call: (a) => a.savePolicy(POLICY), hangs: 'savePolicy', name: 'savePolicy' },
  { call: (a) => a.deletePolicy('p1'), hangs: 'deletePolicy', name: 'deletePolicy' },
  { call: (a) => a.listRoles(), hangs: 'listRoles', name: 'listRoles' },
  { call: (a) => a.getRole('r1'), hangs: 'getRole', name: 'getRole' },
  { call: (a) => a.saveRole(ROLE), hangs: 'saveRole', name: 'saveRole' },
  { call: (a) => a.deleteRole('r1'), hangs: 'deleteRole', name: 'deleteRole' },
  { call: (a) => a.assignRole('u1', 'r1'), hangs: 'assignRole', name: 'assignRole' },
  { call: (a) => a.revokeRole('u1', 'r1'), hangs: 'revokeRole', name: 'revokeRole' },
  { call: (a) => a.assignRoles([{ roleId: 'r1', subjectId: 'u1' }]), hangs: 'assignRole', name: 'assignRoles' },
  { call: (a) => a.revokeRoles([{ roleId: 'r1', subjectId: 'u1' }]), hangs: 'revokeRole', name: 'revokeRoles' },
  {
    call: (a) => a.moveRoleScopes([{ roleId: 'r1', subjectId: 'u1', toScope: 's2' }]),
    hangs: 'updateAssignmentScope',
    name: 'moveRoleScopes',
  },
  { call: (a) => a.getAttributes('u1'), hangs: 'getSubjectAttributes', name: 'getAttributes' },
  { call: (a) => a.setAttributes('u1', { tier: 'gold' }), hangs: 'setSubjectAttributes', name: 'setAttributes' },
  { call: (a) => a.export(), hangs: 'listPolicies', name: 'export' },
  {
    call: (a) => a.import({ exportedAt: '', policies: [POLICY], roles: [], schemaVersion: 1 }),
    hangs: 'savePolicy',
    name: 'import',
  },
]

/** Seeded before anything hangs, so a healthy run has the row each operation names. */
async function engineWith(hangs: string[], adapterTimeoutMs = 40): Promise<{ adapter: Hung; engine: IamEngine }> {
  const adapter = new Hung()
  await adapter.savePolicy(POLICY)
  await adapter.saveRole(ROLE)
  await adapter.assignRole('u1', 'r1')
  for (const h of hangs) adapter.hang.add(h)
  return { adapter, engine: new IamEngine({ adapter, adapterTimeoutMs, cacheTTL: 0, mode: 'production' }) }
}

/** Resolves `'HUNG'` if `p` has not settled by `ms`, so a never-settling call is a value rather than a stuck test. */
async function settle(p: Promise<unknown>, ms = 400): Promise<string> {
  const pending = Symbol('pending')
  const raced = await Promise.race([
    p.then(() => 'resolved').catch((e: unknown) => (e instanceof Error ? e.message : String(e))),
    new Promise<symbol>((r) => setTimeout(() => r(pending), ms)),
  ])
  return raced === pending ? 'HUNG' : String(raced)
}

describe('adapterTimeoutMs bounds the admin facade, not only the decision path', () => {
  it.each(OPS)('$name rejects instead of hanging when the adapter never answers', async ({ call, hangs }) => {
    const { engine } = await engineWith([hangs])
    expect(await settle(call(engine.admin))).toMatch(/timed out after 40ms/)
  })

  it.each(OPS)('$name still answers against a healthy adapter', async ({ call }) => {
    const { engine } = await engineWith([])
    expect(await settle(call(engine.admin))).toBe('resolved')
  })

  it('the timeout names the call that expired', async () => {
    const { engine } = await engineWith(['listRoles'])
    await expect(engine.admin.listRoles()).rejects.toThrow('admin.listRoles timed out')
  })

  it('an admin read is given an abort signal, and it fires', async () => {
    const { adapter, engine } = await engineWith(['listPolicies'])
    await expect(engine.admin.listPolicies()).rejects.toThrow(/timed out/)
    const signal = adapter.signals.at(-1)
    expect(signal).toBeInstanceOf(AbortSignal)
    expect(signal?.aborted).toBe(true)
  })

  it('adapterTimeoutMs 0 keeps the documented unbounded behaviour', async () => {
    const { engine } = await engineWith(['listPolicies'], 0)
    expect(await settle(engine.admin.listPolicies(), 150)).toBe('HUNG')
  })

  it('an admin built without withTimeout is unbounded, as the transaction-bound one is', async () => {
    const adapter = new Hung()
    await adapter.savePolicy(POLICY)
    adapter.hang.add('listPolicies')
    const admin = createAdmin(adapter, {
      cache: { invalidatePolicies: () => {}, invalidateRoles: () => {}, invalidateSubject: () => {} },
    })
    expect(await settle(admin.listPolicies(), 150)).toBe('HUNG')
  })

  it('the decision path was already bounded, and still is', async () => {
    const { engine } = await engineWith(['listPolicies'])
    expect(await engine.can('u1', 'read', { attributes: {}, type: 'post' })).toBe(false)
  })
})
