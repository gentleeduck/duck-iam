import { describe, expect, it } from 'vitest'
import { IamEngine } from '../../core/engine'
import { resolveEffectiveRoles } from '../../core/rbac'
import type { AccessControl, IamAdapter } from '../../core/types'
import { IamFile, IamFileAdapter } from '../file'
import { IamMemoryAdapter } from '../memory'

// `deleteRole` sweeps the grants that named the role. An `inherits` edge names it too, and used to survive, so
// recreating the id handed every holder of the child role whatever the new role grants.

const PATH = '/store.json'
function fileFs(): IamFile.IFS {
  const files = new Map<string, string>([[PATH, JSON.stringify({ assignments: {}, policies: {}, roles: {} })]])
  return {
    async mkdir() {},
    async readFile(p: string) {
      const v = files.get(p)
      if (v === undefined) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
      return v
    },
    async writeFile(p: string, d: string) {
      files.set(p, d)
    },
  }
}

const ADAPTERS: Array<[string, () => IamAdapter.IAdapter<string, string, string, string>]> = [
  ['memory', () => new IamMemoryAdapter()],
  ['file', () => new IamFileAdapter({ fs: fileFs(), path: PATH, rootDir: '/' })],
]

const READER: AccessControl.IRole = {
  id: 'reader',
  name: 'Reader',
  permissions: [{ action: 'read', resource: 'post' }],
}
const GHOST_V1: AccessControl.IRole = {
  id: 'ghost',
  name: 'Ghost',
  permissions: [{ action: 'write', resource: 'post' }],
}
const GHOST_V2: AccessControl.IRole = {
  id: 'ghost',
  name: 'Ghost v2',
  permissions: [{ action: 'delete', resource: 'post' }],
}
const STAFF: AccessControl.IRole = { id: 'staff', inherits: ['ghost'], name: 'Staff', permissions: [] }

async function seeded(make: () => IamAdapter.IAdapter<string, string, string, string>) {
  const a = make()
  for (const r of [READER, GHOST_V1, STAFF]) await a.saveRole(r)
  await a.assignRole('u1', 'reader')
  await a.assignRole('u1', 'staff')
  return a
}

describe.each(ADAPTERS)('%s: a recreated role id does not resurrect an inherits edge', (_name, make) => {
  const can = (a: IamAdapter.IAdapter<string, string, string, string>, action: string) =>
    new IamEngine({ adapter: a, cacheTTL: 0 }).can('u1', action, { attributes: {}, id: 'p1', type: 'post' })

  it('the child inherits the role while it exists', async () => {
    const a = await seeded(make)
    expect({ delete: await can(a, 'delete'), write: await can(a, 'write') }).toEqual({ delete: false, write: true })
  })

  it('deleting the parent takes the permission with it', async () => {
    const a = await seeded(make)
    await a.deleteRole('ghost')
    expect({ delete: await can(a, 'delete'), write: await can(a, 'write') }).toEqual({ delete: false, write: false })
  })

  it('deleting the parent drops the edge, so listRoles has no dangling inherit', async () => {
    const a = await seeded(make)
    await a.deleteRole('ghost')
    expect((await a.getRole('staff'))?.inherits ?? []).toEqual([])
  })

  // The escalation: an id reused for an unrelated role used to hand its permissions to every `staff` holder.
  it('recreating the id under a different role grants nothing through the child', async () => {
    const a = await seeded(make)
    await a.deleteRole('ghost')
    await a.saveRole(GHOST_V2)
    expect({ delete: await can(a, 'delete'), write: await can(a, 'write') }).toEqual({ delete: false, write: false })
    expect(resolveEffectiveRoles(await a.getSubjectRoles('u1'), await a.listRoles()).sort()).toEqual([
      'reader',
      'staff',
    ])
  })

  // A subject granted the recreated role directly still gets it: the sweep is about edges, not about the id.
  it('a fresh grant of the recreated id still works', async () => {
    const a = await seeded(make)
    await a.deleteRole('ghost')
    await a.saveRole(GHOST_V2)
    await a.assignRole('u1', 'ghost')
    expect(await can(a, 'delete')).toBe(true)
  })

  it('an unrelated edge on the same role survives the sweep', async () => {
    const a = await seeded(make)
    await a.saveRole({ id: 'other', name: 'Other', permissions: [] })
    await a.saveRole({ id: 'staff', inherits: ['ghost', 'other'], name: 'Staff', permissions: [] })
    await a.deleteRole('ghost')
    expect((await a.getRole('staff'))?.inherits).toEqual(['other'])
  })
})
