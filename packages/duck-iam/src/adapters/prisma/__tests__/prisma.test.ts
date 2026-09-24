import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { AccessControl, IamAdapter } from '../../../core/types'
import { runAdapterCompliance } from '../../__compliance__/compliance'
import { runEngineCapabilityCompliance } from '../../__compliance__/engine-capability'
import { OPTIONAL_SUPPORT } from '../../__compliance__/optional-support'
import { IamPrismaAdapter, iamPrismaAdapter } from '../index'

type A = 'read' | 'write'
type R = 'post' | 'comment'
type Ro = 'viewer' | 'editor'
type S = 'org-1' | 'org-2'

/** The shape the adapter really sends to `upsert`, including the `update` half. */
interface IamUpsertArgs {
  where: { id: string }
  create: Record<string, unknown>
  update: Record<string, unknown>
}
interface PolicyRow {
  id: string
  name: string
  description: string | null
  version: number
  algorithm: string
  rules: unknown
  targets: unknown | null
}
interface RoleRow {
  id: string
  name: string
  description: string | null
  permissions: unknown
  inherits: string[] | null
  scope: string | null
  metadata: unknown | null
}
interface AssignmentRow {
  subjectId: string
  roleId: string
  scope: string | null
}
interface AttrRow {
  subjectId: string
  data: unknown
}

/** A Prisma-shaped error: the real client rejects with an `Error` carrying a `code`. */
function prismaError(code: string, message: string): Error & { code: string } {
  return Object.assign(new Error(message), { code })
}

/** Equality `where` matcher that also understands a `NOT` block. */
function matchesWhere(row: AssignmentRow, where: Record<string, unknown>): boolean {
  const fields: Record<string, unknown> = { roleId: row.roleId, scope: row.scope, subjectId: row.subjectId }
  for (const [key, value] of Object.entries(where)) {
    if (key === 'NOT') {
      if (typeof value !== 'object' || value === null) continue
      if (Object.entries(value).every(([k, v]) => fields[k] === v)) return false
      continue
    }
    if (fields[key] !== value) return false
  }
  return true
}

function makePrismaMock() {
  const policies = new Map<string, PolicyRow>()
  const roles = new Map<string, RoleRow>()
  const assignments: AssignmentRow[] = []
  const attrs = new Map<string, AttrRow>()

  return {
    accessPolicy: {
      findMany: vi.fn(async () => Array.from(policies.values())),
      findUnique: vi.fn(async ({ where }: { where: { id: string } }) => policies.get(where.id) ?? null),
      // Like a real `upsert`: `create` only on insert, `update` only on conflict.
      upsert: vi.fn(async ({ where, create, update }: IamUpsertArgs) => {
        const prev = policies.get(where.id)
        const next = (prev ? { ...prev, ...update } : create) as unknown as PolicyRow
        policies.set(where.id, next)
        return next
      }),
      // INFO: `deleteMany` reports a count on a miss, where Prisma's `delete` throws `P2025`.
      deleteMany: vi.fn(async ({ where }: { where: { id: string } }) => {
        const count = policies.delete(where.id) ? 1 : 0
        return { count }
      }),
    },
    accessRole: {
      findMany: vi.fn(async () => Array.from(roles.values())),
      findUnique: vi.fn(async ({ where }: { where: { id: string } }) => roles.get(where.id) ?? null),
      upsert: vi.fn(async ({ where, create, update }: IamUpsertArgs) => {
        const prev = roles.get(where.id)
        const next = (prev ? { ...prev, ...update } : create) as unknown as RoleRow
        roles.set(where.id, next)
        return next
      }),
      // See `accessPolicy.deleteMany`.
      deleteMany: vi.fn(async ({ where }: { where: { id: string } }) => {
        const count = roles.delete(where.id) ? 1 : 0
        // INFO: `AccessAssignment.role` is `onDelete: Cascade`, so the database drops the grants with the role.
        for (let i = assignments.length - 1; i >= 0; i--) {
          if (assignments[i]?.roleId === where.id) assignments.splice(i, 1)
        }
        return { count }
      }),
    },
    accessAssignment: {
      // Honours `roleId`, so an unrelated grant never reads as an existing one.
      findMany: vi.fn(
        async ({
          where,
          take,
        }: {
          where: { subjectId: string; roleId?: string; scope?: string | null }
          take?: number
        }) => {
          const hits = assignments.filter((a) => {
            if (a.subjectId !== where.subjectId) return false
            if (where.roleId !== undefined && a.roleId !== where.roleId) return false
            // Mirror Prisma: `scope: null` filter matches NULL rows only.
            if ('scope' in where) return a.scope === where.scope
            return true
          })
          return take === undefined ? hits : hits.slice(0, take)
        },
      ),
      // INFO: the reference schema's `@@unique([subjectId, roleId, scope])` raises P2002 on a duplicate.
      create: vi.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row = data as unknown as AssignmentRow
        // INFO: `AccessAssignment.role` is a required relation, so a grant naming a missing role raises P2003.
        if (!roles.has(row.roleId)) {
          throw prismaError('P2003', 'Foreign key constraint failed on the field: `roleId`')
        }
        const clash = assignments.some(
          (a) => a.subjectId === row.subjectId && a.roleId === row.roleId && a.scope === row.scope,
        )
        if (clash) throw prismaError('P2002', 'Unique constraint failed on the fields: (`subjectId`,`roleId`,`scope`)')
        assignments.push(row)
        return row
      }),
      deleteMany: vi.fn(async ({ where }: { where: Record<string, unknown> }) => {
        const before = assignments.length
        for (let i = assignments.length - 1; i >= 0; i--) {
          if (matchesWhere(assignments[i]!, where)) assignments.splice(i, 1)
        }
        return { count: before - assignments.length }
      }),
      updateMany: vi.fn(async ({ where, data }: { where: Record<string, unknown>; data: Record<string, unknown> }) => {
        let count = 0
        for (const a of assignments) {
          if (!matchesWhere(a, where)) continue
          Object.assign(a, data)
          count++
        }
        return { count }
      }),
    },
    accessSubjectAttr: {
      findUnique: vi.fn(async ({ where }: { where: { subjectId: string } }) => attrs.get(where.subjectId) ?? null),
      upsert: vi.fn(
        async ({
          where,
          create,
          update,
        }: {
          where: { subjectId: string }
          create: Record<string, unknown>
          update: Record<string, unknown>
        }) => {
          const existing = attrs.get(where.subjectId)
          if (existing) {
            attrs.set(where.subjectId, { ...existing, ...(update as Partial<AttrRow>) })
          } else {
            attrs.set(where.subjectId, create as unknown as AttrRow)
          }
          return attrs.get(where.subjectId)!
        },
      ),
    },
  }
}

// IamAdapter compliance - fresh prisma mock per call.
runAdapterCompliance('IamPrismaAdapter', () => new IamPrismaAdapter(makePrismaMock()), {
  supports: OPTIONAL_SUPPORT.IamPrismaAdapter,
})

runEngineCapabilityCompliance('IamPrismaAdapter', () => new IamPrismaAdapter(makePrismaMock()))

/** Stores roles so assignments naming them pass the `P2003` relation check. */
async function seedRoles(prisma: ReturnType<typeof makePrismaMock>, ...ids: string[]): Promise<void> {
  for (const id of ids) {
    const row = { id, name: id, permissions: [] }
    await prisma.accessRole.upsert({ create: row, update: row, where: { id } })
  }
}

describe('IamPrismaAdapter', () => {
  let prisma: ReturnType<typeof makePrismaMock>
  let adapter: IamPrismaAdapter<A, R, Ro, S>

  beforeEach(() => {
    prisma = makePrismaMock()
    adapter = new IamPrismaAdapter<A, R, Ro, S>(prisma)
  })

  describe('IamAdapter.IPolicyStore', () => {
    const policy: AccessControl.IPolicy<A, R, Ro> = {
      id: 'p1',
      name: 'Test AccessControl.IPolicy',
      description: 'desc',
      version: 1,
      algorithm: 'deny-overrides',
      rules: [],
      targets: { actions: ['read'] },
    }

    it('listPolicies returns empty initially', async () => {
      expect(await adapter.listPolicies()).toEqual([])
    })

    it('savePolicy writes via upsert', async () => {
      await adapter.savePolicy(policy)
      expect(prisma.accessPolicy.upsert).toHaveBeenCalledOnce()
      const list = await adapter.listPolicies()
      expect(list).toHaveLength(1)
      expect(list[0]?.id).toBe('p1')
    })

    it('getPolicy roundtrips description and targets', async () => {
      await adapter.savePolicy(policy)
      const got = await adapter.getPolicy('p1')
      expect(got?.description).toBe('desc')
      expect(got?.targets).toEqual({ actions: ['read'] })
    })

    it('getPolicy null when missing', async () => {
      expect(await adapter.getPolicy('nope')).toBeNull()
    })

    it('savePolicy normalizes optional fields to null', async () => {
      await adapter.savePolicy({
        id: 'p2',
        name: 'Bare',
        algorithm: 'allow-overrides',
        rules: [],
      })
      const args = (prisma.accessPolicy.upsert as ReturnType<typeof vi.fn>).mock.calls[0]![0] as {
        create: Record<string, unknown>
      }
      expect(args.create.description).toBeNull()
      expect(args.create.targets).toBeNull()
      expect(args.create.version).toBe(1)
    })

    it('toPolicy converts null description back to undefined', async () => {
      await adapter.savePolicy({
        id: 'p3',
        name: 'Bare',
        algorithm: 'first-match',
        rules: [],
      })
      const got = await adapter.getPolicy('p3')
      expect(got?.description).toBeUndefined()
      expect(got?.targets).toBeUndefined()
    })

    it('deletePolicy removes the row', async () => {
      await adapter.savePolicy(policy)
      await adapter.deletePolicy('p1')
      expect(prisma.accessPolicy.deleteMany).toHaveBeenCalledWith({ where: { id: 'p1' } })
      expect(await adapter.listPolicies()).toEqual([])
    })

    // INFO: Prisma's `delete` raises `P2025` when nothing matches, so a retried delete must not use it.
    it('deletePolicy is idempotent, like every other adapter', async () => {
      await adapter.savePolicy(policy)
      await adapter.deletePolicy('p1')
      await expect(adapter.deletePolicy('p1')).resolves.toBeUndefined()
      await expect(adapter.deletePolicy('never-existed')).resolves.toBeUndefined()
    })
  })

  describe('IamAdapter.IRoleStore', () => {
    const role: AccessControl.IRole<A, R, Ro, S> = {
      id: 'editor',
      name: 'Editor',
      description: 'Can edit',
      permissions: [{ action: 'write', resource: 'post' }],
      inherits: ['viewer'] as Ro[],
      scope: 'org-1',
      metadata: { color: 'blue' },
    }

    it('listRoles empty', async () => {
      expect(await adapter.listRoles()).toEqual([])
    })

    it('saveRole + getRole roundtrip', async () => {
      await adapter.saveRole(role)
      const got = await adapter.getRole('editor')
      expect(got).toMatchObject({
        id: 'editor',
        name: 'Editor',
        description: 'Can edit',
        inherits: ['viewer'],
        scope: 'org-1',
        metadata: { color: 'blue' },
      })
    })

    it('getRole null when missing', async () => {
      expect(await adapter.getRole('nope')).toBeNull()
    })

    it('saveRole normalizes optionals', async () => {
      await adapter.saveRole({
        id: 'minimal' as Ro,
        name: 'Minimal',
        permissions: [],
      })
      const args = (prisma.accessRole.upsert as ReturnType<typeof vi.fn>).mock.calls[0]![0] as {
        create: Record<string, unknown>
      }
      expect(args.create.description).toBeNull()
      expect(args.create.scope).toBeNull()
      expect(args.create.metadata).toBeNull()
      expect(args.create.inherits).toEqual([])
    })

    // The write path sends `inherits: []`, but the read omits absent keys so every adapter returns the same shape.
    it('toRole omits the keys the stored role does not have', async () => {
      const saved = { id: 'r2' as Ro, name: 'R', permissions: [] }
      await adapter.saveRole(saved)
      const got = await adapter.getRole('r2')

      expect(got).toEqual(saved)
      expect(Object.keys(got ?? {}).sort()).toEqual(['id', 'name', 'permissions'])
      expect('inherits' in (got ?? {})).toBe(false)
      expect('description' in (got ?? {})).toBe(false)
      expect('scope' in (got ?? {})).toBe(false)
      expect('metadata' in (got ?? {})).toBe(false)
    })

    it('toRole keeps every key the stored role does have', async () => {
      const saved = {
        id: 'r3' as Ro,
        name: 'R3',
        description: 'has one',
        permissions: [],
        inherits: ['viewer' as Ro],
        scope: 'org-1' as S,
        metadata: { tier: 'gold' },
      }
      await adapter.saveRole(saved)
      expect(await adapter.getRole('r3')).toEqual(saved)
    })

    it('deleteRole removes the row', async () => {
      await adapter.saveRole(role)
      await adapter.deleteRole('editor')
      expect(await adapter.listRoles()).toEqual([])
    })
  })

  describe('IamAdapter.ISubjectStore', () => {
    beforeEach(async () => {
      await seedRoles(prisma, 'editor', 'viewer')
    })

    // INFO: a repeat scoped `create` raises `P2002`; a repeat unscoped one inserts again, since SQL unique
    // indexes do not collapse `NULL`s.
    it('assignRole is idempotent for a scoped grant', async () => {
      await adapter.assignRole('user-1', 'editor' as Ro, 'org-1')
      await expect(adapter.assignRole('user-1', 'editor' as Ro, 'org-1')).resolves.toBeUndefined()
      expect(await adapter.getSubjectScopedRoles('user-1')).toEqual([{ role: 'editor', scope: 'org-1' }])
    })

    it('assignRole does not accumulate duplicate rows for an unscoped grant', async () => {
      await adapter.assignRole('user-1', 'editor' as Ro)
      await adapter.assignRole('user-1', 'editor' as Ro)
      await adapter.assignRole('user-1', 'editor' as Ro)
      expect(prisma.accessAssignment.create).toHaveBeenCalledOnce()
      expect(await adapter.getSubjectRoles('user-1')).toEqual(['editor'])
    })

    // Without this, an `assignRole` that stopped writing after the first call would pass the tests above.
    it('control: distinct grants are still distinct rows', async () => {
      await adapter.assignRole('user-1', 'editor' as Ro)
      await adapter.assignRole('user-1', 'editor' as Ro, 'org-1')
      await adapter.assignRole('user-1', 'editor' as Ro, 'org-2')
      expect(prisma.accessAssignment.create).toHaveBeenCalledTimes(3)
      expect((await adapter.getSubjectScopedRoles('user-1')).map((r) => r.scope).sort()).toEqual(['org-1', 'org-2'])
    })

    it('deleteRole is idempotent, like every other adapter', async () => {
      await adapter.saveRole({ id: 'r-gone' as Ro, name: 'R', permissions: [] })
      await adapter.deleteRole('r-gone')
      await expect(adapter.deleteRole('r-gone')).resolves.toBeUndefined()
      await expect(adapter.deleteRole('never-existed')).resolves.toBeUndefined()
    })

    it('getSubjectRoles returns deduplicated list', async () => {
      await adapter.assignRole('user-1', 'editor' as Ro)
      await adapter.assignRole('user-1', 'editor' as Ro, 'org-1')
      await adapter.assignRole('user-1', 'viewer' as Ro)
      const out = await adapter.getSubjectRoles('user-1')
      expect(out.sort()).toEqual(['editor', 'viewer'])
    })

    it('getSubjectScopedRoles returns only scoped', async () => {
      await adapter.assignRole('user-1', 'editor' as Ro) // unscoped
      await adapter.assignRole('user-1', 'editor' as Ro, 'org-1')
      await adapter.assignRole('user-1', 'viewer' as Ro, 'org-2')
      const out = await adapter.getSubjectScopedRoles('user-1')
      expect(out).toHaveLength(2)
      expect(out).toContainEqual({ role: 'editor', scope: 'org-1' })
      expect(out).toContainEqual({ role: 'viewer', scope: 'org-2' })
    })

    it('assignRole writes scope:null when omitted', async () => {
      await adapter.assignRole('user-1', 'editor' as Ro)
      const call = (prisma.accessAssignment.create as ReturnType<typeof vi.fn>).mock.calls[0]![0] as {
        data: Record<string, unknown>
      }
      expect(call.data.scope).toBeNull()
    })

    it('revokeRole without scope clears all scopes', async () => {
      await adapter.assignRole('user-1', 'editor' as Ro)
      await adapter.assignRole('user-1', 'editor' as Ro, 'org-1')
      await adapter.revokeRole('user-1', 'editor' as Ro)
      expect(await adapter.getSubjectRoles('user-1')).toEqual([])
    })

    it('revokeRole refuses an empty-string scope and leaves both grants standing', async () => {
      await adapter.assignRole('user-1', 'editor' as Ro)
      await adapter.assignRole('user-1', 'editor' as Ro, 'org-1')
      await expect(adapter.revokeRole('user-1', 'editor' as Ro, '' as S)).rejects.toThrow('IAM_SCOPE_INVALID')
      expect(await adapter.getSubjectRoles('user-1')).toEqual(['editor'])
      expect((await adapter.getSubjectScopedRoles('user-1')).map((r) => r.scope)).toEqual(['org-1'])
    })

    it('revokeRole with scope only clears matching scope', async () => {
      await adapter.assignRole('user-1', 'editor' as Ro)
      await adapter.assignRole('user-1', 'editor' as Ro, 'org-1')
      await adapter.revokeRole('user-1', 'editor' as Ro, 'org-1')
      const remaining = await adapter.getSubjectScopedRoles('user-1')
      expect(remaining).toEqual([])
      expect(await adapter.getSubjectRoles('user-1')).toEqual(['editor'])
    })

    it('getSubjectAttributes returns {} when missing', async () => {
      expect(await adapter.getSubjectAttributes('nobody')).toEqual({})
    })

    it('setSubjectAttributes upsert + merge', async () => {
      await adapter.setSubjectAttributes('user-1', { team: 'A' })
      await adapter.setSubjectAttributes('user-1', { plan: 'pro' })
      const got = await adapter.getSubjectAttributes('user-1')
      expect(got).toEqual({ team: 'A', plan: 'pro' })
    })

    it('setSubjectAttributes overwrites existing keys on merge', async () => {
      await adapter.setSubjectAttributes('user-1', { team: 'A' })
      await adapter.setSubjectAttributes('user-1', { team: 'B' })
      expect((await adapter.getSubjectAttributes('user-1')).team).toBe('B')
    })
  })

  describe('iamPrismaAdapter factory', () => {
    it('builds an adapter equivalent to `new IamPrismaAdapter(...)`', async () => {
      const built = iamPrismaAdapter(makePrismaMock())
      expect(built).toBeInstanceOf(IamPrismaAdapter)
      await built.savePolicy({ algorithm: 'deny-overrides', id: 'p1', name: 'P', rules: [] })
      expect((await built.listPolicies()).map((p) => p.id)).toEqual(['p1'])
    })

    it('binds the client it was handed, not a shared one', async () => {
      const a = iamPrismaAdapter(makePrismaMock())
      const b = iamPrismaAdapter(makePrismaMock())
      await a.savePolicy({ algorithm: 'deny-overrides', id: 'p1', name: 'P', rules: [] })
      expect(await b.listPolicies()).toEqual([])
    })
  })
})

// A mock more forgiving than the driver would hide real divergences, so it must reject what Prisma rejects.
describe('the prisma mock rejects what Prisma rejects', () => {
  it('raises P2002 on a duplicate (subjectId, roleId, scope)', async () => {
    const prisma = makePrismaMock()
    await seedRoles(prisma, 'editor')
    const row = { roleId: 'editor', scope: null, subjectId: 'user-1' }
    await prisma.accessAssignment.create({ data: row })
    await expect(prisma.accessAssignment.create({ data: row })).rejects.toMatchObject({ code: 'P2002' })
  })

  it("so the adapter's duplicate-assign pre-check is what keeps the write legal", async () => {
    const mock = makePrismaMock()
    await seedRoles(mock, 'editor')
    const adapter = new IamPrismaAdapter<A, R, Ro, S>(mock)
    await adapter.assignRole('user-1', 'editor')
    // The `findMany` pre-check skips `create` here; a racing P2002 is also swallowed by `assignRole`.
    await expect(adapter.assignRole('user-1', 'editor')).resolves.toBeUndefined()
    expect(await adapter.getSubjectRoles('user-1')).toEqual(['editor'])
  })

  it('interprets `NOT` in a deleteMany where-clause', async () => {
    const prisma = makePrismaMock()
    await seedRoles(prisma, 'editor')
    await prisma.accessAssignment.create({ data: { roleId: 'editor', scope: 'org-1', subjectId: 'user-1' } })
    await prisma.accessAssignment.create({ data: { roleId: 'editor', scope: 'org-2', subjectId: 'user-1' } })
    // Drops the row on `org-2` but never the one on `org-1`.
    const result = await prisma.accessAssignment.deleteMany({
      where: { NOT: { scope: 'org-1' }, roleId: 'editor', scope: 'org-2', subjectId: 'user-1' },
    })
    expect(result.count).toBe(1)
    expect(await prisma.accessAssignment.findMany({ where: { subjectId: 'user-1' } })).toHaveLength(1)
  })

  it('runs the conflict-drop end to end: moving onto a scope the subject already holds', async () => {
    const mock = makePrismaMock()
    await seedRoles(mock, 'editor')
    const adapter = new IamPrismaAdapter<A, R, Ro, S>(mock)
    await adapter.assignRole('user-1', 'editor', 'org-1')
    await adapter.assignRole('user-1', 'editor', 'org-2')
    expect(await adapter.updateAssignmentScope('user-1', 'editor', 'org-1', 'org-2')).toBe(true)
    expect(await adapter.getSubjectScopedRoles?.('user-1')).toEqual([{ role: 'editor', scope: 'org-2' }])
  })
})
