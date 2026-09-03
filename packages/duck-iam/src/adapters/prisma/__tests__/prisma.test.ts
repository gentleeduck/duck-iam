import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { AccessControl, IamAdapter } from '../../../core/types'
import { runAdapterCompliance } from '../../__compliance__/compliance'
import { IamPrismaAdapter, iamPrismaAdapter } from '../index'

type A = 'read' | 'write'
type R = 'post' | 'comment'
type Ro = 'viewer' | 'editor'
type S = 'org-1' | 'org-2'

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

/**
 * A Prisma-shaped error. The client rejects with an object carrying a `code`;
 * anything the adapter does with `err.code` has to see the same shape here or
 * the mock is testing a driver that does not exist.
 */
function prismaError(code: string, message: string): Error & { code: string } {
  return Object.assign(new Error(message), { code })
}

/**
 * A `where` matcher that understands `NOT`.
 *
 * The old matcher compared every key with `===`, so `NOT: { scope: 'org-1' }`
 * was tested as if `NOT` were a column - it matched nothing, and
 * `updateAssignmentScope`'s conflict-drop (`prisma/index.ts:364`) silently did
 * nothing under test while working against the real driver. A mock that cannot
 * express the query the code sends is not standing in for the driver.
 */
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
      upsert: vi.fn(async ({ where, create }: { where: { id: string }; create: Record<string, unknown> }) => {
        policies.set(where.id, create as unknown as PolicyRow)
        return create as unknown as PolicyRow
      }),
      // `deleteMany`, matching the adapter and the real client: it reports how
      // many rows it removed rather than throwing `P2025` on a miss. The old
      // mock spelled the miss `policies.get(id)!`, which returned `undefined` and
      // hid the divergence the real driver would have shown.
      deleteMany: vi.fn(async ({ where }: { where: { id: string } }) => {
        const count = policies.delete(where.id) ? 1 : 0
        return { count }
      }),
    },
    accessRole: {
      findMany: vi.fn(async () => Array.from(roles.values())),
      findUnique: vi.fn(async ({ where }: { where: { id: string } }) => roles.get(where.id) ?? null),
      upsert: vi.fn(async ({ where, create }: { where: { id: string }; create: Record<string, unknown> }) => {
        roles.set(where.id, create as unknown as RoleRow)
        return create as unknown as RoleRow
      }),
      // `deleteMany`, matching the adapter and the real client: it reports how
      // many rows it removed rather than throwing `P2025` on a miss. The old
      // mock spelled the miss `roles.get(id)!`, which returned `undefined` and
      // hid the divergence the real driver would have shown.
      deleteMany: vi.fn(async ({ where }: { where: { id: string } }) => {
        const count = roles.delete(where.id) ? 1 : 0
        // `AccessAssignment.role` is declared `onDelete: Cascade`, so the
        // database takes the grants with the role. Without this the mock
        // certified an orphan the real schema cannot produce.
        for (let i = assignments.length - 1; i >= 0; i--) {
          if (assignments[i]?.roleId === where.id) assignments.splice(i, 1)
        }
        return { count }
      }),
    },
    accessAssignment: {
      // `roleId` is honoured. It used to be ignored, so any `where` naming a
      // role matched every row for the subject - which would have reported an
      // unrelated grant as an existing one.
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
      // The reference schema declares `@@unique([subjectId, roleId, scope])`.
      // The mock used to accept any `create`, so a duplicate assignment looked
      // fine here and raised P2002 in production - the mock was the reason CI
      // could not see it.
      create: vi.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row = data as unknown as AssignmentRow
        // `AccessAssignment.role` is a required relation, so the real client
        // raises P2003 for a grant naming a role that does not exist. A mock
        // that accepts one lets this suite certify behaviour no real database
        // has.
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
runAdapterCompliance('IamPrismaAdapter', () => new IamPrismaAdapter(makePrismaMock()))

/**
 * Stores a role so an assignment naming it is legal.
 *
 * `AccessAssignment.role` is a required relation, so a grant naming a role the
 * table does not hold raises `P2003` - on the mock as on the real client.
 *
 * @param prisma - The mock client to seed.
 * @param ids - Role ids to store.
 */
async function seedRoles(prisma: ReturnType<typeof makePrismaMock>, ...ids: string[]): Promise<void> {
  for (const id of ids) {
    await prisma.accessRole.upsert({ create: { id, name: id, permissions: [] }, where: { id } })
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

    // This suite only ever deleted a row it had just created, which is why the
    // `delete`-vs-`deleteMany` divergence survived: Prisma's `delete` raises
    // `P2025` when nothing matches, so an idempotent admin retry succeeded on
    // the other five adapters and threw here.
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

    /**
     * The write path still sends `[]` for a role with no parents - the column
     * needs a value - but the *read* path no longer invents one. `toRole` used
     * to return `inherits: []` plus `description`/`scope`/`metadata` as keys
     * holding `undefined`, so a role saved as `{id, name, permissions}` came
     * back from prisma with seven keys and from memory with three: `Object.keys`
     * disagreed, `'inherits' in role` disagreed, and a consumer branching on
     * either got two answers from one write.
     *
     * Drizzle's `_safeParseRole` already omits both, with a docstring saying
     * why, and `RoleBuilder.build()` omits `inherits` when the author names no
     * parents - so absent is the shape both ends of the round trip already
     * agreed on, and prisma was the one store that did not.
     */
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

    /**
     * `assignRole` used a bare `create` against `@@unique([subjectId, roleId,
     * scope])`. A repeat *scoped* grant raised `P2002`, so re-running a
     * provisioning script failed on Prisma alone; a repeat *unscoped* one did
     * not even do that, because SQL unique indexes do not collapse `NULL`s, so
     * the row was inserted again and the table grew without bound. The other
     * five adapters are all explicitly idempotent.
     */
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

    // Control: idempotence must not collapse grants that differ. A scoped and
    // an unscoped grant of the same role are two rows, and two scopes are two
    // rows - without this the assertions above would also pass on an
    // `assignRole` that simply stopped writing after the first call.
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

    // Was: `''` targets only the empty scope rather than all scopes. `''` is now
    // refused at the shared boundary, so the stronger property holds - it
    // revokes nothing because it never runs.
    it('revokeRole refuses an empty-string scope and leaves both grants standing', async () => {
      await adapter.assignRole('user-1', 'editor' as Ro)
      await adapter.assignRole('user-1', 'editor' as Ro, 'org-1')
      await expect(adapter.revokeRole('user-1', 'editor' as Ro, '' as S)).rejects.toThrow(/must not be an empty string/)
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

/**
 * The shipped mock is the only Prisma the suite ever sees, so a mock more
 * forgiving than the driver makes real divergences invisible by construction.
 * These pin the two ways it used to be wrong.
 */
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
    // Without the `findMany` pre-check in `assignRole` this second call reaches
    // `create` and raises P2002 - which is exactly what production did.
    await expect(adapter.assignRole('user-1', 'editor')).resolves.toBeUndefined()
    expect(await adapter.getSubjectRoles('user-1')).toEqual(['editor'])
  })

  it('interprets `NOT` in a deleteMany where-clause', async () => {
    const prisma = makePrismaMock()
    await seedRoles(prisma, 'editor')
    await prisma.accessAssignment.create({ data: { roleId: 'editor', scope: 'org-1', subjectId: 'user-1' } })
    await prisma.accessAssignment.create({ data: { roleId: 'editor', scope: 'org-2', subjectId: 'user-1' } })
    // The clause `updateAssignmentScope` sends: drop the row already sitting on
    // the target scope, but never the source row it is about to move.
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
