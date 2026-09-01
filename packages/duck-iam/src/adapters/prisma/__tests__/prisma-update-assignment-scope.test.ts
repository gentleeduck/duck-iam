/**
 * `updateAssignmentScope` moves an existing grant in place - one write instead of
 * revoke + assign - so the row keeps its `id`/`createdAt`. Returning `false` is the
 * signal the engine uses to fall back to revoke + assign.
 */
import { describe, expect, it, vi } from 'vitest'
import { IamPrismaAdapter } from '../index'

type Ro = 'viewer' | 'editor'
type S = 'org-1' | 'org-2'

interface AssignmentRow {
  id: string
  subjectId: string
  roleId: string
  scope: string | null
  createdAt: number
}

/** Matches a Prisma `where` object supporting equality plus a single `NOT` block. */
function matches(row: AssignmentRow, where: Record<string, unknown>): boolean {
  for (const [key, value] of Object.entries(where)) {
    if (key === 'NOT') {
      const not = value as Record<string, unknown>
      const negated = Object.entries(not).every(([k, v]) => (row as unknown as Record<string, unknown>)[k] === v)
      if (negated) return false
      continue
    }
    if ((row as unknown as Record<string, unknown>)[key] !== value) return false
  }
  return true
}

function makeMock(seed: Array<Omit<AssignmentRow, 'id' | 'createdAt'>> = []) {
  let nextId = 1
  const assignments: AssignmentRow[] = seed.map((row) => ({ ...row, createdAt: 1_000, id: `a${nextId++}` }))

  const prisma = {
    accessAssignment: {
      create: vi.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row = { ...data, createdAt: 1_000, id: `a${nextId++}` } as unknown as AssignmentRow
        assignments.push(row)
        return row
      }),
      deleteMany: vi.fn(async ({ where }: { where: Record<string, unknown> }) => {
        const before = assignments.length
        for (let i = assignments.length - 1; i >= 0; i--) {
          if (matches(assignments[i]!, where)) assignments.splice(i, 1)
        }
        return { count: before - assignments.length }
      }),
      findMany: vi.fn(async ({ where }: { where: Record<string, unknown> }) =>
        assignments.filter((a) => matches(a, where)),
      ),
      updateMany: vi.fn(async ({ where, data }: { where: Record<string, unknown>; data: Record<string, unknown> }) => {
        let count = 0
        for (const a of assignments) {
          if (!matches(a, where)) continue
          Object.assign(a, data)
          count++
        }
        return { count }
      }),
    },
    accessPolicy: { delete: vi.fn(), findMany: vi.fn(), findUnique: vi.fn(), upsert: vi.fn() },
    accessRole: { delete: vi.fn(), findMany: vi.fn(), findUnique: vi.fn(), upsert: vi.fn() },
    accessSubjectAttr: { findUnique: vi.fn(), upsert: vi.fn() },
  }

  return { adapter: new IamPrismaAdapter<'read', 'post', Ro, S>(prisma), assignments }
}

describe('IamPrismaAdapter.updateAssignmentScope', () => {
  it('moves the row to the new scope in place, preserving its id', async () => {
    const { adapter, assignments } = makeMock([{ roleId: 'editor', scope: 'org-1', subjectId: 'sub-1' }])
    const moved = await adapter.updateAssignmentScope('sub-1', 'editor', 'org-1', 'org-2')
    expect(moved).toBe(true)
    expect(assignments).toHaveLength(1)
    expect(assignments[0]).toMatchObject({ id: 'a1', scope: 'org-2' })
  })

  it('moves a global (unscoped) assignment, matching scope NULL', async () => {
    const { adapter, assignments } = makeMock([{ roleId: 'editor', scope: null, subjectId: 'sub-1' }])
    const moved = await adapter.updateAssignmentScope('sub-1', 'editor', undefined, 'org-2')
    expect(moved).toBe(true)
    expect(assignments[0]?.scope).toBe('org-2')
  })

  it('moves a scoped assignment back to global', async () => {
    const { adapter, assignments } = makeMock([{ roleId: 'editor', scope: 'org-1', subjectId: 'sub-1' }])
    const moved = await adapter.updateAssignmentScope('sub-1', 'editor', 'org-1', undefined)
    expect(moved).toBe(true)
    expect(assignments[0]?.scope).toBeNull()
  })

  it('drops the source row instead of colliding when the target scope is already granted', async () => {
    const { adapter, assignments } = makeMock([
      { roleId: 'editor', scope: 'org-1', subjectId: 'sub-1' },
      { roleId: 'editor', scope: 'org-2', subjectId: 'sub-1' },
    ])
    const moved = await adapter.updateAssignmentScope('sub-1', 'editor', 'org-1', 'org-2')
    expect(moved).toBe(true)
    expect(assignments).toHaveLength(1)
    expect(assignments[0]?.scope).toBe('org-2')
  })

  it('returns false when no assignment matches the source scope', async () => {
    const { adapter } = makeMock([{ roleId: 'editor', scope: 'org-2', subjectId: 'sub-1' }])
    expect(await adapter.updateAssignmentScope('sub-1', 'editor', 'org-1', 'org-2')).toBe(false)
  })

  it('returns false for a subject with no assignments at all', async () => {
    const { adapter } = makeMock()
    expect(await adapter.updateAssignmentScope('nobody', 'editor', 'org-1', 'org-2')).toBe(false)
  })

  it('leaves other subjects untouched', async () => {
    const { adapter, assignments } = makeMock([
      { roleId: 'editor', scope: 'org-1', subjectId: 'sub-1' },
      { roleId: 'editor', scope: 'org-1', subjectId: 'sub-2' },
    ])
    await adapter.updateAssignmentScope('sub-1', 'editor', 'org-1', 'org-2')
    expect(assignments.find((a) => a.subjectId === 'sub-2')?.scope).toBe('org-1')
  })

  it('leaves other roles of the same subject untouched', async () => {
    const { adapter, assignments } = makeMock([
      { roleId: 'editor', scope: 'org-1', subjectId: 'sub-1' },
      { roleId: 'viewer', scope: 'org-1', subjectId: 'sub-1' },
    ])
    await adapter.updateAssignmentScope('sub-1', 'editor', 'org-1', 'org-2')
    expect(assignments.find((a) => a.roleId === 'viewer')?.scope).toBe('org-1')
  })

  it('is a no-op that still reports true when from and to scope are equal', async () => {
    const { adapter, assignments } = makeMock([{ roleId: 'editor', scope: 'org-1', subjectId: 'sub-1' }])
    const moved = await adapter.updateAssignmentScope('sub-1', 'editor', 'org-1', 'org-1')
    expect(moved).toBe(true)
    expect(assignments).toHaveLength(1)
    expect(assignments[0]?.scope).toBe('org-1')
  })

  it('the moved grant is visible through getSubjectScopedRoles afterwards', async () => {
    const { adapter } = makeMock([{ roleId: 'editor', scope: 'org-1', subjectId: 'sub-1' }])
    await adapter.updateAssignmentScope('sub-1', 'editor', 'org-1', 'org-2')
    expect(await adapter.getSubjectScopedRoles('sub-1')).toEqual([{ role: 'editor', scope: 'org-2' }])
  })
})

/**
 * The conflict cleanup on the target scope must only run once the source row is
 * known to exist - otherwise a stale `fromScope` destroys the grant the caller
 * was moving *onto* and reports `false` as if nothing happened.
 */
describe('updateAssignmentScope source check', () => {
  it('leaves the target-scope row untouched when the source scope has no row', async () => {
    const { adapter, assignments } = makeMock([{ roleId: 'editor', scope: 'org-2', subjectId: 'sub-1' }])
    const moved = await adapter.updateAssignmentScope('sub-1', 'editor', 'org-1', 'org-2')
    expect(moved).toBe(false)
    expect(assignments).toHaveLength(1)
    expect(assignments[0]).toMatchObject({ scope: 'org-2' })
  })

  it('accepts the contract-level optional actor argument', async () => {
    const { adapter, assignments } = makeMock([{ roleId: 'editor', scope: 'org-1', subjectId: 'sub-1' }])
    const moved = await adapter.updateAssignmentScope('sub-1', 'editor', 'org-1', 'org-2', 'admin-1')
    expect(moved).toBe(true)
    expect(assignments[0]).toMatchObject({ scope: 'org-2' })
  })
})
