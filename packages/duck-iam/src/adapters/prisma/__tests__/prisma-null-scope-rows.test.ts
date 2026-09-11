import { describe, expect, it, vi } from 'vitest'
import { IamPrismaAdapter } from '../index'

// `getSubjectScopedRoles` must skip unscoped (`scope: null`) rows, not emit them with a null scope.
// A null scope in that list matches nothing and hides a global grant.
function makeAdapter(assignments: Array<{ roleId: string; scope: string | null; subjectId: string }>) {
  const prisma = {
    accessAssignment: {
      create: vi.fn(),
      deleteMany: vi.fn(),
      // `getSubjectRoles` filters `scope: null` in the query; `getSubjectScopedRoles` splits rows itself,
      // so the fake honours both.
      findMany: vi.fn(async ({ where }: { where: { scope?: null; subjectId: string } }) =>
        assignments.filter((a) => a.subjectId === where.subjectId && (where.scope === null ? a.scope === null : true)),
      ),
      updateMany: vi.fn(),
    },
    accessPolicy: { delete: vi.fn(), findMany: vi.fn(), findUnique: vi.fn(), upsert: vi.fn() },
    accessRole: { delete: vi.fn(), findMany: vi.fn(), findUnique: vi.fn(), upsert: vi.fn() },
    accessSubjectAttr: { findUnique: vi.fn(), upsert: vi.fn() },
  }
  return new IamPrismaAdapter(prisma as never)
}

describe('prisma getSubjectScopedRoles', () => {
  it('returns the scoped rows (control)', async () => {
    const adapter = makeAdapter([
      { roleId: 'editor', scope: 'org-1', subjectId: 'u1' },
      { roleId: 'viewer', scope: 'org-2', subjectId: 'u1' },
    ])
    expect(await adapter.getSubjectScopedRoles('u1')).toEqual([
      { role: 'editor', scope: 'org-1' },
      { role: 'viewer', scope: 'org-2' },
    ])
  })

  it('skips the unscoped rows rather than emitting a null scope', async () => {
    const adapter = makeAdapter([
      { roleId: 'admin', scope: null, subjectId: 'u1' },
      { roleId: 'editor', scope: 'org-1', subjectId: 'u1' },
    ])
    const scoped = await adapter.getSubjectScopedRoles('u1')
    expect(scoped).toEqual([{ role: 'editor', scope: 'org-1' }])
    expect(scoped.map((s) => s.scope)).not.toContain(null)
  })

  it('returns nothing when every grant is unscoped', async () => {
    const adapter = makeAdapter([
      { roleId: 'admin', scope: null, subjectId: 'u1' },
      { roleId: 'viewer', scope: null, subjectId: 'u1' },
    ])
    expect(await adapter.getSubjectScopedRoles('u1')).toEqual([])
  })

  // The unscoped list is the other half of the same split: an unscoped grant
  // has to appear in exactly one of the two.
  it('reports the unscoped grants through getSubjectRoles', async () => {
    const adapter = makeAdapter([
      { roleId: 'admin', scope: null, subjectId: 'u1' },
      { roleId: 'editor', scope: 'org-1', subjectId: 'u1' },
    ])
    expect(await adapter.getSubjectRoles('u1')).toEqual(['admin'])
  })
})
