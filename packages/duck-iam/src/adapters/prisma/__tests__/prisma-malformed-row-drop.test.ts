/**
 * A Prisma `Json` column can desync from the row shape via a partial migration or a
 * manual SQL edit. The adapter must validate and drop the bad row instead of letting
 * it escape into the evaluator, and must keep the clean rows around it.
 */
import { describe, expect, it, vi } from 'vitest'
import { IamPrismaAdapter } from '../index'

type Row = Record<string, unknown>

const goodPolicy: Row = {
  algorithm: 'deny-overrides',
  description: null,
  id: 'good',
  name: 'Good',
  rules: [],
  targets: null,
  version: 1,
}

const goodRole: Row = {
  description: null,
  id: 'good',
  inherits: [],
  metadata: null,
  name: 'Good',
  permissions: [],
  scope: null,
}

function makeMock(policies: Row[] = [], roles: Row[] = []) {
  const prisma = {
    accessAssignment: { create: vi.fn(), deleteMany: vi.fn(), findMany: vi.fn(), updateMany: vi.fn() },
    accessPolicy: {
      delete: vi.fn(),
      findMany: vi.fn(async () => policies),
      findUnique: vi.fn(
        async ({ where }: { where: { id: string } }) => policies.find((p) => p.id === where.id) ?? null,
      ),
      upsert: vi.fn(),
    },
    accessRole: {
      delete: vi.fn(),
      findMany: vi.fn(async () => roles),
      findUnique: vi.fn(async ({ where }: { where: { id: string } }) => roles.find((r) => r.id === where.id) ?? null),
      upsert: vi.fn(),
    },
    accessSubjectAttr: { findUnique: vi.fn(), upsert: vi.fn() },
  }
  return new IamPrismaAdapter(prisma as never)
}

describe('IamPrismaAdapter malformed-row drop', () => {
  it('listPolicies keeps a well-formed row (control)', async () => {
    const adapter = makeMock([goodPolicy])
    expect((await adapter.listPolicies()).map((p) => p.id)).toEqual(['good'])
  })

  it('listPolicies drops a row whose algorithm is not a combining algorithm', async () => {
    const adapter = makeMock([goodPolicy, { ...goodPolicy, algorithm: 'not-an-algorithm', id: 'bad' }])
    expect((await adapter.listPolicies()).map((p) => p.id)).toEqual(['good'])
  })

  it('listPolicies drops a row whose rules column is not an array', async () => {
    const adapter = makeMock([goodPolicy, { ...goodPolicy, id: 'bad', rules: { not: 'an array' } }])
    expect((await adapter.listPolicies()).map((p) => p.id)).toEqual(['good'])
  })

  it('listPolicies drops a row whose rules column is a raw JSON string, not parsed JSON', async () => {
    // Prisma hands back already-parsed JSON; a TEXT column migrated in from
    // another adapter arrives as a string and must not be trusted.
    const adapter = makeMock([goodPolicy, { ...goodPolicy, id: 'bad', rules: '[]' }])
    expect((await adapter.listPolicies()).map((p) => p.id)).toEqual(['good'])
  })

  it('getPolicy returns null for a row that fails validation', async () => {
    const adapter = makeMock([{ ...goodPolicy, algorithm: 'not-an-algorithm', id: 'bad' }])
    expect(await adapter.getPolicy('bad')).toBeNull()
  })

  it('listRoles keeps a well-formed row (control)', async () => {
    const adapter = makeMock([], [goodRole])
    expect((await adapter.listRoles()).map((r) => r.id)).toEqual(['good'])
  })

  it('listRoles drops a row whose permissions column is not an array', async () => {
    const adapter = makeMock([], [goodRole, { ...goodRole, id: 'bad', permissions: 'read:post' }])
    expect((await adapter.listRoles()).map((r) => r.id)).toEqual(['good'])
  })

  it('listRoles drops a row whose inherits column holds a non-string entry', async () => {
    const adapter = makeMock([], [goodRole, { ...goodRole, id: 'bad', inherits: [42] }])
    expect((await adapter.listRoles()).map((r) => r.id)).toEqual(['good'])
  })

  it('getRole returns null for a row that fails validation', async () => {
    const adapter = makeMock([], [{ ...goodRole, id: 'bad', permissions: 'read:post' }])
    expect(await adapter.getRole('bad')).toBeNull()
  })
})
