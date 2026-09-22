/**
 * A corrupt role row is dropped and the rest kept; the engine reports the grants and targets left naming it.
 * SECURITY: a corrupt policy row throws; any policy may deny (even allow-only under `policyCombine: 'and'`).
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

describe('IamPrismaAdapter malformed-row handling', () => {
  it('listPolicies keeps a well-formed row (control)', async () => {
    const adapter = makeMock([goodPolicy])
    expect((await adapter.listPolicies()).map((p) => p.id)).toEqual(['good'])
  })

  it('listPolicies refuses a row whose algorithm is not a combining algorithm', async () => {
    const adapter = makeMock([goodPolicy, { ...goodPolicy, algorithm: 'not-an-algorithm', id: 'bad' }])
    // SECURITY: not `['good']` - returning the readable half would drop a possible deny with no signal.
    await expect(adapter.listPolicies()).rejects.toThrow(/policy "bad" cannot be read and will not be skipped/)
  })

  it('listPolicies refuses a row whose rules column is not an array', async () => {
    const adapter = makeMock([goodPolicy, { ...goodPolicy, id: 'bad', rules: { not: 'an array' } }])
    await expect(adapter.listPolicies()).rejects.toThrow(/cannot be read/)
  })

  it('listPolicies refuses a row whose rules column is a raw JSON string, not parsed JSON', async () => {
    // INFO: Prisma returns `Json` already parsed, so a string is corruption. Read loosely,
    // `'[]'` would be a policy with no rules that denies nothing.
    const adapter = makeMock([goodPolicy, { ...goodPolicy, id: 'bad', rules: '[]' }])
    await expect(adapter.listPolicies()).rejects.toThrow(/cannot be read/)
  })

  it('getPolicy throws for a row that fails validation, rather than reading as absent', async () => {
    const adapter = makeMock([{ ...goodPolicy, algorithm: 'not-an-algorithm', id: 'bad' }])
    // SECURITY: `null` means "no such policy"; a corrupt row must not pass as a deleted one.
    await expect(adapter.getPolicy('bad')).rejects.toThrow(/cannot be read/)
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
