/**
 * A Prisma `Json` column can desync from the row shape via a partial migration
 * or a manual SQL edit. The adapter must validate it and never let it escape
 * into the evaluator - but what it does next depends on which table the row
 * came from.
 *
 * A *role* row is dropped and the clean rows around it are kept: role
 * permissions are allow-only, so losing one can only remove a grant.
 *
 * A *policy* row is reported and then throws. The row that will not parse may
 * have been the rule saying NO, and dropping it turns a corrupt byte into an
 * allow; under `policyCombine: 'and'` even an allow-only policy votes deny
 * when none of its rules match, so there is no subset of policies an adapter
 * can safely drop without knowing a combine mode it cannot see. One unreadable
 * policy row denies every request until it is repaired - that cost is the
 * point, not an oversight.
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
    // Not `['good']`. Handing back the readable half is the fail-open: the
    // caller gets a policy set with a deny quietly subtracted and no signal
    // that one was ever there.
    await expect(adapter.listPolicies()).rejects.toThrow(/policy "bad" cannot be read and will not be skipped/)
  })

  it('listPolicies refuses a row whose rules column is not an array', async () => {
    const adapter = makeMock([goodPolicy, { ...goodPolicy, id: 'bad', rules: { not: 'an array' } }])
    await expect(adapter.listPolicies()).rejects.toThrow(/cannot be read/)
  })

  it('listPolicies refuses a row whose rules column is a raw JSON string, not parsed JSON', async () => {
    // Prisma hands back already-parsed JSON; a TEXT column migrated in from
    // another adapter arrives as a string and must not be trusted. `'[]'` is
    // the nastiest shape of this bug: read loosely it looks like a policy with
    // no rules, which under `deny-overrides` is a policy that denies nothing.
    const adapter = makeMock([goodPolicy, { ...goodPolicy, id: 'bad', rules: '[]' }])
    await expect(adapter.listPolicies()).rejects.toThrow(/cannot be read/)
  })

  it('getPolicy throws for a row that fails validation, rather than reading as absent', async () => {
    const adapter = makeMock([{ ...goodPolicy, algorithm: 'not-an-algorithm', id: 'bad' }])
    // `null` is the answer for "no such policy" - the same shape a deleted row
    // takes. A corrupt row must not be able to impersonate a deleted one.
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
