import { describe, expect, it, vi } from 'vitest'
import { type IamPrisma, IamPrismaAdapter } from '../index'

/**
 * `withClient` is how an adapter joins a caller's transaction: the engine hands
 * back the opaque driver handle it was given, and the adapter re-makes itself
 * against it. drizzle has `with-client.test.ts` for exactly this; prisma's copy
 * was named by no test at any level, and `engine.ts` points operators at prisma
 * *because* it is the transactional one.
 *
 * The property that matters is not that a different object comes back - a
 * `return this` mutant satisfies that, and satisfies a conformance clause that
 * only checks `typeof withClient === 'function'`. It is that the write lands on
 * the rebound client and nowhere near the original. Under `return this` the
 * insert goes to the base client, so a write inside `$transaction` commits even
 * when the caller rolls back.
 */
type Row = Record<string, unknown>

/** A client stand-in that records the assignment rows written through it. */
function makeClient(): { client: IamPrisma.ILike; created: Row[] } {
  const created: Row[] = []
  const client: IamPrisma.ILike = {
    accessAssignment: {
      create: vi.fn(async ({ data }: { data: Row }) => {
        created.push(data)
        return { createdAt: 0, id: 'a1', roleId: '', scope: null, subjectId: '' }
      }),
      deleteMany: vi.fn(async () => ({ count: 0 })),
      findMany: vi.fn(async () => []),
      updateMany: vi.fn(async () => ({ count: 0 })),
    },
    accessPolicy: {
      deleteMany: vi.fn(async () => ({ count: 0 })),
      findMany: vi.fn(async () => []),
      findUnique: vi.fn(async () => null),
      upsert: vi.fn(),
    },
    accessRole: {
      deleteMany: vi.fn(async () => ({ count: 0 })),
      findMany: vi.fn(async () => []),
      findUnique: vi.fn(async () => null),
      upsert: vi.fn(),
    },
    accessSubjectAttr: { findUnique: vi.fn(async () => null), upsert: vi.fn() },
  }
  return { client, created }
}

describe('IamPrismaAdapter.withClient rebinds writes onto the given client', () => {
  it('the write lands on the transaction client', async () => {
    const base = makeClient()
    const tx = makeClient()

    await new IamPrismaAdapter(base.client).withClient(tx.client).assignRole('u1', 'editor')

    expect(tx.created).toEqual([{ roleId: 'editor', scope: null, subjectId: 'u1' }])
  })

  it('and never on the client the adapter was built with', async () => {
    // The half a `return this` mutant fails. Asserting only the line above
    // would pass for an adapter that wrote to both, or to the wrong one while
    // some other test seeded the right one.
    const base = makeClient()
    const tx = makeClient()

    await new IamPrismaAdapter(base.client).withClient(tx.client).assignRole('u1', 'editor')

    expect(base.created).toEqual([])
    expect(base.client.accessAssignment.create).not.toHaveBeenCalled()
  })

  it('reads go to the rebound client too, not just writes', async () => {
    const base = makeClient()
    const tx = makeClient()

    await new IamPrismaAdapter(base.client).withClient(tx.client).listPolicies()

    expect(tx.client.accessPolicy.findMany).toHaveBeenCalled()
    expect(base.client.accessPolicy.findMany).not.toHaveBeenCalled()
  })

  it('the original adapter is unaffected and still writes to its own client', () => {
    // `withClient` returns a new adapter rather than mutating this one, so a
    // transaction cannot hijack the shared instance the engine holds.
    const base = makeClient()
    const tx = makeClient()
    const adapter = new IamPrismaAdapter(base.client)

    expect(adapter.withClient(tx.client)).not.toBe(adapter)
  })
})
