import { describe, expect, it, vi } from 'vitest'
import { type IamPrisma, IamPrismaAdapter } from '../index'

// `withClient` must send reads and writes to the rebound client, never the base one.
// Under a `return this` mutant a write inside `$transaction` commits even when the caller rolls back.
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
    // The half a `return this` mutant, or an adapter writing to both clients, fails.
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
    // A new adapter, not a mutated one, so a transaction cannot hijack the engine's shared instance.
    const base = makeClient()
    const tx = makeClient()
    const adapter = new IamPrismaAdapter(base.client)

    expect(adapter.withClient(tx.client)).not.toBe(adapter)
  })
})
