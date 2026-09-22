import { describe, expect, it } from 'vitest'
import { IamPrismaAdapter } from '../index'

type A = 'read'
type R = 'post'
type Ro = 'viewer'
type S = 'org-1'

interface UpsertArgs {
  where: { id: string }
  create: Record<string, unknown>
  update: Record<string, unknown>
}

/** A store that applies `create` on insert and `update` on conflict, like a real Prisma `upsert`. */
function makeStore() {
  const rows = new Map<string, Record<string, unknown>>()
  const calls: UpsertArgs[] = []
  const model = {
    findUnique: async ({ where }: { where: { id: string } }) => rows.get(where.id) ?? null,
    upsert: async (args: UpsertArgs) => {
      calls.push(args)
      const prev = rows.get(args.where.id)
      const next = prev ? { ...prev, ...args.update } : args.create
      rows.set(args.where.id, next)
      return next
    },
  }
  return { calls, model, rows }
}

function makeAdapter() {
  const policy = makeStore()
  const role = makeStore()
  // A partial client: only the two definition writes are driven.
  const prisma = { accessPolicy: policy.model, accessRole: role.model }
  const adapter = new IamPrismaAdapter<A, R, Ro, S>(prisma as never)
  return { adapter, policy, role }
}

// `created_by` goes on insert and `updated_by` on overwrite; swapping them names the last editor as the author.
describe('prisma definition writes record their author', () => {
  it('savePolicy stamps created_by on insert and updated_by on overwrite', async () => {
    const { adapter, policy } = makeAdapter()

    await adapter.savePolicy({ algorithm: 'first-match', id: 'p1', name: 'P', rules: [] }, { actor: 'author-1' })
    await adapter.savePolicy({ algorithm: 'first-match', id: 'p1', name: 'P edited', rules: [] }, { actor: 'editor-2' })

    const stored = policy.rows.get('p1')
    expect(stored?.name).toBe('P edited')
    // The author must not move to whoever edited last.
    expect(stored?.createdBy).toBe('author-1')
    expect(stored?.updatedBy).toBe('editor-2')
    // Neither half may carry the other's column, or a first write records an editor.
    expect('updatedBy' in (policy.calls[0]?.create ?? {})).toBe(false)
    expect('createdBy' in (policy.calls[0]?.update ?? {})).toBe(false)
  })

  it('saveRole does the same', async () => {
    const { adapter, role } = makeAdapter()

    await adapter.saveRole({ id: 'viewer', name: 'V', permissions: [] }, { actor: 'author-1' })
    await adapter.saveRole({ id: 'viewer', name: 'V edited', permissions: [] }, { actor: 'editor-2' })

    const stored = role.rows.get('viewer')
    expect(stored?.name).toBe('V edited')
    expect(stored?.createdBy).toBe('author-1')
    expect(stored?.updatedBy).toBe('editor-2')
  })

  it('records no author at all when the caller supplies none', async () => {
    const { adapter, policy } = makeAdapter()

    await adapter.savePolicy({ algorithm: 'first-match', id: 'p1', name: 'P', rules: [] })

    const stored = policy.rows.get('p1')
    expect('createdBy' in (stored ?? {})).toBe(false)
    expect('updatedBy' in (stored ?? {})).toBe(false)
  })
})
