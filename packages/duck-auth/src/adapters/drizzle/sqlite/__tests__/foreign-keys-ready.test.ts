/**
 * `pragma foreign_keys = on` was issued fire-and-forget. A raw driver has it set synchronously through
 * `exec` before drizzle wraps it, but the constructor also takes a drizzle handle you already have, and
 * for an async one the pragma was still in flight when the first query went out — with foreign keys off,
 * which is the state the pragma's own SECURITY comment says leaves dangling links behind.
 */
import { describe, expect, it } from 'vitest'
import { DrizzleSqliteAdapter } from '../sqlite'

/** A drizzle select chain that answers no rows, however it is walked: every builder method returns another
 *  link, and awaiting any of them yields an empty result. */
function chain(): PromiseLike<unknown[]> {
  const base: PromiseLike<unknown[]> = { then: (onfulfilled) => Promise.resolve([]).then(onfulfilled) }
  return new Proxy(base, { get: (target, prop) => (prop === 'then' ? target.then : () => chain()) })
}

/** A drizzle handle whose first `run` — the pragma — only settles when the test says so. */
function gatedHandle() {
  let release!: () => void
  const gate = new Promise<void>((r) => {
    release = r
  })
  const order: string[] = []
  let pragmaIssued = false
  const handle = {
    resultKind: 'async',
    run: async () => {
      if (pragmaIssued) return []
      pragmaIssued = true
      order.push('pragma:start')
      await gate
      order.push('pragma:done')
      return []
    },
    select: () => {
      order.push('query')
      return chain()
    },
  }
  return { handle, order, release }
}

describe('the sqlite adapter waits for foreign keys before it answers', () => {
  it('issues no query until the pragma has settled', async () => {
    const { handle, order, release } = gatedHandle()
    const adapter = new DrizzleSqliteAdapter(handle as never)

    const pending = adapter.identities.find({ id: 'missing' }).catch(() => null)
    // Several turns, so anything that was going to run without awaiting the pragma has run by now.
    for (let i = 0; i < 8; i++) await Promise.resolve()
    expect(order).toEqual(['pragma:start'])

    release()
    await pending
    expect(order).toEqual(['pragma:start', 'pragma:done', 'query'])
  })

  it('fails the operation when the pragma itself failed, rather than serving it unenforced', async () => {
    const handle = {
      resultKind: 'async',
      run: async () => {
        throw new Error('pragma refused')
      },
      select: () => chain(),
    }
    const adapter = new DrizzleSqliteAdapter(handle as never)

    await expect(adapter.identities.find({ id: 'missing' })).rejects.toMatchObject({ code: 'AUTH_ADAPTER_FAILED' })
  })
})
