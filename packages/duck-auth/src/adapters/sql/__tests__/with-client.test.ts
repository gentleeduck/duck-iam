import Database from 'better-sqlite3'
import { drizzle } from 'drizzle-orm/better-sqlite3'
import { describe, expect, it } from 'vitest'
import { createDrizzleSqliteBridge } from '~/adapters/drizzle/sqlite'
import { MemoryAdapter } from '~/adapters/memory'
import { createSqlStores } from '~/adapters/sql'

type P = { username: string; email: string }

/**
 * No schema is applied on purpose: `withClient` is pure construction, so these
 * assertions need the wiring, not the tables. Behaviour against real tables is
 * covered by the compliance suites and the pg e2e suite.
 */
const client = () => drizzle(new Database(':memory:'))

describe('withClient', () => {
  it('every sql store exposes it', () => {
    const stores = createSqlStores<P>(createDrizzleSqliteBridge<P>(client()))

    expect(stores.identities.withClient).toBeTypeOf('function')
    expect(stores.sessions.withClient).toBeTypeOf('function')
    expect(stores.credentials.withClient).toBeTypeOf('function')
  })

  it('returns a distinct store, never the original', () => {
    const stores = createSqlStores<P>(createDrizzleSqliteBridge<P>(client()))
    const rebound = stores.identities.withClient?.(client())

    expect(rebound).toBeDefined()
    expect(rebound).not.toBe(stores.identities)
    // Re-binding must not mutate the store it was called on.
    expect(stores.identities.withClient).toBeTypeOf('function')
  })

  it('the rebound store carries the full interface, not a partial', () => {
    const stores = createSqlStores<P>(createDrizzleSqliteBridge<P>(client()))
    const rebound = stores.identities.withClient?.(client())

    for (const method of ['findById', 'findByEmail', 'create', 'update', 'softDelete', 'erase', 'link', 'merge']) {
      expect(rebound?.[method as keyof typeof rebound]).toBeTypeOf('function')
    }
    expect(rebound?.withClient).toBeTypeOf('function')
  })

  it('memory adapter stores deliberately do NOT expose it', () => {
    const mem = new MemoryAdapter<P>()

    expect(mem.identities.withClient).toBeUndefined()
    expect(mem.sessions.withClient).toBeUndefined()
    expect(mem.credentials.withClient).toBeUndefined()
  })
})
