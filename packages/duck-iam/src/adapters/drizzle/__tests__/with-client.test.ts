/**
 * `withClient` is how an adapter joins a caller's transaction: the engine hands
 * back the opaque driver handle it was given, and the adapter - the only layer
 * that knows what a drizzle db actually is - re-makes itself against it.
 *
 * Returning a *different* object is not the property that matters; writing to
 * the *new* client is. These tests assert the write lands on the rebound
 * client's tables and nowhere near the original's.
 */
import { describe, expect, it } from 'vitest'
import type { IamAdapter } from '../../../core/types/adapter'
import { IamMemoryAdapter } from '../../memory'
import { type IamDrizzle, IamDrizzleAdapter } from '../index'

type Row = Record<string, unknown>

/** A db stand-in that records the rows `assignRole` inserts. */
function makeDb(): { db: IamDrizzle.AnyDrizzleDb; rows: Row[] } {
  const rows: Row[] = []
  const db: IamDrizzle.AnyDrizzleDb = {
    delete: () => ({ where: () => Promise.resolve() }),
    insert: () => ({
      values: (data: Row) => ({
        onConflictDoNothing: () => {
          rows.push(data)
          return Promise.resolve()
        },
      }),
    }),
    select: () => ({ from: () => ({ where: () => Promise.resolve([]) }) }),
    update: () => ({ set: () => ({ where: () => Promise.resolve() }) }),
  }
  return { db, rows }
}

const TABLES = {
  assignments: { roleId: { __col: 'roleId' }, scope: { __col: 'scope' }, subjectId: { __col: 'subjectId' } },
  attrs: {},
  policies: {},
  roles: {},
} as unknown as IamDrizzle.IConfig<IamDrizzle.AnyDrizzleDb, 'pg'>['tables']

const OPS = { and: () => undefined, eq: () => ({}) } satisfies IamDrizzle.IConfig<IamDrizzle.AnyDrizzleDb, 'pg'>['ops']

describe('IamAdapter.withClient', () => {
  it('the memory adapter deliberately does not implement it', () => {
    // Not an oversight: an in-memory Map has no transaction to join, so the
    // engine must refuse rather than leave the writes outside the caller's tx.
    // Typed as the interface, because that is what a consumer holds.
    const adapter: IamAdapter.IAdapter = new IamMemoryAdapter()

    expect(adapter.withClient).toBeUndefined()
  })

  it('the drizzle adapter exposes it', () => {
    const { db } = makeDb()
    const adapter = new IamDrizzleAdapter<'read', 'post', 'editor', 'org-1'>({ db, ops: OPS, tables: TABLES })

    expect(adapter.withClient).toBeTypeOf('function')
  })

  it('writes on the rebound adapter land on the new client, not the original', async () => {
    const original = makeDb()
    const other = makeDb()
    const adapter = new IamDrizzleAdapter<'read', 'post', 'editor', 'org-1'>({
      db: original.db,
      ops: OPS,
      tables: TABLES,
    })

    const bound = adapter.withClient(other.db)
    await bound.assignRole('u1', 'editor', 'org-1')

    expect(other.rows).toEqual([
      { attributes: null, expiresAt: null, roleId: 'editor', scope: 'org-1', startsAt: null, subjectId: 'u1' },
    ])
    expect(original.rows).toEqual([])
  })

  it('the original adapter keeps writing to its own client after a rebind', async () => {
    const original = makeDb()
    const other = makeDb()
    const adapter = new IamDrizzleAdapter<'read', 'post', 'editor', 'org-1'>({
      db: original.db,
      ops: OPS,
      tables: TABLES,
    })

    adapter.withClient(other.db)
    await adapter.assignRole('u2', 'editor')

    expect(original.rows).toHaveLength(1)
    expect(other.rows).toEqual([])
  })

  it('carries the rest of the config across the rebind', async () => {
    // json:'string' must survive, or the rebound adapter would silently write a
    // different encoding into the same columns mid-transaction.
    const original = makeDb()
    const other = makeDb()
    const adapter = new IamDrizzleAdapter<'read', 'post', 'editor', 'org-1'>({
      db: original.db,
      json: 'string',
      ops: OPS,
      tables: TABLES,
    })

    await adapter.withClient(other.db).assignRole('u3', 'editor', 'org-1', { attributes: { dept: 'eng' } })

    expect(other.rows[0]?.attributes).toBe('{"dept":"eng"}')
  })
})
