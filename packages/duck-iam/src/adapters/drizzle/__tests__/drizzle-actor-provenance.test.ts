// Pins that `actor` fills `created_by`/`updated_by`, and that no actor names no column,
// so a table without those columns still accepts the write.
import { describe, expect, it, vi } from 'vitest'
import { type IamDrizzle, IamDrizzleAdapter } from '../index'
import { fakeSql } from './fake-sql'

type A = 'read'
type R = 'post'
type Ro = 'editor' | 'viewer'
type S = 'org-1' | 'org-2'

/** Records the value objects every insert was handed, without executing SQL. */
function makeMock(ops?: Partial<IamDrizzle.IConfig<IamDrizzle.AnyDrizzleDb, 'pg'>['ops']>) {
  const inserted: (Record<string, unknown> | Record<string, unknown>[])[] = []
  const updated: Record<string, unknown>[] = []
  const col = (name: string) => ({ __col: name })
  const colName = (c: unknown): string => {
    if (c !== null && typeof c === 'object' && '__col' in c && typeof c.__col === 'string') return c.__col
    throw new TypeError('not a column ref')
  }

  const tableRefs = {
    assignments: { id: col('id'), roleId: col('roleId'), scope: col('scope'), subjectId: col('subjectId') },
    attrs: { data: col('data'), subjectId: col('subjectId') },
    policies: { id: col('id') },
    roles: { id: col('id') },
  } as unknown as IamDrizzle.IConfig<IamDrizzle.AnyDrizzleDb, 'pg'>['tables']

  const config: IamDrizzle.IConfig<IamDrizzle.AnyDrizzleDb, 'pg'> = {
    db: {
      delete: () => ({ where: () => ({ returning: () => Promise.resolve([]) }) }),
      insert: () => ({
        values: (data: Record<string, unknown> | Record<string, unknown>[]) => {
          inserted.push(data)
          return {
            onConflictDoNothing: () => ({
              returning: () => Promise.resolve([]),
              then: (onFulfilled: (v: unknown) => unknown) => Promise.resolve(undefined).then(onFulfilled),
            }),
            onConflictDoUpdate: ({ set }: { set: Record<string, unknown> }) => {
              updated.push(set)
              return Promise.resolve()
            },
          }
        },
      }),
      // `limit` answers the attribute read `setSubjectAttributes` does first.
      select: () => ({
        from: () => ({
          where: () => ({
            limit: () => Promise.resolve([]),
            then: (onFulfilled: (v: unknown[]) => unknown) => Promise.resolve([]).then(onFulfilled),
          }),
        }),
      }),
      update: () => ({ set: () => ({ where: () => Promise.resolve() }) }),
    } as unknown as IamDrizzle.AnyDrizzleDb,
    ops: {
      // This mock's `where` ignores its argument, and `and` is typed `SQL | undefined`.
      and: () => undefined,
      eq: (c: unknown, val: unknown) => fakeSql({ col: colName(c), kind: 'eq', val }),
      ...ops,
    },
    tables: tableRefs,
  }

  return { config, inserted, updated }
}

/** The single value object an `assignRole` insert produced. */
function onlyRow(inserted: (Record<string, unknown> | Record<string, unknown>[])[]): Record<string, unknown> {
  const first = inserted[0]
  if (first === undefined || Array.isArray(first)) throw new TypeError('expected one value object')
  return first
}

/** The value array an `assignRoleMany` insert produced. */
function rows(inserted: (Record<string, unknown> | Record<string, unknown>[])[]): Record<string, unknown>[] {
  const first = inserted[0]
  if (!Array.isArray(first)) throw new TypeError('expected an array of value objects')
  return first
}

describe('assignRole records who made the grant', () => {
  it("writes the caller's actor to created_by", async () => {
    const mock = makeMock()
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)

    await adapter.assignRole('sub-1', 'editor', 'org-1', { actor: 'admin-7' })

    expect(onlyRow(mock.inserted).createdBy).toBe('admin-7')
  })

  it('names no createdBy column at all when the caller supplies no actor', async () => {
    const mock = makeMock()
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)

    await adapter.assignRole('sub-1', 'editor', 'org-1')

    // A table that predates the column must still accept the insert.
    expect('createdBy' in onlyRow(mock.inserted)).toBe(false)
  })

  it('carries the actor alongside the temporal bounds, not instead of them', async () => {
    const mock = makeMock()
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    const expiresAt = new Date(Date.now() + 60_000)

    await adapter.assignRole('sub-1', 'editor', undefined, { actor: 'admin-7', expiresAt })

    expect(onlyRow(mock.inserted)).toMatchObject({ createdBy: 'admin-7', expiresAt })
  })
})

describe('assignRoleMany keeps one column list across the batch', () => {
  it('gives every row a createdBy once any row names an actor', async () => {
    const mock = makeMock()
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)

    await adapter.assignRoleMany([
      { opts: { actor: 'admin-7' }, roleId: 'editor', subjectId: 'sub-1' },
      { roleId: 'viewer', subjectId: 'sub-2' },
    ])

    // A multi-row insert builds its column list from the value objects, so a
    // partially-present column is a row the driver has to reconcile.
    expect(rows(mock.inserted).map((r) => r.createdBy)).toEqual(['admin-7', null])
  })

  it('names no createdBy on any row when no row names an actor', async () => {
    const mock = makeMock()
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)

    await adapter.assignRoleMany([
      { roleId: 'editor', subjectId: 'sub-1' },
      { roleId: 'viewer', subjectId: 'sub-2' },
    ])

    expect(rows(mock.inserted).every((r) => !('createdBy' in r))).toBe(true)
  })
})

describe('the degraded-ops warning', () => {
  it('names both missing ops at construction, once per process', async () => {
    vi.resetModules()
    const { IamDrizzleAdapter: Fresh } = await import('../index')
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      new Fresh<A, R, Ro, S>(makeMock().config)

      expect(warn).toHaveBeenCalledTimes(1)
      const message = String(warn.mock.calls[0]?.[0])
      expect(message).toContain('`isNull`')
      expect(message).toContain('`or`')
      expect(message).toContain('ops: { eq, and, isNull, or }')

      // `withClient` rebuilds the adapter per transaction, so a second one must not re-warn.
      new Fresh<A, R, Ro, S>(makeMock().config)
      expect(warn).toHaveBeenCalledTimes(1)
    } finally {
      warn.mockRestore()
    }
  })

  it('stays quiet when both ops were supplied', async () => {
    vi.resetModules()
    const { IamDrizzleAdapter: Fresh } = await import('../index')
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      // The check only asks whether these are functions; a throwing body proves nothing calls them.
      const unused = (): never => {
        throw new Error('the degraded-ops check never calls these')
      }
      const mock = makeMock({ isNull: unused, or: unused })
      new Fresh<A, R, Ro, S>(mock.config)

      expect(warn).not.toHaveBeenCalled()
    } finally {
      warn.mockRestore()
    }
  })
})

// `created_by` goes on the insert and `updated_by` on the overwrite; swapped, every edit rewrites the author.
describe('definition writes record their author', () => {
  it('savePolicy stamps created_by on insert and updated_by on overwrite', async () => {
    const mock = makeMock()
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)

    await adapter.savePolicy({ algorithm: 'first-match', id: 'p1', name: 'P', rules: [] }, { actor: 'admin-7' })

    expect(onlyRow(mock.inserted).createdBy).toBe('admin-7')
    expect(mock.updated[0]?.updatedBy).toBe('admin-7')
    // The insert half must not carry `updatedBy`, or a first write records an editor nobody was.
    expect('updatedBy' in onlyRow(mock.inserted)).toBe(false)
    expect(mock.updated[0] && 'createdBy' in mock.updated[0]).toBe(false)
  })

  it('saveRole does the same', async () => {
    const mock = makeMock()
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)

    await adapter.saveRole({ id: 'editor', name: 'Editor', permissions: [] }, { actor: 'admin-7' })

    expect(onlyRow(mock.inserted).createdBy).toBe('admin-7')
    expect(mock.updated[0]?.updatedBy).toBe('admin-7')
  })

  it('setSubjectAttributes does the same', async () => {
    const mock = makeMock()
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)

    await adapter.setSubjectAttributes('sub-1', { tier: 'gold' }, { actor: 'admin-7' })

    expect(onlyRow(mock.inserted).createdBy).toBe('admin-7')
    expect(mock.updated[0]?.updatedBy).toBe('admin-7')
  })

  it('names neither column when the caller supplies no actor', async () => {
    const mock = makeMock()
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)

    await adapter.saveRole({ id: 'editor', name: 'Editor', permissions: [] })

    const row = onlyRow(mock.inserted)
    expect('createdBy' in row || 'updatedBy' in row).toBe(false)
  })
})
