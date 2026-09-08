/**
 * `created_by` has been in the pg and mysql schemas since they were written,
 * and nothing ever wrote to it: a grant row recorded who held the role and
 * never who gave it. `IAssignOptions.actor` is what finally fills it.
 *
 * The column is written by spread rather than as an explicit null, so a caller
 * whose table predates the column is untouched unless they name an actor -
 * which is the part worth pinning, since the failure mode is an insert naming a
 * column the table does not have.
 */
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
      select: () => ({ from: () => ({ where: () => Promise.resolve([]) }) }),
      update: () => ({ set: () => ({ where: () => Promise.resolve() }) }),
    } as unknown as IamDrizzle.AnyDrizzleDb,
    ops: {
      // These tests only ever reach the insert path, and this mock's `where`
      // ignores its argument, so `undefined` is a real answer here rather than
      // a stand-in for one: `and` is declared to return `SQL | undefined`.
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

      // A second adapter must not re-warn: `withClient` rebuilds one per
      // transaction, and a per-instance flag would turn one misconfiguration
      // into one line per transaction.
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
      // The construction-time check asks only whether these are functions; it
      // never calls them, and no code path in this test does either. A body
      // that throws says so, instead of dressing up a fake condition object as
      // a `SQLWrapper` it is not.
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

/**
 * `iam_policies`, `iam_roles` and `iam_subject_attrs` have carried `created_by`
 * and `updated_by` for as long as they have existed and nothing ever wrote to
 * them: six columns, on three dialects, promising a provenance the API could
 * not produce. These pin the split - `created_by` on the insert, `updated_by`
 * on the overwrite - because getting it backwards silently rewrites who
 * authored a policy every time somebody edits it.
 */
describe('definition writes record their author', () => {
  it('savePolicy stamps created_by on insert and updated_by on overwrite', async () => {
    const mock = makeMock()
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)

    await adapter.savePolicy({ algorithm: 'first-match', id: 'p1', name: 'P', rules: [] }, { actor: 'admin-7' })

    expect(onlyRow(mock.inserted).createdBy).toBe('admin-7')
    expect(mock.updated[0]?.updatedBy).toBe('admin-7')
    // The insert half must not claim to be an update, or a first write would
    // record an editor for a row nobody has edited.
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
