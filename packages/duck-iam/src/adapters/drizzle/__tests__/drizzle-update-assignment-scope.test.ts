/**
 * `updateAssignmentScope` is the one adapter method whose whole point is a single
 * `UPDATE` instead of revoke + assign, and it needs `ops.isNull` to match the
 * global/unscoped case correctly (`eq(col, null)` is not `IS NULL` in SQL). These
 * tests pin: the happy path moves the row in place, a target-scope conflict drops the
 * source instead of erroring, a missing source returns false, and omitting `ops.isNull`
 * disables the whole feature (so the engine's revoke+assign fallback takes over).
 */
import { beforeEach, describe, expect, it } from 'vitest'
import { type IamDrizzle, IamDrizzleAdapter } from '../index'

type A = 'read'
type R = 'post'
type Ro = 'editor'
type S = 'org-1' | 'org-2'

interface Row {
  [key: string]: unknown
}

type Condition =
  | { kind: 'eq'; col: string; val: unknown }
  | { kind: 'and'; conds: Condition[] }
  | { kind: 'isNull'; col: string }

function rowMatches(row: Row, cond: Condition | undefined): boolean {
  if (!cond) return true
  if (cond.kind === 'and') return cond.conds.every((c) => rowMatches(row, c))
  if (cond.kind === 'isNull') return row[cond.col] == null
  return row[cond.col] === cond.val
}

function makeMock() {
  const assignments: Row[] = []
  const col = (name: string) => ({ __col: name })
  const colName = (c: unknown): string => (c as { __col: string }).__col

  const tableRefs = {
    assignments: { id: col('id'), subjectId: col('subjectId'), roleId: col('roleId'), scope: col('scope') },
  } as unknown as IamDrizzle.IConfig<IamDrizzle.AnyDrizzleDb, 'pg'>['tables']

  const buildSelect = () => {
    let where: Condition | undefined
    const run = () => assignments.filter((r) => rowMatches(r, where))
    const chain = {
      where(c: Condition) {
        where = c
        return chain
      },
      limit(n: number) {
        return Promise.resolve(run().slice(0, n))
      },
      then(onFulfilled: (v: Row[]) => unknown) {
        return Promise.resolve(run()).then(onFulfilled)
      },
    }
    return chain
  }

  const config: IamDrizzle.IConfig<IamDrizzle.AnyDrizzleDb, 'pg'> = {
    db: {
      select: () => ({ from: () => buildSelect() }),
      insert: () => ({ values: () => ({ onConflictDoNothing: () => Promise.resolve() }) }),
      update: () => ({
        set: (data: Record<string, unknown>) => ({
          where: (c: Condition) => {
            for (const row of assignments) if (rowMatches(row, c)) Object.assign(row, data)
            return Promise.resolve()
          },
        }),
      }),
      delete: () => ({
        where: (c: Condition) => {
          for (let i = assignments.length - 1; i >= 0; i--) {
            const row = assignments[i]
            if (row && rowMatches(row, c)) assignments.splice(i, 1)
          }
          return Promise.resolve()
        },
      }),
    } as unknown as IamDrizzle.AnyDrizzleDb,
    tables: tableRefs,
    ops: {
      eq: (c, val) => ({ kind: 'eq', col: colName(c), val }) satisfies Condition,
      and: (...conds) =>
        ({ kind: 'and', conds: conds.filter(Boolean) }) as unknown as ReturnType<
          IamDrizzle.IConfig<IamDrizzle.AnyDrizzleDb, 'pg'>['ops']['and']
        >,
      isNull: (c) => ({ kind: 'isNull', col: colName(c) }) as never,
    },
  }

  return { config, assignments }
}

describe('IamDrizzleAdapter.updateAssignmentScope', () => {
  let mock: ReturnType<typeof makeMock>

  beforeEach(() => {
    mock = makeMock()
    mock.assignments.push({ id: 'a1', subjectId: 'sub-1', roleId: 'editor', scope: 'org-1' })
  })

  it('moves the row to the new scope in place, preserving its id', async () => {
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    const moved = await adapter.updateAssignmentScope('sub-1', 'editor', 'org-1', 'org-2')
    expect(moved).toBe(true)
    expect(mock.assignments).toEqual([{ id: 'a1', subjectId: 'sub-1', roleId: 'editor', scope: 'org-2' }])
  })

  it('records the actor in updated_by when supplied', async () => {
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    await adapter.updateAssignmentScope('sub-1', 'editor', 'org-1', 'org-2', 'admin-1')
    expect(mock.assignments[0]?.updatedBy).toBe('admin-1')
  })

  it('moves a global (unscoped) assignment via IS NULL matching', async () => {
    mock.assignments[0] = { id: 'a1', subjectId: 'sub-1', roleId: 'editor', scope: null }
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    const moved = await adapter.updateAssignmentScope('sub-1', 'editor', undefined, 'org-2')
    expect(moved).toBe(true)
    expect(mock.assignments[0]?.scope).toBe('org-2')
  })

  it('drops the source row instead of erroring when the target scope is already granted', async () => {
    mock.assignments.push({ id: 'a2', subjectId: 'sub-1', roleId: 'editor', scope: 'org-2' })
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    const moved = await adapter.updateAssignmentScope('sub-1', 'editor', 'org-1', 'org-2')
    expect(moved).toBe(true)
    expect(mock.assignments).toEqual([{ id: 'a2', subjectId: 'sub-1', roleId: 'editor', scope: 'org-2' }])
  })

  it('returns false when no assignment matches the source scope', async () => {
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    const moved = await adapter.updateAssignmentScope('sub-1', 'editor', 'org-2', 'org-1')
    expect(moved).toBe(false)
    expect(mock.assignments).toEqual([{ id: 'a1', subjectId: 'sub-1', roleId: 'editor', scope: 'org-1' }])
  })

  it('returns false without ops.isNull, leaving the row untouched for the engine to fall back on', async () => {
    const { isNull, ...opsWithoutIsNull } = mock.config.ops
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>({ ...mock.config, ops: opsWithoutIsNull })
    const moved = await adapter.updateAssignmentScope('sub-1', 'editor', 'org-1', 'org-2')
    expect(moved).toBe(false)
    expect(mock.assignments).toEqual([{ id: 'a1', subjectId: 'sub-1', roleId: 'editor', scope: 'org-1' }])
  })
})
