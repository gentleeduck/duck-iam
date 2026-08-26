/**
 * `deletedAt` is never set by this adapter (no soft-delete method exists), but a row
 * can arrive already soft-deleted by something outside it (an admin tool, a trigger).
 * These tests pin that: with `ops.isNull` configured, reads exclude it; without it
 * (the pre-existing default), reads behave exactly as before this column existed.
 */
import { beforeEach, describe, expect, it } from 'vitest'
import type { AccessControl } from '../../../core/types'
import { type IamDrizzle, IamDrizzleAdapter } from '../index'

type A = 'read'
type R = 'post'
type Ro = 'viewer'
type S = never

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
  const policies: Row[] = []

  const col = (name: string) => ({ __col: name })
  const colName = (c: unknown): string => (c as { __col: string }).__col

  const tableRefs = { policies: { id: col('id'), deletedAt: col('deletedAt') } } as unknown as IamDrizzle.IConfig<
    IamDrizzle.AnyDrizzleDb,
    'pg'
  >['tables']

  const buildSelect = () => {
    let where: Condition | undefined
    const run = () => policies.filter((r) => rowMatches(r, where))
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
      insert: () => ({ values: () => ({ onConflictDoUpdate: () => Promise.resolve() }) }),
      delete: () => ({ where: () => Promise.resolve() }),
    } as unknown as IamDrizzle.AnyDrizzleDb,
    tables: tableRefs,
    ops: {
      eq: (c, val) => ({ kind: 'eq', col: colName(c), val }) satisfies Condition,
      and: (...conds) =>
        ({ kind: 'and', conds: conds.filter(Boolean) }) as unknown as ReturnType<
          IamDrizzle.IConfig<IamDrizzle.AnyDrizzleDb, 'pg'>['ops']['and']
        >,
    },
  }

  return { config, policies }
}

const policyRow = (id: string, deletedAt: Date | null = null): Row => ({
  id,
  name: id,
  version: 1,
  algorithm: 'deny-overrides',
  rules: JSON.stringify([
    { id: 'r1', effect: 'allow', priority: 1, actions: ['read'], resources: ['post'], conditions: { all: [] } },
  ] satisfies AccessControl.IRule[]),
  targets: null,
  deletedAt,
})

describe('IamDrizzleAdapter deletedAt filtering', () => {
  let mock: ReturnType<typeof makeMock>

  beforeEach(() => {
    mock = makeMock()
    mock.policies.push(policyRow('live'), policyRow('gone', new Date()))
  })

  it('without ops.isNull, reads return every row including soft-deleted ones (pre-existing default)', async () => {
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    const ids = (await adapter.listPolicies()).map((p) => p.id).sort()
    expect(ids).toEqual(['gone', 'live'])
    expect(await adapter.getPolicy('gone')).not.toBeNull()
  })

  it('with ops.isNull configured, reads exclude rows with deletedAt set', async () => {
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>({
      ...mock.config,
      ops: { ...mock.config.ops, isNull: (c) => ({ kind: 'isNull', col: (c as { __col: string }).__col }) as never },
    })
    const ids = (await adapter.listPolicies()).map((p) => p.id)
    expect(ids).toEqual(['live'])
    expect(await adapter.getPolicy('gone')).toBeNull()
    expect(await adapter.getPolicy('live')).not.toBeNull()
  })
})
