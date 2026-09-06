import { beforeEach, describe, expect, it, vi } from 'vitest'
import { type IamDrizzle, IamDrizzleAdapter } from '../index'

/** `IConfig` gained <TDb, TType> in the rename these suites were disabled for. */
type TestConfig = IamDrizzle.IConfig<IamDrizzle.AnyDrizzleDb, 'pg'>

type A = 'read'
type R = 'post'
type Ro = 'viewer'
type S = 'org-1'

interface Row {
  [key: string]: unknown
}

function makeMock(initialAttrs: Row[]) {
  const tableRefs = {
    policies: { id: { name: 'id' } },
    roles: { id: { name: 'id' } },
    assignments: {
      id: { name: 'id' },
      subjectId: { name: 'subjectId' },
      roleId: { name: 'roleId' },
      scope: { name: 'scope' },
    },
    attrs: { id: { name: 'id' }, subjectId: { name: 'subjectId' } },
  } as unknown as TestConfig['tables']

  const buildSelect = (table: Row[]) => {
    let lim: number | null = null
    let where: unknown = null
    const result = () => {
      let rows = table.filter((r) => {
        if (!where) return true
        const w = where as { type: string; args: [{ name: string }, unknown] }
        if (w.type === 'eq') return r[w.args[0].name] === w.args[1]
        return true
      })
      if (lim != null) rows = rows.slice(0, lim)
      return rows
    }
    const chain: {
      where: (c: unknown) => typeof chain
      limit: (n: number) => Promise<Row[]>
      then: (cb: (v: Row[]) => unknown) => Promise<unknown>
    } = {
      where(c) {
        where = c
        return chain
      },
      limit(n) {
        lim = n
        return Promise.resolve(result())
      },
      then(cb) {
        return Promise.resolve(result()).then(cb)
      },
    }
    return chain
  }

  const config: TestConfig = {
    db: {
      select: vi.fn(
        () =>
          ({
            from: () => buildSelect(initialAttrs),
          }) as unknown as ReturnType<TestConfig['db']['select']>,
      ) as unknown as TestConfig['db']['select'],
      insert: vi.fn(),
      update: vi.fn(),
      delete: vi.fn(),
    },
    tables: tableRefs,
    ops: {
      eq: (col: unknown, val: unknown) => ({ type: 'eq', args: [col, val] }) as never,
      and: (...conditions: unknown[]) => ({ type: 'and', args: conditions }) as never,
    },
  }
  return config
}

describe('IamDrizzleAdapter native JSONB shape validation', () => {
  let onPolicyErrorMock: ReturnType<typeof vi.fn<(err: Error, ctx: { adapter: 'drizzle'; rowId: string }) => void>>

  beforeEach(() => {
    onPolicyErrorMock = vi.fn<(err: Error, ctx: { adapter: 'drizzle'; rowId: string }) => void>()
  })

  function buildAdapter(initialAttrs: Row[]) {
    const config = makeMock(initialAttrs)
    return new IamDrizzleAdapter<A, R, Ro, S>({ ...config, onPolicyError: onPolicyErrorMock })
  }

  it('throws when native data column holds an array', async () => {
    const adapter = buildAdapter([{ subjectId: 'user-1', data: [1, 2, 3] }])
    await expect(adapter.getSubjectAttributes('user-1')).rejects.toThrow(
      /corrupted attributes for "user-1" \(not a JSON object\)/,
    )
    expect(onPolicyErrorMock).toHaveBeenCalled()
    const errArg = onPolicyErrorMock.mock.calls[0]?.[0] as Error | undefined
    expect(errArg).toBeInstanceOf(Error)
    // The guard now also rejects a bag whose *values* are unstorable, so the
    // message says "of scalar values"; the `(got array)` suffix is unchanged.
    expect(errArg?.message).toContain('must be a JSON object of scalar values (got array)')
  })

  it('throws when native data column holds a number', async () => {
    const adapter = buildAdapter([{ subjectId: 'user-1', data: 42 }])
    await expect(adapter.getSubjectAttributes('user-1')).rejects.toThrow(
      /corrupted attributes for "user-1" \(not a JSON object\)/,
    )
  })

  it('throws when native data column holds a boolean', async () => {
    const adapter = buildAdapter([{ subjectId: 'user-1', data: true }])
    await expect(adapter.getSubjectAttributes('user-1')).rejects.toThrow(
      /corrupted attributes for "user-1" \(not a JSON object\)/,
    )
  })

  it('returns {} when data column is null (legit empty state, not corruption)', async () => {
    const adapter = buildAdapter([{ subjectId: 'user-1', data: null }])
    await expect(adapter.getSubjectAttributes('user-1')).resolves.toEqual({})
  })

  it('returns {} when data column is undefined', async () => {
    const adapter = buildAdapter([{ subjectId: 'user-1', data: undefined }])
    await expect(adapter.getSubjectAttributes('user-1')).resolves.toEqual({})
  })

  it('accepts a valid native object', async () => {
    const adapter = buildAdapter([{ subjectId: 'user-1', data: { tier: 'gold', verified: true } }])
    await expect(adapter.getSubjectAttributes('user-1')).resolves.toEqual({
      tier: 'gold',
      verified: true,
    })
  })

  it('still validates the string-JSON path', async () => {
    const adapter = buildAdapter([{ subjectId: 'user-1', data: '"a string, not an object"' }])
    await expect(adapter.getSubjectAttributes('user-1')).rejects.toThrow(
      /corrupted attributes for "user-1" \(not a JSON object\)/,
    )
  })

  /**
   * `iamAssertAttributesParam` is the shared boundary guard every adapter runs
   * first. Drizzle and Prisma - the two SQL backends - never called it, so
   * `setSubjectAttributes(id, 'abc')` spread into per-character keys and wrote
   * `{0:'a',1:'b',2:'c'}` here while the other four threw.
   */
  it.each([
    ['a string', '"abc"'],
    ['an array', '[1,2]'],
    ['null', 'null'],
    ['a number', '7'],
  ])('setSubjectAttributes rejects %s', async (_label, json) => {
    const adapter = buildAdapter([])
    await expect(adapter.setSubjectAttributes('user-1', JSON.parse(json))).rejects.toThrow(/must be a plain object/)
  })

  // Control: a plain object gets *past* the guard. The mock has no write path,
  // so it still fails - but on the write, not on the guard's message, which is
  // what distinguishes "rejected correctly" from "method became inert".
  it('setSubjectAttributes lets a plain object past the guard', async () => {
    let message = ''
    try {
      await buildAdapter([]).setSubjectAttributes('user-1', { tier: 'gold' })
    } catch (err) {
      message = err instanceof Error ? err.message : String(err)
    }
    expect(message).not.toMatch(/must be a plain object/)
  })

  it('error text never echoes the raw column value', async () => {
    const secret = 'attacker-controlled-jsonb-value-secret-marker'
    const adapter = buildAdapter([{ subjectId: 'user-1', data: secret }])
    try {
      await adapter.getSubjectAttributes('user-1')
      throw new Error('expected throw')
    } catch (err) {
      const msg = (err as Error).message
      expect(msg).not.toContain(secret)
    }
  })
})
