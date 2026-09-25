import { beforeEach, describe, expect, it, vi } from 'vitest'
import { type IamDrizzle, IamDrizzleAdapter } from '../index'

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
    await expect(adapter.getSubjectAttributes('user-1')).rejects.toMatchObject({ code: 'IAM_ATTRIBUTES_CORRUPT' })
    expect(onPolicyErrorMock).toHaveBeenCalled()
    const errArg = onPolicyErrorMock.mock.calls[0]?.[0] as Error | undefined
    expect(errArg).toBeInstanceOf(Error)
    expect(errArg?.message).toContain('must be a JSON object of scalar values (got array)')
  })

  it('throws when native data column holds a number', async () => {
    const adapter = buildAdapter([{ subjectId: 'user-1', data: 42 }])
    await expect(adapter.getSubjectAttributes('user-1')).rejects.toMatchObject({ code: 'IAM_ATTRIBUTES_CORRUPT' })
  })

  it('throws when native data column holds a boolean', async () => {
    const adapter = buildAdapter([{ subjectId: 'user-1', data: true }])
    await expect(adapter.getSubjectAttributes('user-1')).rejects.toMatchObject({ code: 'IAM_ATTRIBUTES_CORRUPT' })
  })

  // SECURITY: `data` is `.notNull()`, so a `null` is a stored `'null'::jsonb` and must throw, not read as `{}`
  // and drop deny rules. A subject with no attributes has no row and still reads `{}`.
  it('throws when the data column holds a stored JSON null', async () => {
    const adapter = buildAdapter([{ subjectId: 'user-1', data: null }])
    await expect(adapter.getSubjectAttributes('user-1')).rejects.toMatchObject({ code: 'IAM_ATTRIBUTES_CORRUPT' })
  })

  it('throws when the data column is undefined', async () => {
    const adapter = buildAdapter([{ subjectId: 'user-1', data: undefined }])
    await expect(adapter.getSubjectAttributes('user-1')).rejects.toMatchObject({ code: 'IAM_ATTRIBUTES_CORRUPT' })
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
    await expect(adapter.getSubjectAttributes('user-1')).rejects.toMatchObject({ code: 'IAM_ATTRIBUTES_CORRUPT' })
  })

  // Without `iamAssertAttributesParam`, a string would spread into per-character keys.
  it.each([
    ['a string', '"abc"'],
    ['an array', '[1,2]'],
    ['null', 'null'],
    ['a number', '7'],
  ])('setSubjectAttributes rejects %s', async (_label, json) => {
    const adapter = buildAdapter([])
    await expect(adapter.setSubjectAttributes('user-1', JSON.parse(json))).rejects.toThrow('IAM_ATTRIBUTES_INVALID')
  })

  // Control: the mock has no write path, so this still fails, but on the write rather than the guard.
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
