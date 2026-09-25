// `starts_at`/`expires_at` bound when an assignment is active; `attributes` carries per-grant data onto `IScopedRole`.
// All three are opt-in: a row with them NULL is an unbounded grant with no attributes.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { IamError, metaOf } from '../../../core/errors'
import { type IamDrizzle, IamDrizzleAdapter } from '../index'
import { fakeSql } from './fake-sql'

type A = 'read'
type R = 'post'
type Ro = 'editor' | 'viewer'
type S = 'org-1' | 'org-2'

interface Row {
  [key: string]: unknown
}

type Condition = { kind: 'eq'; col: string; val: unknown } | { kind: 'and'; conds: Condition[] }

function rowMatches(row: Row, cond: Condition | undefined): boolean {
  if (!cond) return true
  if (cond.kind === 'and') return cond.conds.every((c) => rowMatches(row, c))
  return row[cond.col] === cond.val
}

function makeMock(json: 'native' | 'string' = 'native') {
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
      then(onFulfilled: (v: Row[]) => unknown) {
        return Promise.resolve(run()).then(onFulfilled)
      },
    }
    return chain
  }

  const onPolicyError = vi.fn<(err: Error, ctx: { adapter: 'drizzle'; rowId: string }) => void>()

  const config: IamDrizzle.IConfig<IamDrizzle.AnyDrizzleDb, 'pg'> = {
    db: {
      select: () => ({ from: () => buildSelect() }),
      insert: () => ({
        values: (data: Record<string, unknown>) => ({
          onConflictDoNothing: () => {
            assignments.push({ id: `a${assignments.length + 1}`, ...data })
            return Promise.resolve()
          },
        }),
      }),
      update: () => ({ set: () => ({ where: () => Promise.resolve() }) }),
      delete: () => ({ where: () => Promise.resolve() }),
    } as unknown as IamDrizzle.AnyDrizzleDb,
    tables: tableRefs,
    ops: {
      eq: (c: unknown, val: unknown) => fakeSql({ kind: 'eq', col: colName(c), val } satisfies Condition),
      and: (...conds) =>
        ({ kind: 'and', conds: conds.filter(Boolean) }) as unknown as ReturnType<
          IamDrizzle.IConfig<IamDrizzle.AnyDrizzleDb, 'pg'>['ops']['and']
        >,
    },
    json,
    onPolicyError,
  }

  return { config, assignments, onPolicyError }
}

const HOUR = 60 * 60 * 1000

describe('IamDrizzleAdapter assignment expiry', () => {
  let mock: ReturnType<typeof makeMock>

  beforeEach(() => {
    mock = makeMock()
  })

  it('getSubjectRoles excludes an expired unscoped assignment', async () => {
    mock.assignments.push({
      id: 'a1',
      subjectId: 'sub-1',
      roleId: 'editor',
      scope: null,
      expiresAt: new Date(Date.now() - HOUR),
    })
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    expect(await adapter.getSubjectRoles('sub-1')).toEqual([])
  })

  it('getSubjectRoles excludes an assignment that has not started yet', async () => {
    mock.assignments.push({
      id: 'a1',
      subjectId: 'sub-1',
      roleId: 'editor',
      scope: null,
      startsAt: new Date(Date.now() + HOUR),
    })
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    expect(await adapter.getSubjectRoles('sub-1')).toEqual([])
  })

  it('getSubjectRoles includes an assignment inside its active window', async () => {
    mock.assignments.push({
      id: 'a1',
      subjectId: 'sub-1',
      roleId: 'editor',
      scope: null,
      startsAt: new Date(Date.now() - HOUR),
      expiresAt: new Date(Date.now() + HOUR),
    })
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    expect(await adapter.getSubjectRoles('sub-1')).toEqual(['editor'])
  })

  it('getSubjectRoles includes a row with no bounds at all, unchanged from before this column existed', async () => {
    mock.assignments.push({ id: 'a1', subjectId: 'sub-1', roleId: 'editor', scope: null })
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    expect(await adapter.getSubjectRoles('sub-1')).toEqual(['editor'])
  })

  it('getSubjectScopedRoles excludes an expired scoped assignment', async () => {
    mock.assignments.push({
      id: 'a1',
      subjectId: 'sub-1',
      roleId: 'editor',
      scope: 'org-1',
      expiresAt: new Date(Date.now() - HOUR),
    })
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    expect(await adapter.getSubjectScopedRoles('sub-1')).toEqual([])
  })

  it('only expiresAt set (no startsAt) is active until it expires', async () => {
    mock.assignments.push({
      id: 'a1',
      subjectId: 'sub-1',
      roleId: 'editor',
      scope: null,
      expiresAt: new Date(Date.now() + HOUR),
    })
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    expect(await adapter.getSubjectRoles('sub-1')).toEqual(['editor'])
  })

  it('only startsAt set (no expiresAt) is active forever once started', async () => {
    mock.assignments.push({
      id: 'a1',
      subjectId: 'sub-1',
      roleId: 'editor',
      scope: null,
      startsAt: new Date(Date.now() - HOUR),
    })
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    expect(await adapter.getSubjectRoles('sub-1')).toEqual(['editor'])
  })

  it('dedupes an unscoped role even when one of two grants is expired', async () => {
    mock.assignments.push(
      { id: 'a1', subjectId: 'sub-1', roleId: 'editor', scope: null, expiresAt: new Date(Date.now() - HOUR) },
      { id: 'a2', subjectId: 'sub-1', roleId: 'editor', scope: null },
    )
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    expect(await adapter.getSubjectRoles('sub-1')).toEqual(['editor'])
  })

  it('an expired scoped assignment is fully excluded, attributes included', async () => {
    mock.assignments.push({
      id: 'a1',
      subjectId: 'sub-1',
      roleId: 'editor',
      scope: 'org-1',
      expiresAt: new Date(Date.now() - HOUR),
      attributes: { department: 'sales' },
    })
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    expect(await adapter.getSubjectScopedRoles('sub-1')).toEqual([])
  })

  it('assignRole writes startsAt/expiresAt through to the row', async () => {
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    const startsAt = new Date(Date.now() - HOUR)
    const expiresAt = new Date(Date.now() + HOUR)
    await adapter.assignRole('sub-1', 'editor', undefined, { startsAt, expiresAt })
    expect(mock.assignments[0]).toMatchObject({ startsAt, expiresAt })
  })

  it('assignRole without opts writes null, not undefined, for all three columns', async () => {
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    await adapter.assignRole('sub-1', 'editor')
    expect(mock.assignments[0]).toMatchObject({ startsAt: null, expiresAt: null, attributes: null })
  })
})

describe('IamDrizzleAdapter assignment expiry, exact boundary (fake clock)', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'))
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('is active at the exact instant startsAt is reached (inclusive lower bound)', async () => {
    const mock = makeMock()
    mock.assignments.push({
      id: 'a1',
      subjectId: 'sub-1',
      roleId: 'editor',
      scope: null,
      startsAt: new Date('2026-01-01T00:00:00.000Z'),
    })
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    expect(await adapter.getSubjectRoles('sub-1')).toEqual(['editor'])
  })

  it('is inactive at the exact instant expiresAt is reached (exclusive upper bound)', async () => {
    const mock = makeMock()
    mock.assignments.push({
      id: 'a1',
      subjectId: 'sub-1',
      roleId: 'editor',
      scope: null,
      expiresAt: new Date('2026-01-01T00:00:00.000Z'),
    })
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    expect(await adapter.getSubjectRoles('sub-1')).toEqual([])
  })

  it('is active one millisecond before expiresAt', async () => {
    const mock = makeMock()
    mock.assignments.push({
      id: 'a1',
      subjectId: 'sub-1',
      roleId: 'editor',
      scope: null,
      expiresAt: new Date('2026-01-01T00:00:00.001Z'),
    })
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    expect(await adapter.getSubjectRoles('sub-1')).toEqual(['editor'])
  })
})

describe('IamDrizzleAdapter assignment attributes', () => {
  let mock: ReturnType<typeof makeMock>

  beforeEach(() => {
    mock = makeMock()
  })

  it('surfaces attributes onto the scoped role', async () => {
    mock.assignments.push({
      id: 'a1',
      subjectId: 'sub-1',
      roleId: 'editor',
      scope: 'org-1',
      attributes: { department: 'sales' },
    })
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    expect(await adapter.getSubjectScopedRoles('sub-1')).toEqual([
      { role: 'editor', scope: 'org-1', attributes: { department: 'sales' } },
    ])
  })

  it('omits the attributes key rather than sending null when the column is empty', async () => {
    mock.assignments.push({ id: 'a1', subjectId: 'sub-1', roleId: 'editor', scope: 'org-1', attributes: null })
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    const [scoped] = await adapter.getSubjectScopedRoles('sub-1')
    expect(scoped).toEqual({ role: 'editor', scope: 'org-1' })
    expect(scoped && 'attributes' in scoped).toBe(false)
  })

  it('parses attributes stored as a JSON string (sqlite/text-column mode)', async () => {
    mock = makeMock('string')
    mock.assignments.push({
      id: 'a1',
      subjectId: 'sub-1',
      roleId: 'editor',
      scope: 'org-1',
      attributes: JSON.stringify({ department: 'sales' }),
    })
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    expect(await adapter.getSubjectScopedRoles('sub-1')).toEqual([
      { role: 'editor', scope: 'org-1', attributes: { department: 'sales' } },
    ])
  })

  it('drops a corrupted attributes value without dropping the assignment, and reports it', async () => {
    mock.assignments.push({ id: 'a1', subjectId: 'sub-1', roleId: 'editor', scope: 'org-1', attributes: [1, 2, 3] })
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    const [scoped] = await adapter.getSubjectScopedRoles('sub-1')
    expect(scoped).toEqual({ role: 'editor', scope: 'org-1' })
    expect(mock.onPolicyError).toHaveBeenCalled()
  })

  it('assignRole writes attributes under the configured json mode', async () => {
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    await adapter.assignRole('sub-1', 'editor', 'org-1', { attributes: { department: 'sales' } })
    expect(mock.assignments[0]?.attributes).toEqual({ department: 'sales' })
  })

  it('surfaces an empty object rather than treating it as absent', async () => {
    mock.assignments.push({ id: 'a1', subjectId: 'sub-1', roleId: 'editor', scope: 'org-1', attributes: {} })
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    const [scoped] = await adapter.getSubjectScopedRoles('sub-1')
    expect(scoped).toEqual({ role: 'editor', scope: 'org-1', attributes: {} })
  })

  it('passes a nested object through unchanged', async () => {
    const nested = { department: 'sales', region: { code: 'ES', tier: 2 } }
    mock.assignments.push({ id: 'a1', subjectId: 'sub-1', roleId: 'editor', scope: 'org-1', attributes: nested })
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    const [scoped] = await adapter.getSubjectScopedRoles('sub-1')
    expect(scoped?.attributes).toEqual(nested)
  })

  it('drops an invalid JSON string and reports it, instead of throwing', async () => {
    mock = makeMock('string')
    mock.assignments.push({
      id: 'a1',
      subjectId: 'sub-1',
      roleId: 'editor',
      scope: 'org-1',
      attributes: '{not valid json',
    })
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    const [scoped] = await adapter.getSubjectScopedRoles('sub-1')
    expect(scoped).toEqual({ role: 'editor', scope: 'org-1' })
    expect(mock.onPolicyError).toHaveBeenCalled()
  })

  it('drops a JSON string that parses to null, rather than treating it as {}', async () => {
    mock = makeMock('string')
    mock.assignments.push({ id: 'a1', subjectId: 'sub-1', roleId: 'editor', scope: 'org-1', attributes: 'null' })
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    const [scoped] = await adapter.getSubjectScopedRoles('sub-1')
    expect(scoped).toEqual({ role: 'editor', scope: 'org-1' })
    expect(mock.onPolicyError).toHaveBeenCalled()
  })

  it('drops a native number and reports it', async () => {
    mock.assignments.push({ id: 'a1', subjectId: 'sub-1', roleId: 'editor', scope: 'org-1', attributes: 42 })
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    const [scoped] = await adapter.getSubjectScopedRoles('sub-1')
    expect(scoped).toEqual({ role: 'editor', scope: 'org-1' })
    expect(mock.onPolicyError).toHaveBeenCalled()
  })

  it('drops a native boolean and reports it', async () => {
    mock.assignments.push({ id: 'a1', subjectId: 'sub-1', roleId: 'editor', scope: 'org-1', attributes: true })
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    const [scoped] = await adapter.getSubjectScopedRoles('sub-1')
    expect(scoped).toEqual({ role: 'editor', scope: 'org-1' })
    expect(mock.onPolicyError).toHaveBeenCalled()
  })

  it('a corrupted attributes value on one row does not affect a clean row for the same subject', async () => {
    mock.assignments.push(
      { id: 'a1', subjectId: 'sub-1', roleId: 'editor', scope: 'org-1', attributes: [1, 2, 3] },
      { id: 'a2', subjectId: 'sub-1', roleId: 'viewer', scope: 'org-2', attributes: { department: 'sales' } },
    )
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    const scoped = await adapter.getSubjectScopedRoles('sub-1')
    expect(scoped).toEqual([
      { role: 'editor', scope: 'org-1' },
      { role: 'viewer', scope: 'org-2', attributes: { department: 'sales' } },
    ])
  })

  it('falls back to subjectId in the error report when mysql leaves id null', async () => {
    mock.assignments.push({ id: null, subjectId: 'sub-1', roleId: 'editor', scope: 'org-1', attributes: [1, 2] })
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    await adapter.getSubjectScopedRoles('sub-1')
    const [, ctx] = mock.onPolicyError.mock.calls[0] ?? []
    expect(ctx?.rowId).toBe('sub-1')
  })
})

describe('an unreadable time bound fails closed', () => {
  it.each([
    ['garbage string', 'not-a-date'],
    ['empty-ish string', '   '],
    ['invalid Date object', new Date('nope')],
  ])('an assignment with an unparseable expiresAt (%s) is inactive', async (_label, expiresAt) => {
    const mock = makeMock()
    mock.assignments.push({ id: 'a1', subjectId: 'sub-1', roleId: 'editor', scope: null, expiresAt })
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    expect(await adapter.getSubjectRoles('sub-1')).toEqual([])
  })

  it('an assignment with an unparseable startsAt is inactive', async () => {
    const mock = makeMock()
    mock.assignments.push({ id: 'a1', subjectId: 'sub-1', roleId: 'editor', scope: null, startsAt: 'whenever' })
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    expect(await adapter.getSubjectRoles('sub-1')).toEqual([])
  })

  it('a readable window still grants', async () => {
    const mock = makeMock()
    mock.assignments.push({
      expiresAt: new Date(Date.now() + HOUR),
      id: 'a1',
      roleId: 'editor',
      scope: null,
      startsAt: new Date(Date.now() - HOUR),
      subjectId: 'sub-1',
    })
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    expect(await adapter.getSubjectRoles('sub-1')).toEqual(['editor'])
  })
})

// The engine caches reads for `cacheTTL`, so this must report exactly the next future instant a window opens or closes.
describe('IamDrizzleAdapter.getSubjectGrantBoundary', () => {
  const NOW = Date.UTC(2026, 5, 1, 9, 0, 0)

  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(NOW)
  })
  afterEach(() => {
    vi.useRealTimers()
  })

  function seed(rows: Array<Record<string, unknown>>) {
    const mock = makeMock()
    rows.forEach((r, i) => mock.assignments.push({ id: `a${i + 1}`, scope: null, subjectId: 'sub-1', ...r }))
    return { adapter: new IamDrizzleAdapter<A, R, Ro, S>(mock.config), mock }
  }

  it('is null when the subject holds nothing', async () => {
    const { adapter } = seed([])
    expect(await adapter.getSubjectGrantBoundary('sub-1')).toBeNull()
  })

  it('is null when every grant is unbounded', async () => {
    const { adapter } = seed([{ roleId: 'editor' }, { roleId: 'viewer', scope: 'org-1' }])
    expect(await adapter.getSubjectGrantBoundary('sub-1')).toBeNull()
  })

  it('reports the expiry of the one grant that has one', async () => {
    const { adapter } = seed([{ expiresAt: new Date(NOW + HOUR), roleId: 'editor' }])
    expect(await adapter.getSubjectGrantBoundary('sub-1')).toBe(NOW + HOUR)
  })

  it('reports a future start, so a scheduled grant is not cached as absent past it', async () => {
    const { adapter } = seed([{ roleId: 'editor', startsAt: new Date(NOW + 5 * HOUR) }])
    expect(await adapter.getSubjectGrantBoundary('sub-1')).toBe(NOW + 5 * HOUR)
  })

  it('takes the earliest of several bounds across several grants', async () => {
    const { adapter } = seed([
      { expiresAt: new Date(NOW + 8 * HOUR), roleId: 'editor' },
      { roleId: 'viewer', scope: 'org-1', startsAt: new Date(NOW + 2 * HOUR) },
      { expiresAt: new Date(NOW + 30 * HOUR), roleId: 'viewer', scope: 'org-2' },
    ])
    expect(await adapter.getSubjectGrantBoundary('sub-1')).toBe(NOW + 2 * HOUR)
  })

  it('takes the earliest of the two bounds on a single grant', async () => {
    const { adapter } = seed([
      { expiresAt: new Date(NOW + 3 * HOUR), roleId: 'editor', startsAt: new Date(NOW + HOUR) },
    ])
    expect(await adapter.getSubjectGrantBoundary('sub-1')).toBe(NOW + HOUR)
  })

  it('ignores a bound already in the past - it has nothing left to change', async () => {
    const { adapter } = seed([
      { expiresAt: new Date(NOW - HOUR), roleId: 'editor' },
      { expiresAt: new Date(NOW + HOUR), roleId: 'viewer' },
    ])
    expect(await adapter.getSubjectGrantBoundary('sub-1')).toBe(NOW + HOUR)
  })

  it('ignores a bound at exactly now - the window it describes has already turned', async () => {
    const { adapter } = seed([{ expiresAt: new Date(NOW), roleId: 'editor' }])
    expect(await adapter.getSubjectGrantBoundary('sub-1')).toBeNull()
  })

  it('ignores an unreadable bound, which makes its row inactive on sight anyway', async () => {
    const { adapter } = seed([
      { expiresAt: 'whenever', roleId: 'editor' },
      { expiresAt: new Date(NOW + HOUR), roleId: 'viewer' },
    ])
    expect(await adapter.getSubjectGrantBoundary('sub-1')).toBe(NOW + HOUR)
  })

  it('ignores postgres `infinity`, which is a bound that never arrives', async () => {
    // INFO: node-postgres parses `infinity` to the JS number, which `_isActive` reads as "always".
    const { adapter } = seed([{ expiresAt: Number.POSITIVE_INFINITY, roleId: 'editor' }])
    expect(await adapter.getSubjectGrantBoundary('sub-1')).toBeNull()
  })

  it('reads only the subject it was asked about', async () => {
    const mock = makeMock()
    mock.assignments.push({
      expiresAt: new Date(NOW + HOUR),
      id: 'a1',
      roleId: 'editor',
      scope: null,
      subjectId: 'sub-1',
    })
    mock.assignments.push({
      expiresAt: new Date(NOW + 60_000),
      id: 'a2',
      roleId: 'editor',
      scope: null,
      subjectId: 'sub-2',
    })
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    expect(await adapter.getSubjectGrantBoundary('sub-1')).toBe(NOW + HOUR)
  })

  it('is null for a subject id nothing is stored under', async () => {
    const { adapter } = seed([{ expiresAt: new Date(NOW + HOUR), roleId: 'editor' }])
    expect(await adapter.getSubjectGrantBoundary('nobody')).toBeNull()
    expect(await adapter.getSubjectGrantBoundary('')).toBeNull()
  })
})

// `startsAt >= expiresAt` is an empty window that would store a dead grant and report success. The shipped
// schemas CHECK it, but callers can bring their own table, so the code refuses it too.
describe('IamDrizzleAdapter refuses a window it could never honour', () => {
  const NOW = Date.UTC(2026, 5, 1, 9, 0, 0)

  it('refuses a window that ends before it starts, and stores nothing', async () => {
    const mock = makeMock()
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    await expect(
      adapter.assignRole('sub-1', 'editor', undefined, {
        expiresAt: new Date(NOW),
        startsAt: new Date(NOW + HOUR),
      }),
    ).rejects.toThrow('IAM_ASSIGN_WINDOW_EMPTY')
    expect(mock.assignments).toEqual([])
  })

  it('refuses a zero-length window, which is never active either', async () => {
    const mock = makeMock()
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    await expect(
      adapter.assignRole('sub-1', 'editor', undefined, { expiresAt: new Date(NOW), startsAt: new Date(NOW) }),
    ).rejects.toThrow('IAM_ASSIGN_WINDOW_EMPTY')
    expect(mock.assignments).toEqual([])
  })

  it.each(['startsAt', 'expiresAt'] as const)('refuses an Invalid Date in %s', async (field) => {
    const mock = makeMock()
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    try {
      await adapter.assignRole('sub-1', 'editor', undefined, { [field]: new Date('nope') })
      expect.unreachable()
    } catch (err) {
      expect(metaOf(err as IamError<'IAM_ASSIGN_WINDOW_INVALID_DATE'>, 'IAM_ASSIGN_WINDOW_INVALID_DATE').field).toBe(
        field,
      )
    }
    expect(mock.assignments).toEqual([])
  })

  it('does not repeat the caller-supplied instants back in the message', async () => {
    const mock = makeMock()
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    const startsAt = new Date(NOW + HOUR)
    await expect(
      adapter.assignRole('sub-1', 'editor', undefined, { expiresAt: new Date(NOW), startsAt }),
    ).rejects.toThrow(expect.not.stringContaining(startsAt.toISOString()))
  })

  it('a one-millisecond window is legal - it is short, not empty', async () => {
    const mock = makeMock()
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    await adapter.assignRole('sub-1', 'editor', undefined, {
      expiresAt: new Date(NOW + 1),
      startsAt: new Date(NOW),
    })
    expect(mock.assignments).toHaveLength(1)
  })

  it.each([
    ['only a start', { startsAt: new Date(NOW) }],
    ['only an expiry', { expiresAt: new Date(NOW) }],
    ['neither', {}],
  ])('leaves %s alone', async (_label, opts) => {
    const mock = makeMock()
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    await adapter.assignRole('sub-1', 'editor', undefined, opts)
    expect(mock.assignments).toHaveLength(1)
  })

  it('refuses the whole batch when one row carries an impossible window', async () => {
    const mock = makeMock()
    const adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
    await expect(
      adapter.assignRoleMany([
        { roleId: 'editor', subjectId: 'sub-1' },
        {
          opts: { expiresAt: new Date(NOW), startsAt: new Date(NOW + HOUR) },
          roleId: 'viewer',
          subjectId: 'sub-2',
        },
      ]),
    ).rejects.toThrow('IAM_ASSIGN_WINDOW_EMPTY')
    expect(mock.assignments, 'a refused batch must not land its good rows either').toEqual([])
  })
})
