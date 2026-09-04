import type { SQL } from 'drizzle-orm'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { IamConfig } from '../../../core/config'
import type { AccessControl, IamAdapter } from '../../../core/types'
import { runAdapterCompliance } from '../../__compliance__/compliance'
import { createIamDrizzleAdapter, type IamDrizzle, IamDrizzleAdapter, iamDrizzleAdapter } from '../index'

/** `IConfig` gained <TDb, TType> in the rename these suites were disabled for. */
type TestConfig = IamDrizzle.IConfig<IamDrizzle.AnyDrizzleDb, 'pg'>
/** MySQL config shape: `dialect` narrows to `'mysql'`, branching the adapter's upsert chain. */
type MysqlTestConfig = IamDrizzle.IConfig<IamDrizzle.AnyDrizzleDb, 'mysql'>

type A = 'read' | 'write'
type R = 'post' | 'comment'
type Ro = 'viewer' | 'editor'
type S = 'org-1' | 'org-2'

interface Row {
  [key: string]: unknown
}

interface WhereCondition {
  type: 'eq' | 'and'
  args: unknown[]
}

function isEq(c: unknown): c is { type: 'eq'; args: [{ name: string }, unknown] } {
  return typeof c === 'object' && c !== null && (c as { type?: string }).type === 'eq'
}

function isAnd(c: unknown): c is { type: 'and'; args: WhereCondition[] } {
  return typeof c === 'object' && c !== null && (c as { type?: string }).type === 'and'
}

function rowMatches(row: Row, cond: unknown): boolean {
  if (!cond) return true
  if (isAnd(cond)) return cond.args.every((sub) => rowMatches(row, sub))
  if (isEq(cond)) {
    const [col, val] = cond.args
    return row[col.name] === val
  }
  return false
}

function makeDrizzleMock(): {
  config: TestConfig
  tables: { policies: Row[]; roles: Row[]; assignments: Row[]; attrs: Row[] }
} {
  const tables = {
    policies: [] as Row[],
    roles: [] as Row[],
    assignments: [] as Row[],
    attrs: [] as Row[],
  }

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

  const tableForRef = (ref: unknown): Row[] => {
    if (ref === tableRefs.policies) return tables.policies
    if (ref === tableRefs.roles) return tables.roles
    if (ref === tableRefs.assignments) return tables.assignments
    if (ref === tableRefs.attrs) return tables.attrs
    throw new Error('unknown table ref')
  }

  const buildSelect = (table: Row[]) => {
    let where: unknown = null
    let lim: number | null = null
    const result = (): Row[] => {
      let rows = table.filter((r) => rowMatches(r, where))
      if (lim != null) rows = rows.slice(0, lim)
      return rows
    }
    const chain = {
      where(c: unknown) {
        where = c
        return chain
      },
      limit(n: number) {
        lim = n
        return Promise.resolve(result())
      },
      then(onFulfilled: (v: Row[]) => unknown) {
        return Promise.resolve(result()).then(onFulfilled)
      },
    }
    return chain
  }

  /**
   * A drizzle statement: awaitable on its own, and - where the dialect has
   * `RETURNING` - able to name the rows it touched. Pass `null` for a builder
   * that has no `returning()`, so calling it fails loudly rather than passing.
   */
  const statement = (returned: Row[] | null) => {
    const base = { then: (onFulfilled: (v: undefined) => unknown) => Promise.resolve(undefined).then(onFulfilled) }
    return returned === null ? base : { ...base, returning: () => Promise.resolve(returned) }
  }

  const config: TestConfig = {
    db: {
      select: vi.fn(() => ({
        from: (tableRef: unknown) =>
          buildSelect(tableForRef(tableRef)) as unknown as ReturnType<TestConfig['db']['select']>['from'] extends (
            ...a: any
          ) => infer X
            ? X
            : never,
      })) as unknown as TestConfig['db']['select'],
      insert: vi.fn((tableRef: unknown) => {
        const table = tableForRef(tableRef)
        // What the unique index covers: `id` where the table has one, the
        // assignment triple otherwise. `onConflictDoNothing` has to skip a
        // duplicate rather than push it twice, or `RETURNING` would report a
        // row the database never wrote.
        const identity = (row: Row): string =>
          'id' in row ? String(row.id) : `${String(row.subjectId)} ${String(row.roleId)} ${String(row.scope ?? '')}`
        const insertNew = (data: Record<string, unknown> | Record<string, unknown>[]): Row[] => {
          const held = new Set(table.map(identity))
          const fresh: Row[] = []
          for (const row of Array.isArray(data) ? data : [data]) {
            if (held.has(identity(row))) continue
            held.add(identity(row))
            table.push({ ...row })
            fresh.push({ ...row })
          }
          return fresh
        }
        return {
          values(data: Record<string, unknown> | Record<string, unknown>[]) {
            return {
              onConflictDoUpdate({ set }: { target: unknown; set: Record<string, unknown> }) {
                if (Array.isArray(data)) throw new Error('the onConflictDoUpdate mock takes a single row')
                const idCol = (data as { id?: string; subjectId?: string }).id ?? data.subjectId
                const idKey = 'id' in data ? 'id' : 'subjectId'
                const idx = table.findIndex((r) => r[idKey] === idCol)
                if (idx >= 0) table[idx] = { ...table[idx], ...set }
                else table.push({ ...data })
                return Promise.resolve(undefined)
              },
              onConflictDoNothing() {
                return statement(insertNew(data))
              },
            }
          },
        }
      }) as unknown as TestConfig['db']['insert'],
      update: vi.fn((tableRef: unknown) => {
        const table = tableForRef(tableRef)
        return {
          set(data: Record<string, unknown>) {
            return {
              where(c: unknown) {
                for (let i = 0; i < table.length; i++) {
                  if (rowMatches(table[i]!, c)) table[i] = { ...table[i], ...data }
                }
                return Promise.resolve(undefined)
              },
            }
          },
        }
      }) as unknown as TestConfig['db']['update'],
      delete: vi.fn((tableRef: unknown) => {
        const table = tableForRef(tableRef)
        return {
          where(c: unknown) {
            const removed: Row[] = []
            for (let i = table.length - 1; i >= 0; i--) {
              if (rowMatches(table[i]!, c)) removed.unshift(...table.splice(i, 1))
            }
            return statement(removed)
          },
        }
      }) as unknown as TestConfig['db']['delete'],
    },
    tables: tableRefs,
    ops: {
      eq: (col, val) => ({ type: 'eq', args: [col, val] }),
      and: (...conditions) => ({ type: 'and', args: conditions }) as unknown as SQL<unknown>,
    },
  }

  return { config, tables }
}

// IamAdapter compliance - fresh mock per call.
runAdapterCompliance('IamDrizzleAdapter', () => new IamDrizzleAdapter(makeDrizzleMock().config))

describe('IamDrizzleAdapter', () => {
  let mock: ReturnType<typeof makeDrizzleMock>
  let adapter: IamDrizzleAdapter<A, R, Ro, S>

  beforeEach(() => {
    mock = makeDrizzleMock()
    adapter = new IamDrizzleAdapter<A, R, Ro, S>(mock.config)
  })

  describe('IamAdapter.IPolicyStore', () => {
    const policy: AccessControl.IPolicy<A, R, Ro> = {
      id: 'p1',
      name: 'Test AccessControl.IPolicy',
      description: 'desc',
      version: 2,
      algorithm: 'deny-overrides',
      rules: [],
      targets: { actions: ['read'] },
    }

    it('listPolicies starts empty', async () => {
      expect(await adapter.listPolicies()).toEqual([])
    })

    it('savePolicy + listPolicies roundtrip with JSON serialization', async () => {
      await adapter.savePolicy(policy)
      const list = await adapter.listPolicies()
      expect(list).toHaveLength(1)
      expect(list[0]?.id).toBe('p1')
      expect(list[0]?.targets).toEqual({ actions: ['read'] })
    })

    it('rules and targets stored as native JSON by default', async () => {
      await adapter.savePolicy(policy)
      const raw = mock.tables.policies[0]!
      expect(raw.rules).toEqual([])
      expect(raw.targets).toEqual({ actions: ['read'] })
    })

    it('rules and targets stringified in json:string mode', async () => {
      const m = makeDrizzleMock()
      const a = new IamDrizzleAdapter<A, R, Ro, S>({ ...m.config, json: 'string' })
      await a.savePolicy(policy)
      const raw = m.tables.policies[0]!
      expect(typeof raw.rules).toBe('string')
      expect(typeof raw.targets).toBe('string')
      expect(JSON.parse(raw.rules as string)).toEqual([])
    })

    it('parsePolicy handles object form (already deserialized JSON)', async () => {
      mock.tables.policies.push({
        id: 'pre',
        name: 'Pre',
        description: null,
        version: 1,
        algorithm: 'allow-overrides',
        rules: [
          { id: 'r1', actions: ['read'], resources: ['post'], effect: 'allow', conditions: { all: [] }, priority: 0 },
        ],
        targets: null,
      })
      const got = await adapter.getPolicy('pre')
      expect(got?.rules).toHaveLength(1)
      expect(got?.targets).toBeUndefined()
    })

    it('getPolicy returns null when missing', async () => {
      expect(await adapter.getPolicy('nope')).toBeNull()
    })

    it('savePolicy normalizes optionals', async () => {
      await adapter.savePolicy({
        id: 'p2',
        name: 'Bare',
        algorithm: 'first-match',
        rules: [],
      })
      const raw = mock.tables.policies[0]!
      expect(raw.description).toBeNull()
      expect(raw.targets).toBeNull()
      expect(raw.version).toBe(1)
    })

    it('savePolicy upserts existing row by id', async () => {
      await adapter.savePolicy(policy)
      await adapter.savePolicy({ ...policy, name: 'Updated' })
      expect(mock.tables.policies).toHaveLength(1)
      const got = await adapter.getPolicy('p1')
      expect(got?.name).toBe('Updated')
    })

    it('deletePolicy removes row', async () => {
      await adapter.savePolicy(policy)
      await adapter.deletePolicy('p1')
      expect(await adapter.listPolicies()).toEqual([])
    })
  })

  describe('IamAdapter.IRoleStore', () => {
    const role: AccessControl.IRole<A, R, Ro, S> = {
      id: 'editor',
      name: 'Editor',
      description: 'desc',
      permissions: [{ action: 'write', resource: 'post' }],
      inherits: ['viewer'] as Ro[],
      scope: 'org-1',
      metadata: { color: 'blue' },
    }

    it('saveRole stores native JSON columns by default', async () => {
      await adapter.saveRole(role)
      const raw = mock.tables.roles[0]!
      expect(raw.permissions).toEqual([{ action: 'write', resource: 'post' }])
      expect(raw.inherits).toEqual(['viewer'])
      expect(raw.metadata).toEqual({ color: 'blue' })
    })

    it('saveRole stringifies JSON columns in json:string mode', async () => {
      const m = makeDrizzleMock()
      const a = new IamDrizzleAdapter<A, R, Ro, S>({ ...m.config, json: 'string' })
      await a.saveRole(role)
      const raw = m.tables.roles[0]!
      expect(typeof raw.permissions).toBe('string')
      expect(typeof raw.inherits).toBe('string')
      expect(typeof raw.metadata).toBe('string')
    })

    it('getRole roundtrip parses JSON columns', async () => {
      await adapter.saveRole(role)
      const got = await adapter.getRole('editor')
      expect(got?.permissions).toEqual([{ action: 'write', resource: 'post' }])
      expect(got?.inherits).toEqual(['viewer'])
      expect(got?.metadata).toEqual({ color: 'blue' })
    })

    it('parseRole handles already-parsed objects', async () => {
      mock.tables.roles.push({
        id: 'pre',
        name: 'Pre',
        description: null,
        permissions: [{ action: 'read', resource: 'post' }],
        inherits: ['viewer'],
        scope: null,
        metadata: null,
      })
      const got = await adapter.getRole('pre')
      expect(got?.permissions).toEqual([{ action: 'read', resource: 'post' }])
      expect(got?.inherits).toEqual(['viewer'])
    })

    it('saveRole normalizes empty inherits', async () => {
      await adapter.saveRole({ id: 'r1' as Ro, name: 'R', permissions: [] })
      const raw = mock.tables.roles[0]!
      expect(raw.inherits).toEqual([])
      expect(raw.scope).toBeNull()
      expect(raw.metadata).toBeNull()
    })

    it('getRole null when missing', async () => {
      expect(await adapter.getRole('nope')).toBeNull()
    })

    it('listRoles returns parsed array', async () => {
      await adapter.saveRole(role)
      const list = await adapter.listRoles()
      expect(list).toHaveLength(1)
      expect(list[0]?.id).toBe('editor')
    })

    it('deleteRole removes', async () => {
      await adapter.saveRole(role)
      await adapter.deleteRole('editor')
      expect(await adapter.listRoles()).toEqual([])
    })
  })

  describe('IamAdapter.ISubjectStore', () => {
    it('assignRole + getSubjectRoles dedups', async () => {
      await adapter.assignRole('user-1', 'editor' as Ro)
      await adapter.assignRole('user-1', 'editor' as Ro, 'org-1')
      await adapter.assignRole('user-1', 'viewer' as Ro)
      const out = await adapter.getSubjectRoles('user-1')
      expect(out.sort()).toEqual(['editor', 'viewer'])
    })

    it('getSubjectRoles returns ONLY unscoped roles, not scoped', async () => {
      await adapter.assignRole('user-1', 'viewer' as Ro)
      await adapter.assignRole('user-1', 'editor' as Ro, 'org-1')
      const unscoped = await adapter.getSubjectRoles('user-1')
      expect(unscoped).toEqual(['viewer'])
      const scoped = await adapter.getSubjectScopedRoles('user-1')
      expect(scoped).toEqual([{ role: 'editor', scope: 'org-1' }])
    })

    it('getSubjectScopedRoles only returns scoped assignments', async () => {
      await adapter.assignRole('user-1', 'editor' as Ro)
      await adapter.assignRole('user-1', 'editor' as Ro, 'org-1')
      const scoped = await adapter.getSubjectScopedRoles('user-1')
      expect(scoped).toEqual([{ role: 'editor', scope: 'org-1' }])
    })

    it('revokeRole without scope clears all matching assignments', async () => {
      await adapter.assignRole('user-1', 'editor' as Ro)
      await adapter.assignRole('user-1', 'editor' as Ro, 'org-1')
      await adapter.assignRole('user-1', 'editor' as Ro, 'org-2')
      await adapter.revokeRole('user-1', 'editor' as Ro)
      expect(await adapter.getSubjectRoles('user-1')).toEqual([])
    })

    it('revokeRole with an empty-string scope targets only that scope, never all', async () => {
      await adapter.assignRole('user-1', 'editor' as Ro)
      await adapter.assignRole('user-1', 'editor' as Ro, 'org-1')
      await adapter.revokeRole('user-1', 'editor' as Ro, '' as S)
      expect(await adapter.getSubjectRoles('user-1')).toEqual(['editor'])
      expect((await adapter.getSubjectScopedRoles('user-1')).map((r) => r.scope)).toEqual(['org-1'])
    })

    it('revokeRole with scope only clears scoped assignment', async () => {
      await adapter.assignRole('user-1', 'editor' as Ro)
      await adapter.assignRole('user-1', 'editor' as Ro, 'org-1')
      await adapter.revokeRole('user-1', 'editor' as Ro, 'org-1')
      const scoped = await adapter.getSubjectScopedRoles('user-1')
      expect(scoped).toEqual([])
    })

    it('assignRoleMany reports only the grants it created', async () => {
      await adapter.assignRole('user-1', 'editor' as Ro)

      const changed = await adapter.assignRoleMany([
        { roleId: 'editor' as Ro, subjectId: 'user-1' },
        { roleId: 'viewer' as Ro, subjectId: 'user-1' },
      ])

      // Both grants are in place afterwards; only the second is one this call
      // made. The conflict clause skipped the first, so `RETURNING` never
      // named it.
      expect(changed?.map((r) => r.roleId)).toEqual(['viewer'])
      expect((await adapter.getSubjectRoles('user-1')).sort()).toEqual(['editor', 'viewer'])
    })

    it('revokeRoleMany reports nothing for a triple that was never granted', async () => {
      await adapter.assignRole('user-1', 'editor' as Ro)

      const changed = await adapter.revokeRoleMany([
        { roleId: 'editor' as Ro, subjectId: 'user-1' },
        { roleId: 'viewer' as Ro, subjectId: 'user-1' },
      ])

      expect(changed?.map((r) => r.roleId)).toEqual(['editor'])
    })

    it('revokeRoleMany keeps an unscoped row distinct from one scoped to the empty string', async () => {
      // `scope` is NULL for this row, not `''` - the two are different rows,
      // which `revokeRole` already distinguishes.
      await adapter.assignRole('user-1', 'editor' as Ro)

      const changed = await adapter.revokeRoleMany([
        { roleId: 'editor' as Ro, scope: '' as S, subjectId: 'user-1' },
        { roleId: 'editor' as Ro, subjectId: 'user-1' },
      ])

      // The second request is what removed the row. The first named a scope no
      // row held, so it changed nothing - even though both requests name the
      // same subject and role, and the engine's outcome id cannot tell them
      // apart.
      expect(changed?.map((r) => r.scope)).toEqual([undefined])
      expect(await adapter.getSubjectRoles('user-1')).toEqual([])
    })

    it('getSubjectAttributes returns {} when missing', async () => {
      expect(await adapter.getSubjectAttributes('nobody')).toEqual({})
    })

    it('setSubjectAttributes merges and stringifies', async () => {
      await adapter.setSubjectAttributes('user-1', { team: 'A' })
      await adapter.setSubjectAttributes('user-1', { plan: 'pro' })
      const got = await adapter.getSubjectAttributes('user-1')
      expect(got).toEqual({ team: 'A', plan: 'pro' })
      expect(mock.tables.attrs[0]?.data).toEqual({ team: 'A', plan: 'pro' })
    })

    it('setSubjectAttributes stringifies in json:string mode', async () => {
      const m = makeDrizzleMock()
      const a = new IamDrizzleAdapter<A, R, Ro, S>({ ...m.config, json: 'string' })
      await a.setSubjectAttributes('user-1', { team: 'A' })
      expect(typeof m.tables.attrs[0]?.data).toBe('string')
      expect(await a.getSubjectAttributes('user-1')).toEqual({ team: 'A' })
    })

    it('getSubjectAttributes parses string blob', async () => {
      mock.tables.attrs.push({ subjectId: 'pre', data: JSON.stringify({ x: 1 }) })
      expect(await adapter.getSubjectAttributes('pre')).toEqual({ x: 1 })
    })

    it('getSubjectAttributes accepts object blob', async () => {
      mock.tables.attrs.push({ subjectId: 'pre', data: { x: 2 } })
      expect(await adapter.getSubjectAttributes('pre')).toEqual({ x: 2 })
    })

    it('getSubjectAttributes throws on corrupt JSON string', async () => {
      mock.tables.attrs.push({ subjectId: 'corrupt', data: '{not-json' })
      await expect(adapter.getSubjectAttributes('corrupt')).rejects.toThrow(/corrupted attributes/)
    })

    it('setSubjectAttributes recovers from corrupt existing blob', async () => {
      mock.tables.attrs.push({ subjectId: 'corrupt', data: '{not-json' })
      await adapter.setSubjectAttributes('corrupt', { team: 'A' })
      expect(await adapter.getSubjectAttributes('corrupt')).toEqual({ team: 'A' })
    })
  })

  describe('malformed-row drop (P0)', () => {
    // IamDrizzle's JSON-stringified columns can desync from the row shape via
    // partial migrations or manual SQL edits. The adapter must validate +
    // drop instead of letting a corrupt row escape into the evaluator.
    it('drops a policy row whose rules column is unparseable', async () => {
      const errors: Array<{ rowId: string }> = []
      const mock = makeDrizzleMock()
      const adapter = new IamDrizzleAdapter<A, R, Ro, S>({
        ...mock.config,
        onPolicyError: (_err, ctx) => errors.push({ rowId: ctx.rowId }),
      })
      // Seed one good row + one with a corrupt JSON column.
      mock.tables.policies.push({
        id: 'good',
        name: 'good',
        description: null,
        version: 1,
        algorithm: 'deny-overrides',
        rules: '[]',
        targets: null,
      })
      mock.tables.policies.push({
        id: 'bad',
        name: 'bad',
        description: null,
        version: 1,
        algorithm: 'deny-overrides',
        rules: '{not json',
        targets: null,
      })

      const list = await adapter.listPolicies()
      expect(list.map((p) => p.id)).toEqual(['good'])
      expect(errors[0]?.rowId).toBe('bad')
    })

    it('drops a policy row that parses but fails shape validation', async () => {
      const errors: Array<{ rowId: string }> = []
      const mock = makeDrizzleMock()
      const adapter = new IamDrizzleAdapter<A, R, Ro, S>({
        ...mock.config,
        onPolicyError: (_err, ctx) => errors.push({ rowId: ctx.rowId }),
      })
      // Invalid algorithm => shape validation rejects.
      mock.tables.policies.push({
        id: 'bad-algo',
        name: 'bad',
        description: null,
        version: 1,
        algorithm: 'not-an-algorithm',
        rules: '[]',
        targets: null,
      })
      const list = await adapter.listPolicies()
      expect(list).toEqual([])
      expect(errors[0]?.rowId).toBe('bad-algo')
    })

    it('drops a role row whose permissions column is unparseable', async () => {
      const errors: Array<{ rowId: string }> = []
      const mock = makeDrizzleMock()
      const adapter = new IamDrizzleAdapter<A, R, Ro, S>({
        ...mock.config,
        onPolicyError: (_err, ctx) => errors.push({ rowId: ctx.rowId }),
      })
      mock.tables.roles.push({
        id: 'good',
        name: 'g',
        description: null,
        permissions: '[]',
        inherits: '[]',
        scope: null,
        metadata: null,
      })
      mock.tables.roles.push({
        id: 'bad',
        name: 'b',
        description: null,
        permissions: '{not json',
        inherits: '[]',
        scope: null,
        metadata: null,
      })
      const list = await adapter.listRoles()
      expect(list.map((r) => r.id)).toEqual(['good'])
      expect(errors[0]?.rowId).toBe('bad')
    })

    it('getPolicy returns null when row fails validation', async () => {
      const errors: Array<{ rowId: string }> = []
      const mock = makeDrizzleMock()
      const adapter = new IamDrizzleAdapter<A, R, Ro, S>({
        ...mock.config,
        onPolicyError: (_err, ctx) => errors.push({ rowId: ctx.rowId }),
      })
      mock.tables.policies.push({
        id: 'bad',
        name: 'bad',
        description: null,
        version: 1,
        algorithm: 'deny-overrides',
        rules: '{not json',
        targets: null,
      })
      expect(await adapter.getPolicy('bad')).toBeNull()
      expect(errors[0]?.rowId).toBe('bad')
    })
  })

  describe('mysql dialect', () => {
    // MySQL has no `ON CONFLICT` clause. `assignRole` uses `.ignore()` +
    // `.values(...)` (its real insert-or-skip chain). `savePolicy`/
    // `saveRole`/`setSubjectAttributes` upsert via select-then-branch
    // instead of a blanket `.onDuplicateKeyUpdate(...)`: that fires on
    // *any* unique-index violation, not just the target column, so a fresh
    // id colliding with an unrelated row's `name` (`iamPolicies`) or
    // `name`+`scope` (`iamRoles`) would silently overwrite that row - id
    // included - instead of erroring like pg/sqlite's target-scoped
    // `onConflictDoUpdate`. This mock implements only mysql's real
    // `ignore()`/plain-`values()`/`select().from().where().limit()`/
    // `update().set().where()` chains, not `onConflictDoUpdate()`/
    // `onConflictDoNothing()` - a regression back to those fails loudly
    // instead of silently passing.
    function makeMysqlMock() {
      const tables = { policies: [] as Row[], roles: [] as Row[], assignments: [] as Row[], attrs: [] as Row[] }
      const tableRefs = {
        policies: { id: { name: 'id' } },
        roles: { id: { name: 'id' } },
        assignments: { subjectId: { name: 'subjectId' }, roleId: { name: 'roleId' } },
        attrs: { subjectId: { name: 'subjectId' } },
      }
      const tableForRef = (ref: unknown): Row[] => {
        for (const [key, val] of Object.entries(tableRefs)) {
          if (val === ref) return tables[key as keyof typeof tables]
        }
        throw new Error('unknown table ref')
      }
      type EqCond = { type: 'eq'; args: [{ name: string }, unknown] }
      const config: MysqlTestConfig = {
        dialect: 'mysql',
        db: {
          insert: vi.fn((tableRef: unknown) => {
            const table = tableForRef(tableRef)
            return {
              // `.ignore().values(...)` - MySQL's insert-or-skip chain
              // (assignRole, assignRoleMany). It returns a bare promise, with
              // no `returning()`: MySQL has none, so an adapter that reached
              // for one here would fail loudly.
              ignore() {
                return {
                  values(data: Record<string, unknown> | Record<string, unknown>[]) {
                    for (const row of Array.isArray(data) ? data : [data]) table.push({ ...row })
                    return Promise.resolve(undefined)
                  },
                }
              },
              // Plain `.values(...)` - the insert half of the select-then-branch upsert.
              values(data: Record<string, unknown>) {
                table.push({ ...data })
                return Promise.resolve(undefined)
              },
            }
          }) as unknown as MysqlTestConfig['db']['insert'],
          select: vi.fn(() => ({
            from: (tableRef: unknown) => {
              const table = tableForRef(tableRef)
              return {
                where: (cond: EqCond) => ({
                  limit: (_n: number) => {
                    const [col, val] = cond.args
                    return table.filter((r) => r[col.name] === val)
                  },
                }),
              }
            },
          })) as unknown as MysqlTestConfig['db']['select'],
          update: vi.fn((tableRef: unknown) => {
            const table = tableForRef(tableRef)
            return {
              set: (set: Record<string, unknown>) => ({
                where: (cond: EqCond) => {
                  const [col, val] = cond.args
                  const idx = table.findIndex((r) => r[col.name] === val)
                  if (idx >= 0) table[idx] = { ...table[idx], ...set }
                  return Promise.resolve(undefined)
                },
              }),
            }
          }) as unknown as MysqlTestConfig['db']['update'],
          delete: vi.fn((tableRef: unknown) => {
            const table = tableForRef(tableRef)
            return {
              // Also `returning()`-free, for the same reason as `ignore()`.
              where: (cond: unknown) => {
                for (let i = table.length - 1; i >= 0; i--) {
                  if (rowMatches(table[i]!, cond)) table.splice(i, 1)
                }
                return Promise.resolve(undefined)
              },
            }
          }) as unknown as MysqlTestConfig['db']['delete'],
        },
        tables: tableRefs as unknown as MysqlTestConfig['tables'],
        ops: {
          eq: (col, val) => ({ type: 'eq', args: [col, val] }),
          and: (...c) => ({ type: 'and', args: c }) as unknown as SQL,
        },
      }
      return { config, tables }
    }

    it('savePolicy inserts a new row via select-then-insert, not onConflictDoUpdate', async () => {
      const mock = makeMysqlMock()
      const adapter = new IamDrizzleAdapter<A, R, Ro, S, IamDrizzle.AnyDrizzleDb, 'mysql'>(mock.config)
      await adapter.savePolicy({
        id: 'p1',
        name: 'p1',
        version: 1,
        algorithm: 'deny-overrides',
        rules: [],
      } as unknown as AccessControl.IPolicy<A, R, Ro>)
      expect(mock.tables.policies).toHaveLength(1)
    })

    it('saveRole with a new id inserts a new row, even if an existing row shares its name', async () => {
      const mock = makeMysqlMock()
      const adapter = new IamDrizzleAdapter<A, R, Ro, S, IamDrizzle.AnyDrizzleDb, 'mysql'>(mock.config)
      await adapter.saveRole({ id: 'r1' as Ro, name: 'editor', permissions: [] })
      await adapter.saveRole({ id: 'r2' as Ro, name: 'editor', permissions: [] })

      // Two distinct rows, not one overwritten via a name match. Real
      // MySQL's `ON DUPLICATE KEY UPDATE` would instead collide on the
      // `name`+`scope` unique index and silently rewrite r1's row (id
      // included) with r2's data; the adapter never reaches that path
      // because it keys strictly on `id`.
      expect(mock.tables.roles).toHaveLength(2)
      expect(mock.tables.roles.map((r) => r.id)).toEqual(['r1', 'r2'])
    })

    it('saveRole with an existing id updates that row in place', async () => {
      const mock = makeMysqlMock()
      const adapter = new IamDrizzleAdapter<A, R, Ro, S, IamDrizzle.AnyDrizzleDb, 'mysql'>(mock.config)
      await adapter.saveRole({ id: 'r1' as Ro, name: 'editor', permissions: [] })
      await adapter.saveRole({ id: 'r1' as Ro, name: 'editor-v2', permissions: [] })

      expect(mock.tables.roles).toHaveLength(1)
      expect(mock.tables.roles[0]?.name).toBe('editor-v2')
    })

    it('assignRole inserts via ignore(), not onConflictDoNothing', async () => {
      const mock = makeMysqlMock()
      const adapter = new IamDrizzleAdapter<A, R, Ro, S, IamDrizzle.AnyDrizzleDb, 'mysql'>(mock.config)
      await adapter.assignRole('u1', 'editor' as Ro)
      expect(mock.tables.assignments).toHaveLength(1)
    })

    it('assignRoleMany writes every row and answers null, having no RETURNING to read', async () => {
      const mock = makeMysqlMock()
      const adapter = new IamDrizzleAdapter<A, R, Ro, S, IamDrizzle.AnyDrizzleDb, 'mysql'>(mock.config)

      const changed = await adapter.assignRoleMany([
        { roleId: 'editor' as Ro, subjectId: 'u1' },
        { roleId: 'viewer' as Ro, subjectId: 'u2' },
      ])

      // `null` is not "nothing was written" - both rows landed. It says the
      // driver cannot name which of them were new, so the engine leaves
      // `changed` off rather than guessing. The mock's `ignore()` chain has no
      // `returning()`, so an adapter that reached for one here would throw.
      expect(changed).toBeNull()
      expect(mock.tables.assignments).toHaveLength(2)
    })

    it('revokeRoleMany removes every row and answers null', async () => {
      const mock = makeMysqlMock()
      const adapter = new IamDrizzleAdapter<A, R, Ro, S, IamDrizzle.AnyDrizzleDb, 'mysql'>(mock.config)
      await adapter.assignRole('u1', 'editor' as Ro)
      await adapter.assignRole('u2', 'viewer' as Ro)

      const changed = await adapter.revokeRoleMany([
        { roleId: 'editor' as Ro, subjectId: 'u1' },
        { roleId: 'viewer' as Ro, subjectId: 'u2' },
      ])

      expect(changed).toBeNull()
      expect(mock.tables.assignments).toHaveLength(0)
    })

    it('setSubjectAttributes upserts on subjectId via select-then-branch', async () => {
      const mock = makeMysqlMock()
      const adapter = new IamDrizzleAdapter<A, R, Ro, S, IamDrizzle.AnyDrizzleDb, 'mysql'>(mock.config)
      await adapter.setSubjectAttributes('u1', { tier: 'gold' })
      expect(mock.tables.attrs).toHaveLength(1)
    })
  })

  describe('factories', () => {
    it('iamDrizzleAdapter builds an adapter equivalent to `new IamDrizzleAdapter(...)`', async () => {
      const m = makeDrizzleMock()
      const built = iamDrizzleAdapter<A, R, Ro, S>(m.config)
      expect(built).toBeInstanceOf(IamDrizzleAdapter)
      await built.savePolicy({ algorithm: 'deny-overrides', id: 'p1', name: 'P', rules: [] })
      expect((await built.listPolicies()).map((p) => p.id)).toEqual(['p1'])
    })

    it('createIamDrizzleAdapter builds an adapter bound to the config it was handed', async () => {
      const m = makeDrizzleMock()
      const built = createIamDrizzleAdapter<IamConfig.IAccessConfig<A, R, Ro, S>, IamDrizzle.AnyDrizzleDb>(m.config)
      expect(built).toBeInstanceOf(IamDrizzleAdapter)
      await built.saveRole({ id: 'editor', name: 'Editor', permissions: [] })
      expect(m.tables.roles.map((r) => r.id)).toEqual(['editor'])
    })

    it('each factory call gets its own db, not a shared one', async () => {
      const a = iamDrizzleAdapter<A, R, Ro, S>(makeDrizzleMock().config)
      const b = iamDrizzleAdapter<A, R, Ro, S>(makeDrizzleMock().config)
      await a.savePolicy({ algorithm: 'deny-overrides', id: 'p1', name: 'P', rules: [] })
      expect(await b.listPolicies()).toEqual([])
    })
  })
})
