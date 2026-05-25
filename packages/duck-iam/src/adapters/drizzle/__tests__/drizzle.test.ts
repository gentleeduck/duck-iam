import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { AccessControl, Adapter } from '../../../core/types'
import { runAdapterCompliance } from '../../__compliance__/compliance'
import { type Drizzle, DrizzleAdapter } from '../index'

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
  config: Drizzle.IConfig
  tables: { policies: Row[]; roles: Row[]; assignments: Row[]; attrs: Row[] }
} {
  const tables = {
    policies: [] as Row[],
    roles: [] as Row[],
    assignments: [] as Row[],
    attrs: [] as Row[],
  }

  const tableRefs: Drizzle.IConfig['tables'] = {
    policies: { id: { name: 'id' } },
    roles: { id: { name: 'id' } },
    assignments: {
      id: { name: 'id' },
      subjectId: { name: 'subjectId' },
      roleId: { name: 'roleId' },
      scope: { name: 'scope' },
    },
    attrs: { id: { name: 'id' }, subjectId: { name: 'subjectId' } },
  }

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

  const config: Drizzle.IConfig = {
    db: {
      select: vi.fn(() => ({
        from: (tableRef: unknown) =>
          buildSelect(tableForRef(tableRef)) as unknown as ReturnType<Drizzle.IConfig['db']['select']>['from'] extends (
            ...a: any
          ) => infer X
            ? X
            : never,
      })) as unknown as Drizzle.IConfig['db']['select'],
      insert: vi.fn((tableRef: unknown) => {
        const table = tableForRef(tableRef)
        return {
          values(data: Record<string, unknown>) {
            return {
              onConflictDoUpdate({ set }: { target: unknown; set: Record<string, unknown> }) {
                const idCol = (data as { id?: string; subjectId?: string }).id ?? data.subjectId
                const idKey = 'id' in data ? 'id' : 'subjectId'
                const idx = table.findIndex((r) => r[idKey] === idCol)
                if (idx >= 0) table[idx] = { ...table[idx], ...set }
                else table.push({ ...data })
                return Promise.resolve(undefined)
              },
              onConflictDoNothing() {
                table.push({ ...data })
                return Promise.resolve(undefined)
              },
            }
          },
        }
      }) as unknown as Drizzle.IConfig['db']['insert'],
      delete: vi.fn((tableRef: unknown) => {
        const table = tableForRef(tableRef)
        return {
          where(c: unknown) {
            for (let i = table.length - 1; i >= 0; i--) {
              if (rowMatches(table[i]!, c)) table.splice(i, 1)
            }
            return Promise.resolve(undefined)
          },
        }
      }) as unknown as Drizzle.IConfig['db']['delete'],
    },
    tables: tableRefs,
    ops: {
      eq: (col, val) => ({ type: 'eq', args: [col, val] }),
      and: (...conditions) => ({ type: 'and', args: conditions }),
    },
  }

  return { config, tables }
}

// Adapter compliance - fresh mock per call.
runAdapterCompliance('DrizzleAdapter', () => new DrizzleAdapter(makeDrizzleMock().config) as never)

describe('DrizzleAdapter', () => {
  let mock: ReturnType<typeof makeDrizzleMock>
  let adapter: DrizzleAdapter<A, R, Ro, S>

  beforeEach(() => {
    mock = makeDrizzleMock()
    adapter = new DrizzleAdapter<A, R, Ro, S>(mock.config)
  })

  describe('Adapter.IPolicyStore', () => {
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

    it('rules and targets stored as JSON strings', async () => {
      await adapter.savePolicy(policy)
      const raw = mock.tables.policies[0]!
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

  describe('Adapter.IRoleStore', () => {
    const role: AccessControl.IRole<A, R, Ro, S> = {
      id: 'editor',
      name: 'Editor',
      description: 'desc',
      permissions: [{ action: 'write', resource: 'post' }],
      inherits: ['viewer'] as Ro[],
      scope: 'org-1',
      metadata: { color: 'blue' },
    }

    it('saveRole serializes JSON columns', async () => {
      await adapter.saveRole(role)
      const raw = mock.tables.roles[0]!
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
      expect(raw.inherits).toBe(JSON.stringify([]))
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

  describe('Adapter.ISubjectStore', () => {
    it('assignRole + getSubjectRoles dedups', async () => {
      await adapter.assignRole('user-1', 'editor' as Ro)
      await adapter.assignRole('user-1', 'editor' as Ro, 'org-1')
      await adapter.assignRole('user-1', 'viewer' as Ro)
      const out = await adapter.getSubjectRoles('user-1')
      expect(out.sort()).toEqual(['editor', 'viewer'])
    })

    it('getSubjectRoles returns ONLY unscoped roles, not scoped (SEC-059)', async () => {
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

    it('revokeRole with scope only clears scoped assignment', async () => {
      await adapter.assignRole('user-1', 'editor' as Ro)
      await adapter.assignRole('user-1', 'editor' as Ro, 'org-1')
      await adapter.revokeRole('user-1', 'editor' as Ro, 'org-1')
      const scoped = await adapter.getSubjectScopedRoles('user-1')
      expect(scoped).toEqual([])
    })

    it('getSubjectAttributes returns {} when missing', async () => {
      expect(await adapter.getSubjectAttributes('nobody')).toEqual({})
    })

    it('setSubjectAttributes merges and stringifies', async () => {
      await adapter.setSubjectAttributes('user-1', { team: 'A' })
      await adapter.setSubjectAttributes('user-1', { plan: 'pro' })
      const got = await adapter.getSubjectAttributes('user-1')
      expect(got).toEqual({ team: 'A', plan: 'pro' })
      // Stored as string
      expect(typeof mock.tables.attrs[0]?.data).toBe('string')
    })

    it('getSubjectAttributes parses string blob', async () => {
      mock.tables.attrs.push({ subjectId: 'pre', data: JSON.stringify({ x: 1 }) })
      expect(await adapter.getSubjectAttributes('pre')).toEqual({ x: 1 })
    })

    it('getSubjectAttributes accepts object blob', async () => {
      mock.tables.attrs.push({ subjectId: 'pre', data: { x: 2 } })
      expect(await adapter.getSubjectAttributes('pre')).toEqual({ x: 2 })
    })

    it('getSubjectAttributes throws on corrupt JSON string (SEC-058)', async () => {
      mock.tables.attrs.push({ subjectId: 'corrupt', data: '{not-json' })
      await expect(adapter.getSubjectAttributes('corrupt')).rejects.toThrow(/corrupted attributes/)
    })

    it('setSubjectAttributes recovers from corrupt existing blob (SEC-067)', async () => {
      mock.tables.attrs.push({ subjectId: 'corrupt', data: '{not-json' })
      await adapter.setSubjectAttributes('corrupt', { team: 'A' })
      expect(await adapter.getSubjectAttributes('corrupt')).toEqual({ team: 'A' })
    })
  })

  describe('malformed-row drop (P0)', () => {
    // Drizzle's JSON-stringified columns can desync from the row shape via
    // partial migrations or manual SQL edits. The adapter must validate +
    // drop instead of letting a corrupt row escape into the evaluator.
    it('drops a policy row whose rules column is unparseable', async () => {
      const errors: Array<{ rowId: string }> = []
      const mock = makeDrizzleMock()
      const adapter = new DrizzleAdapter<A, R, Ro, S>({
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
      const adapter = new DrizzleAdapter<A, R, Ro, S>({
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
      const adapter = new DrizzleAdapter<A, R, Ro, S>({
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
      const adapter = new DrizzleAdapter<A, R, Ro, S>({
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
})
