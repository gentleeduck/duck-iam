/**
 * E2E: `scopeMode` / `scopeCombine` semantics and store-order independence,
 * against REAL Postgres.
 *
 * Two questions:
 *
 * 1. The same catalog under `flat` and `hierarchical`, and under `union` and
 *    `override` - where do the answers differ, and is each difference the one
 *    the config flag promises?
 * 2. A store returns rows in whatever order it likes. Postgres has no implicit
 *    ordering and none of the adapter's reads carry `ORDER BY`, so the physical
 *    row order is genuinely free. The resolved subject and every decision must
 *    be identical whatever order comes back - and the test proves the orders it
 *    compared really were different, rather than assuming they were.
 */
import { and, eq, or } from 'drizzle-orm'
import { drizzle } from 'drizzle-orm/node-postgres'
import { Pool } from 'pg'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { IamDrizzleAdapter } from '../../../adapters/drizzle'
import { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from '../../../adapters/drizzle/pg'
import { applyPgSchema, databaseUrl, isolatedDatabaseUrl } from '../../../test/e2e-env'
import { IamEngine } from '../../engine'

const BASE_URL = databaseUrl()
const URL = await isolatedDatabaseUrl('scope_modes_order')
if (BASE_URL !== undefined && URL === undefined) {
  throw new Error(
    '[e2e-scope] DUCKIAM_E2E_DATABASE_URL is set but an isolated database could not be created. ' +
      'Refusing to skip: a skipped suite is not a passing suite.',
  )
}
const suite = URL ? describe : describe.skip

type Action = 'read' | 'write'
type Resource = 'doc'

const TABLES = { assignments: iamAssignments, attrs: iamSubjectAttrs, policies: iamPolicies, roles: iamRoles }
const OPS = { and, eq, or }
const DOC = { attributes: {}, type: 'doc' as const }

/**
 * Reads one verdict out of a `permissions()` map. The map's key type is a
 * template literal over the declared action/resource/scope unions, and these
 * scopes are plain strings, so it cannot be indexed directly. Narrowed rather
 * than cast: an absent or non-boolean entry comes back as `undefined` and fails
 * the comparison loudly instead of being asserted into a boolean.
 */
function verdictFor(map: object, key: string): boolean | undefined {
  const value = Object.hasOwn(map, key) ? Reflect.get(map, key) : undefined
  return typeof value === 'boolean' ? value : undefined
}

interface RoleSeed {
  id: string
  inherits?: string[]
  permissions?: unknown[]
  scope?: string | null
}

suite('E2E scope: modes, combine, and store order on real Postgres', () => {
  let pool: Pool
  let db: ReturnType<typeof drizzle>
  let engineErrors: string[]

  beforeAll(async () => {
    pool = new Pool({ connectionString: URL })
    await applyPgSchema(pool)
    db = drizzle(pool)
  })

  afterAll(async () => {
    await pool.end()
  })

  beforeEach(async () => {
    await pool.query('TRUNCATE iam_assignments, iam_subject_attrs, iam_roles, iam_policies CASCADE')
    engineErrors = []
  })

  function makeEngine(opts: { scopeCombine?: 'union' | 'override'; scopeMode?: 'flat' | 'hierarchical' } = {}) {
    return new IamEngine<Action, Resource, string, string, 'development'>({
      adapter: new IamDrizzleAdapter<Action, Resource, string, string>({ db, ops: OPS, tables: TABLES }),
      hooks: {
        onError: (err) => {
          engineErrors.push(err.message)
        },
      },
      mode: 'development',
      scopeCombine: opts.scopeCombine ?? 'union',
      scopeMode: opts.scopeMode ?? 'flat',
    })
  }

  async function seedRole(role: RoleSeed): Promise<void> {
    await pool.query(
      'INSERT INTO iam_roles (id, name, permissions, inherits, scope) VALUES ($1, $2, $3::jsonb, $4::jsonb, $5)',
      [
        role.id,
        role.id,
        JSON.stringify(role.permissions ?? []),
        JSON.stringify(role.inherits ?? []),
        role.scope ?? null,
      ],
    )
  }

  async function seedAssignment(subjectId: string, roleId: string, scope: string | null): Promise<void> {
    await pool.query('INSERT INTO iam_assignments (id, subject_id, role_id, scope) VALUES ($1, $2, $3, $4)', [
      `${subjectId}|${roleId}|${scope ?? '-'}`,
      subjectId,
      roleId,
      scope,
    ])
  }

  const SCOPES = ['org-a', 'org-a.team-1', 'org-a.team-1.repo-9', 'org-a.team-2', 'org-ab', 'org', 'org-b']

  /** Every (action, scope) verdict for one subject, as a stable comparable object. */
  async function matrix(
    engine: IamEngine<Action, Resource, string, string, 'development'>,
    subjectId: string,
  ): Promise<Record<string, boolean | readonly string[]>> {
    const out: Record<string, boolean | readonly string[]> = {}
    for (const scope of [...SCOPES, undefined]) {
      const label = scope ?? '<none>'
      out[`roles@${label}`] = [...(await engine.getEffectiveRoles(subjectId, scope))].sort()
      for (const action of ['read', 'write'] as const) {
        out[`${action}@${label}`] = await engine.can(subjectId, action, DOC, undefined, scope)
      }
    }
    return out
  }

  describe('flat vs hierarchical on one catalog', () => {
    beforeEach(async () => {
      await seedRole({ id: 'admin', permissions: [{ action: 'write', resource: 'doc' }] })
      await seedRole({ id: 'viewer', permissions: [{ action: 'read', resource: 'doc' }] })
      await seedAssignment('u1', 'admin', 'org-a')
    })

    it('differs only by adding descendant scopes, never siblings or prefixes', async () => {
      const flat = await matrix(makeEngine({ scopeMode: 'flat' }), 'u1')
      const hier = await matrix(makeEngine({ scopeMode: 'hierarchical' }), 'u1')

      const differing = Object.keys(flat).filter((k) => JSON.stringify(flat[k]) !== JSON.stringify(hier[k]))
      // Every difference is a strict descendant of the assignment scope 'org-a'.
      expect(differing.sort()).toEqual(
        [
          'roles@org-a.team-1',
          'roles@org-a.team-1.repo-9',
          'roles@org-a.team-2',
          'write@org-a.team-1',
          'write@org-a.team-1.repo-9',
          'write@org-a.team-2',
        ].sort(),
      )
      // The role list widened, but only the permission the role actually holds
      // followed it: `read` stays denied at every descendant in both modes.
      for (const scope of ['org-a.team-1', 'org-a.team-1.repo-9', 'org-a.team-2']) {
        expect({ scope, v: hier[`read@${scope}`] }).toEqual({ scope, v: false })
        expect({ scope, v: hier[`write@${scope}`] }).toEqual({ scope, v: true })
        expect({ scope, v: flat[`write@${scope}`] }).toEqual({ scope, v: false })
      }
      // Prefix-shaped near misses are untouched by the mode switch.
      for (const k of ['write@org-ab', 'write@org', 'write@org-b', 'write@<none>']) {
        expect({ [k]: flat[k], mode: 'flat' }).toEqual({ [k]: false, mode: 'flat' })
        expect({ [k]: hier[k], mode: 'hier' }).toEqual({ [k]: false, mode: 'hier' })
      }
      expect(engineErrors).toEqual([])
    })

    it('a child scope whose parent grants nothing stays denied in both modes', async () => {
      await seedAssignment('u2', 'viewer', 'org-b.team-3')
      for (const scopeMode of ['flat', 'hierarchical'] as const) {
        const engine = makeEngine({ scopeMode })
        expect({ mode: scopeMode, v: await engine.can('u2', 'read', DOC, undefined, 'org-b') }).toEqual({
          mode: scopeMode,
          v: false,
        })
        expect({ mode: scopeMode, v: await engine.can('u2', 'read', DOC, undefined, 'org-b.team-4') }).toEqual({
          mode: scopeMode,
          v: false,
        })
      }
    })

    it('a role-declared scope obeys the same mode flag as an assignment scope', async () => {
      // `dept` declares org-a; the assignment is global. Under hierarchical the
      // declared scope must cover descendants, matching what the same flag does
      // for scoped assignments.
      await seedRole({ id: 'dept', permissions: [{ action: 'read', resource: 'doc' }], scope: 'org-a' })
      await seedAssignment('u3', 'dept', null)
      expect(await makeEngine({ scopeMode: 'flat' }).can('u3', 'read', DOC, undefined, 'org-a.team-1')).toBe(false)
      expect(await makeEngine({ scopeMode: 'hierarchical' }).can('u3', 'read', DOC, undefined, 'org-a.team-1')).toBe(
        true,
      )
      // And neither mode reaches a prefix-shaped sibling.
      expect(await makeEngine({ scopeMode: 'hierarchical' }).can('u3', 'read', DOC, undefined, 'org-ab')).toBe(false)
    })
  })

  describe('scopeCombine', () => {
    beforeEach(async () => {
      await seedRole({ id: 'admin', permissions: [{ action: 'write', resource: 'doc' }] })
      await seedRole({ id: 'viewer', permissions: [{ action: 'read', resource: 'doc' }] })
      await seedAssignment('u1', 'admin', 'org-a')
      await seedAssignment('u1', 'viewer', 'org-a.team-1')
    })

    it('union merges the ancestor grant with the specific one', async () => {
      const engine = makeEngine({ scopeCombine: 'union', scopeMode: 'hierarchical' })
      expect([...(await engine.getEffectiveRoles('u1', 'org-a.team-1'))].sort()).toEqual(['admin', 'viewer'])
      expect(await engine.can('u1', 'write', DOC, undefined, 'org-a.team-1')).toBe(true)
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-a.team-1')).toBe(true)
    })

    it('override keeps only the most specific level that has any grant', async () => {
      const engine = makeEngine({ scopeCombine: 'override', scopeMode: 'hierarchical' })
      expect(await engine.getEffectiveRoles('u1', 'org-a.team-1')).toEqual(['viewer'])
      expect(await engine.can('u1', 'write', DOC, undefined, 'org-a.team-1')).toBe(false)
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-a.team-1')).toBe(true)
      // A sibling with no grant of its own falls back to the ancestor level.
      expect(await engine.getEffectiveRoles('u1', 'org-a.team-2')).toEqual(['admin'])
      expect(await engine.can('u1', 'write', DOC, undefined, 'org-a.team-2')).toBe(true)
    })

    it('override never grants anything union would not', async () => {
      const union = await matrix(makeEngine({ scopeCombine: 'union', scopeMode: 'hierarchical' }), 'u1')
      const override = await matrix(makeEngine({ scopeCombine: 'override', scopeMode: 'hierarchical' }), 'u1')
      for (const [key, value] of Object.entries(override)) {
        if (typeof value === 'boolean' && value) {
          expect({ key, union: union[key] }).toEqual({ key, union: true })
        }
      }
    })

    it('scopeCombine is inert under flat scopeMode', async () => {
      const union = await matrix(makeEngine({ scopeCombine: 'union', scopeMode: 'flat' }), 'u1')
      const override = await matrix(makeEngine({ scopeCombine: 'override', scopeMode: 'flat' }), 'u1')
      expect(override).toEqual(union)
    })

    /**
     * OVERRIDE SHADOWING. `mgr` is assigned at `org-a` and inherits
     * `team-tools`, which DECLARES `org-a.team-1`. `resolveSubject` tags the
     * inherited role with its own declared scope, so the subject now has a
     * scoped role at `org-a.team-1` that nobody assigned there - and under
     * `override` that level wins, dropping `mgr` itself. The org-a manager
     * loses their own permission inside team-1.
     */
    it('an inherited role declared at a child scope shadows the parent assignment under override', async () => {
      await pool.query('TRUNCATE iam_assignments, iam_roles CASCADE')
      await seedRole({ id: 'team-tools', permissions: [{ action: 'read', resource: 'doc' }], scope: 'org-a.team-1' })
      await seedRole({ id: 'mgr', inherits: ['team-tools'], permissions: [{ action: 'write', resource: 'doc' }] })
      await seedAssignment('u9', 'mgr', 'org-a')

      const union = makeEngine({ scopeCombine: 'union', scopeMode: 'hierarchical' })
      expect([...(await union.getEffectiveRoles('u9', 'org-a.team-1'))].sort()).toEqual(['mgr', 'team-tools'])
      expect(await union.can('u9', 'write', DOC, undefined, 'org-a.team-1')).toBe(true)

      const override = makeEngine({ scopeCombine: 'override', scopeMode: 'hierarchical' })
      expect(await override.getEffectiveRoles('u9', 'org-a.team-1')).toEqual(['team-tools'])
      // Wrong deny: the manager's own grant at org-a is shadowed inside team-1
      // by a role they only hold there because they inherit it.
      expect(await override.can('u9', 'write', DOC, undefined, 'org-a.team-1')).toBe(false)
      expect(await override.can('u9', 'write', DOC, undefined, 'org-a')).toBe(true)
      expect(engineErrors).toEqual([])
    })

    it('permissions() batch matches can() under override', async () => {
      const engine = makeEngine({ scopeCombine: 'override', scopeMode: 'hierarchical' })
      const checks = SCOPES.flatMap((scope) => [
        { action: 'read' as const, resource: 'doc' as const, scope },
        { action: 'write' as const, resource: 'doc' as const, scope },
      ])
      const batch = await engine.permissions('u1', checks)
      for (const c of checks) {
        const key = `@${c.scope}:${c.action}:${c.resource}`
        expect({ key, value: verdictFor(batch, key) }).toEqual({
          key,
          value: await engine.can('u1', c.action, DOC, undefined, c.scope),
        })
      }
      expect(engineErrors).toEqual([])
    })
  })

  describe('order independence: the store decides what order rows come back in', () => {
    /**
     * A catalog whose answer would change if any traversal were order-sensitive:
     * a diamond with differently-scoped intermediates, a cycle, a role reached
     * at two different depths, and two scoped assignments at different levels.
     */
    const CATALOG: RoleSeed[] = [
      { id: 'inner', permissions: [{ action: 'read', resource: 'doc' }] },
      { id: 'left', inherits: ['inner'], permissions: [{ action: 'write', resource: 'doc' }], scope: 'org-a' },
      { id: 'right', inherits: ['inner'], scope: 'org-b' },
      { id: 'mid', inherits: ['left'] },
      { id: 'top', inherits: ['mid', 'right', 'inner'] },
      { id: 'cyc-a', inherits: ['cyc-b'] },
      { id: 'cyc-b', inherits: ['cyc-a', 'top'] },
    ]

    const ASSIGNMENTS: [role: string, scope: string | null][] = [
      ['top', 'org-a'],
      ['cyc-a', 'org-a.team-1'],
      ['right', null],
    ]

    async function seedAll(roleOrder: RoleSeed[], assignmentOrder: [string, string | null][]): Promise<void> {
      await pool.query('TRUNCATE iam_assignments, iam_roles CASCADE')
      for (const r of roleOrder) await seedRole(r)
      for (const [role, scope] of assignmentOrder) await seedAssignment('u1', role, scope)
    }

    /** Physical row order as Postgres hands it back with no ORDER BY. */
    async function physicalRoleOrder(): Promise<string[]> {
      const r = await pool.query('SELECT id FROM iam_roles')
      return r.rows.map((row) => (row as { id: string }).id)
    }

    it('the same catalog inserted in two different orders resolves identically', async () => {
      await seedAll(CATALOG, ASSIGNMENTS)
      const orderOne = await physicalRoleOrder()
      const first = await matrix(makeEngine({ scopeMode: 'hierarchical' }), 'u1')

      await seedAll([...CATALOG].reverse(), [...ASSIGNMENTS].reverse())
      const orderTwo = await physicalRoleOrder()
      const second = await matrix(makeEngine({ scopeMode: 'hierarchical' }), 'u1')

      // Prove the two runs really saw different orders, or this test asserts nothing.
      expect(orderTwo).not.toEqual(orderOne)
      expect([...orderTwo].sort()).toEqual([...orderOne].sort())
      expect(second).toEqual(first)
      expect(engineErrors).toEqual([])
    })

    it('rewriting rows in place, which moves them in the heap, changes no decision', async () => {
      await seedAll(CATALOG, ASSIGNMENTS)
      const before = await physicalRoleOrder()
      const baseline = await matrix(makeEngine({ scopeMode: 'hierarchical' }), 'u1')

      // An UPDATE writes a new tuple version, which Postgres appends - a
      // sequential scan then returns the touched rows last.
      for (const id of ['inner', 'left', 'top']) {
        await pool.query('UPDATE iam_roles SET updated_at = now() WHERE id = $1', [id])
      }
      const after = await physicalRoleOrder()
      expect(after).not.toEqual(before)
      expect(await matrix(makeEngine({ scopeMode: 'hierarchical' }), 'u1')).toEqual(baseline)
    })

    it('the order of a role\'s own "inherits" array changes no decision', async () => {
      await seedAll(CATALOG, ASSIGNMENTS)
      const baseline = await matrix(makeEngine({ scopeMode: 'hierarchical' }), 'u1')

      await pool.query(`UPDATE iam_roles SET inherits = $1::jsonb WHERE id = 'top'`, [
        JSON.stringify(['inner', 'right', 'mid']),
      ])
      await pool.query(`UPDATE iam_roles SET inherits = $1::jsonb WHERE id = 'cyc-b'`, [
        JSON.stringify(['top', 'cyc-a']),
      ])
      expect(await matrix(makeEngine({ scopeMode: 'hierarchical' }), 'u1')).toEqual(baseline)
      expect(engineErrors).toEqual([])
    })

    it('the same holds under flat mode and under override', async () => {
      for (const opts of [
        { scopeCombine: 'union' as const, scopeMode: 'flat' as const },
        { scopeCombine: 'override' as const, scopeMode: 'hierarchical' as const },
      ]) {
        await seedAll(CATALOG, ASSIGNMENTS)
        const first = await matrix(makeEngine(opts), 'u1')
        await seedAll([...CATALOG].reverse(), [...ASSIGNMENTS].reverse())
        const second = await matrix(makeEngine(opts), 'u1')
        expect({ opts, second }).toEqual({ opts, second: first })
      }
    })

    it('duplicate scoped assignments of the same role at different scopes stay independent', async () => {
      await seedRole({ id: 'admin', permissions: [{ action: 'write', resource: 'doc' }] })
      await seedAssignment('u2', 'admin', 'org-a')
      await seedAssignment('u2', 'admin', 'org-b')
      const engine = makeEngine()
      expect(await engine.can('u2', 'write', DOC, undefined, 'org-a')).toBe(true)
      expect(await engine.can('u2', 'write', DOC, undefined, 'org-b')).toBe(true)
      expect(await engine.can('u2', 'write', DOC, undefined, 'org-c')).toBe(false)
      await engine.admin.revokeRole('u2', 'admin', 'org-a')
      expect(await engine.can('u2', 'write', DOC, undefined, 'org-a')).toBe(false)
      expect(await engine.can('u2', 'write', DOC, undefined, 'org-b')).toBe(true)
    })
  })
})
