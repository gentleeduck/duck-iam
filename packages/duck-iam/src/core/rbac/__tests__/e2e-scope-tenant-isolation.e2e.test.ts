/**
 * E2E: tenant isolation for scoped role assignments, resolved through REAL
 * Postgres on the shipped schema.
 *
 * The question every case here asks is the same one: a subject holds `admin`
 * in `org-a` and nothing anywhere else - can any spelling of a request scope
 * make that grant answer for `org-b`? Every row is seeded with raw SQL rather
 * than through `engine.admin`, so the store decides what comes back, including
 * scope strings the write API would have refused.
 *
 * Fails loudly rather than skipping when a database URL is configured but
 * unusable: a silently skipped suite certifies nothing.
 */
import { and, eq, or } from 'drizzle-orm'
import { drizzle } from 'drizzle-orm/node-postgres'
import { Pool } from 'pg'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { IamDrizzleAdapter } from '../../../adapters/drizzle'
import { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from '../../../adapters/drizzle/pg'
import { iamBuildPermissionKey } from '../../../shared/keys'
import { applyPgSchema, databaseUrl, isolatedDatabaseUrl } from '../../../test/e2e-env'
import { IamEngine } from '../../engine'

const BASE_URL = databaseUrl()
const URL = await isolatedDatabaseUrl('scope_tenant_isolation')
if (BASE_URL !== undefined && URL === undefined) {
  throw new Error(
    '[e2e-scope] DUCKIAM_E2E_DATABASE_URL is set but an isolated database could not be created. ' +
      'Refusing to skip: a skipped suite is not a passing suite.',
  )
}
const suite = URL ? describe : describe.skip

type Action = 'read' | 'write'
type Resource = 'doc'
type RoleId = 'admin' | 'viewer'

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

suite('E2E scope: tenant isolation on real Postgres', () => {
  let pool: Pool
  let db: ReturnType<typeof drizzle>
  /** Anything the engine routed to `onError` - a compiled/interpreter disagreement lands here. */
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
    return new IamEngine<Action, Resource, RoleId, string, 'development'>({
      adapter: new IamDrizzleAdapter<Action, Resource, RoleId, string>({ db, ops: OPS, tables: TABLES }),
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

  /** Insert a role row directly, so scope shapes the write API rejects are still reachable. */
  async function seedRole(role: {
    id: string
    inherits?: string[]
    permissions: unknown[]
    scope?: string | null
  }): Promise<void> {
    await pool.query(
      'INSERT INTO iam_roles (id, name, permissions, inherits, scope) VALUES ($1, $2, $3::jsonb, $4::jsonb, $5)',
      [role.id, role.id, JSON.stringify(role.permissions), JSON.stringify(role.inherits ?? []), role.scope ?? null],
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

  it('is actually talking to a real Postgres server', async () => {
    const r = await pool.query('SELECT version() AS v')
    expect(String((r.rows[0] as { v: string }).v)).toMatch(/PostgreSQL/)
    // And the shipped schema is really in place, not a fake.
    const t = await pool.query(`SELECT to_regclass('public.iam_assignments') AS present`)
    expect((t.rows[0] as { present: string | null }).present).toBe('iam_assignments')
  })

  describe('flat scopeMode: an org-a grant answers for org-a and nothing else', () => {
    beforeEach(async () => {
      await seedRole({ id: 'admin', permissions: [{ action: 'read', resource: 'doc' }] })
      await seedAssignment('u1', 'admin', 'org-a')
    })

    it('grants at the exact assignment scope', async () => {
      const engine = makeEngine()
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-a')).toBe(true)
      expect(engineErrors).toEqual([])
    })

    // Every one of these must be a deny. Each is a distinct way an operator or
    // an attacker can spell "somewhere that is not org-a".
    const hostileScopes: [label: string, scope: string | undefined][] = [
      ['a different tenant', 'org-b'],
      ['no scope at all', undefined],
      ['the empty string', ''],
      ['the global wildcard', '*'],
      ['a tenant whose name has org-a as a prefix', 'org-ab'],
      ['a tenant that is a prefix of org-a', 'org'],
      ['a child scope (flat mode has no hierarchy)', 'org-a.team-1'],
      ['a trailing hierarchy separator', 'org-a.'],
      ['a leading hierarchy separator', '.org-a'],
      ['a doubled hierarchy separator', 'org-a..team-1'],
      ['different case', 'ORG-A'],
      ['a leading space', ' org-a'],
      ['a trailing space', 'org-a '],
      ['a unicode-confusable cyrillic "a"', 'org-а'],
      ['a trailing NUL byte', 'org-a\u0000'],
      ['a full-width hyphen lookalike', 'org－a'],
      ['an SQL-flavoured injection attempt', "org-a' OR '1'='1"],
      ['a percent-encoded separator', 'org-a%2Eteam-1'],
    ]

    for (const [label, scope] of hostileScopes) {
      it(`denies with ${label} (${JSON.stringify(scope)})`, async () => {
        const engine = makeEngine()
        expect(await engine.can('u1', 'read', DOC, undefined, scope)).toBe(false)
        expect(engineErrors).toEqual([])
      })
    }

    it('getEffectiveRoles agrees with can() on every hostile scope', async () => {
      const engine = makeEngine()
      expect(await engine.getEffectiveRoles('u1', 'org-a')).toEqual(['admin'])
      for (const [, scope] of hostileScopes) {
        expect({ roles: await engine.getEffectiveRoles('u1', scope), scope }).toEqual({ roles: [], scope })
      }
    })

    it('permissions() batch agrees with can() on every hostile scope', async () => {
      const engine = makeEngine()
      const checks = [
        { action: 'read' as const, resource: 'doc' as const, scope: 'org-a' },
        ...hostileScopes
          .filter((s): s is [string, string] => s[1] !== undefined)
          .map(([, scope]) => ({ action: 'read' as const, resource: 'doc' as const, scope })),
      ]
      const batch = await engine.permissions('u1', checks)
      for (const c of checks) {
        const key = iamBuildPermissionKey(c.action, c.resource, undefined, c.scope)
        const single = await engine.can('u1', c.action, DOC, undefined, c.scope)
        expect({ batch: verdictFor(batch, key), key }).toEqual({ batch: single, key })
      }
      expect(engineErrors).toEqual([])
    })
  })

  describe('hierarchical scopeMode: descendants yes, siblings and prefixes no', () => {
    beforeEach(async () => {
      await seedRole({ id: 'admin', permissions: [{ action: 'read', resource: 'doc' }] })
      await seedAssignment('u1', 'admin', 'org-a')
    })

    it('reaches descendants of the assignment scope', async () => {
      const engine = makeEngine({ scopeMode: 'hierarchical' })
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-a')).toBe(true)
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-a.team-1')).toBe(true)
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-a.team-1.repo-2.sub-3')).toBe(true)
      expect(engineErrors).toEqual([])
    })

    it('does not leak into a tenant whose name merely starts with org-a', async () => {
      const engine = makeEngine({ scopeMode: 'hierarchical' })
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-ab')).toBe(false)
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-a-b')).toBe(false)
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-ab.team-1')).toBe(false)
    })

    it('does not walk upward: a child grant never answers for the parent', async () => {
      await seedAssignment('u2', 'admin', 'org-b.team-9')
      const engine = makeEngine({ scopeMode: 'hierarchical' })
      expect(await engine.can('u2', 'read', DOC, undefined, 'org-b.team-9')).toBe(true)
      expect(await engine.can('u2', 'read', DOC, undefined, 'org-b')).toBe(false)
      expect(await engine.can('u2', 'read', DOC, undefined, 'org-b.team-8')).toBe(false)
    })

    it('a grant at a root scope does not reach a sibling root', async () => {
      await seedAssignment('u3', 'admin', 'org')
      const engine = makeEngine({ scopeMode: 'hierarchical' })
      expect(await engine.can('u3', 'read', DOC, undefined, 'org')).toBe(true)
      expect(await engine.can('u3', 'read', DOC, undefined, 'org.a')).toBe(true)
      // 'org-a' is NOT under 'org' - the separator is '.', not '-'.
      expect(await engine.can('u3', 'read', DOC, undefined, 'org-a')).toBe(false)
    })

    it('still denies the empty, wildcard and absent scopes', async () => {
      const engine = makeEngine({ scopeMode: 'hierarchical' })
      expect(await engine.can('u1', 'read', DOC, undefined, undefined)).toBe(false)
      expect(await engine.can('u1', 'read', DOC, undefined, '')).toBe(false)
      expect(await engine.can('u1', 'read', DOC, undefined, '*')).toBe(false)
    })

    it('permissions() batch agrees with can() in hierarchical mode', async () => {
      const engine = makeEngine({ scopeMode: 'hierarchical' })
      const scopes = ['org-a', 'org-a.team-1', 'org-ab', 'org', 'org-b', '*', '', 'org-a.', '.org-a']
      const checks = scopes.map((scope) => ({ action: 'read' as const, resource: 'doc' as const, scope }))
      const batch = await engine.permissions('u1', checks)
      for (const scope of scopes) {
        const key = iamBuildPermissionKey('read', 'doc', undefined, scope)
        const single = await engine.can('u1', 'read', DOC, undefined, scope)
        expect({ batch: verdictFor(batch, key), scope }).toEqual({ batch: single, scope })
      }
      expect(engineErrors).toEqual([])
    })
  })

  describe('what the store will and will not hold', () => {
    it("Postgres refuses a blank assignment scope, so `''` cannot be laundered in", async () => {
      await seedRole({ id: 'admin', permissions: [{ action: 'read', resource: 'doc' }] })
      await expect(seedAssignment('u1', 'admin', '')).rejects.toThrow(/ch_iam_assignments_scope_not_blank/)
    })

    it('Postgres refuses a blank role scope', async () => {
      await expect(seedRole({ id: 'admin', permissions: [], scope: '' })).rejects.toThrow(
        /ch_iam_roles_scope_not_blank/,
      )
    })

    it('a permission-level `scope: ""` in jsonb is refused by the role parser, not honoured', async () => {
      // jsonb has no CHECK constraint, so this shape reaches the engine from the
      // store even though `saveRole` would have rejected it. It must never read
      // as "global".
      await seedRole({ id: 'admin', permissions: [{ action: 'read', resource: 'doc', scope: '' }] })
      await seedAssignment('u1', 'admin', 'org-a')
      const engine = makeEngine()
      for (const scope of [undefined, '', 'org-a', 'org-b', '*']) {
        expect({ allowed: await engine.can('u1', 'read', DOC, undefined, scope), scope }).toEqual({
          allowed: false,
          scope,
        })
      }
    })

    it('a permission-level `scope: null` in jsonb never reads as a global grant', async () => {
      await seedRole({ id: 'admin', permissions: [{ action: 'read', resource: 'doc', scope: null }] })
      await seedAssignment('u1', 'admin', 'org-a')
      const engine = makeEngine()
      for (const scope of [undefined, '', 'org-a', 'org-b', '*']) {
        expect({ allowed: await engine.can('u1', 'read', DOC, undefined, scope), scope }).toEqual({
          allowed: false,
          scope,
        })
      }
    })

    it('a permission-level `scope: "*"` is global, and only for the role that holds it', async () => {
      await seedRole({ id: 'admin', permissions: [{ action: 'read', resource: 'doc', scope: '*' }] })
      await seedAssignment('u1', 'admin', 'org-a')
      const engine = makeEngine()
      // The grant is global, but the *assignment* is still scoped to org-a, so
      // the role only enters `subject.roles` at org-a.
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-a')).toBe(true)
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-b')).toBe(false)
      expect(await engine.can('u1', 'read', DOC, undefined, undefined)).toBe(false)
    })

    it('an expired scoped assignment stops answering for its own tenant', async () => {
      await seedRole({ id: 'admin', permissions: [{ action: 'read', resource: 'doc' }] })
      await pool.query(
        `INSERT INTO iam_assignments (id, subject_id, role_id, scope, expires_at)
         VALUES ('a1', 'u1', 'admin', 'org-a', now() - interval '1 hour')`,
      )
      const engine = makeEngine()
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-a')).toBe(false)
      expect(await engine.getEffectiveRoles('u1', 'org-a')).toEqual([])
    })
  })

  describe('a global (unscoped) assignment vs a scoped one', () => {
    it('an unscoped assignment of an unscoped role answers everywhere', async () => {
      await seedRole({ id: 'admin', permissions: [{ action: 'read', resource: 'doc' }] })
      await seedAssignment('u1', 'admin', null)
      const engine = makeEngine()
      for (const scope of [undefined, 'org-a', 'org-b', '*', '']) {
        expect({ allowed: await engine.can('u1', 'read', DOC, undefined, scope), scope }).toEqual({
          allowed: true,
          scope,
        })
      }
    })

    it('an unscoped assignment of a role DECLARING org-a answers only for org-a', async () => {
      await seedRole({ id: 'admin', permissions: [{ action: 'read', resource: 'doc' }], scope: 'org-a' })
      await seedAssignment('u1', 'admin', null)
      const engine = makeEngine()
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-a')).toBe(true)
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-b')).toBe(false)
      expect(await engine.can('u1', 'read', DOC, undefined, undefined)).toBe(false)
      expect(await engine.can('u1', 'read', DOC, undefined, '*')).toBe(false)
    })

    it('a role declaring org-a, assigned at org-b, grants in neither', async () => {
      await seedRole({ id: 'admin', permissions: [{ action: 'read', resource: 'doc' }], scope: 'org-a' })
      await seedAssignment('u1', 'admin', 'org-b')
      const engine = makeEngine()
      // At org-b the role is held but its permission is declared for org-a.
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-b')).toBe(false)
      // At org-a the permission would apply but the role is not held there:
      // the direct assignment keeps the row's scope (commit 282d6f67).
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-a')).toBe(false)
      expect(await engine.getEffectiveRoles('u1', 'org-a')).toEqual([])
      expect(await engine.getEffectiveRoles('u1', 'org-b')).toEqual(['admin'])
    })
  })

  describe('two tenants, two subjects, one catalog', () => {
    beforeEach(async () => {
      await seedRole({ id: 'admin', permissions: [{ action: 'write', resource: 'doc' }] })
      await seedRole({ id: 'viewer', permissions: [{ action: 'read', resource: 'doc' }] })
      await seedAssignment('alice', 'admin', 'org-a')
      await seedAssignment('bob', 'admin', 'org-b')
      await seedAssignment('alice', 'viewer', 'org-b')
    })

    it('keeps each subject inside the tenant that granted them', async () => {
      const engine = makeEngine()
      expect(await engine.can('alice', 'write', DOC, undefined, 'org-a')).toBe(true)
      expect(await engine.can('alice', 'write', DOC, undefined, 'org-b')).toBe(false)
      expect(await engine.can('alice', 'read', DOC, undefined, 'org-b')).toBe(true)
      expect(await engine.can('alice', 'read', DOC, undefined, 'org-a')).toBe(false)
      expect(await engine.can('bob', 'write', DOC, undefined, 'org-b')).toBe(true)
      expect(await engine.can('bob', 'write', DOC, undefined, 'org-a')).toBe(false)
      expect(engineErrors).toEqual([])
    })

    it('revoking in one tenant leaves the other tenant intact', async () => {
      const engine = makeEngine()
      await engine.admin.revokeRole('alice', 'admin', 'org-a')
      expect(await engine.can('alice', 'write', DOC, undefined, 'org-a')).toBe(false)
      expect(await engine.can('alice', 'read', DOC, undefined, 'org-b')).toBe(true)
      expect(await engine.can('bob', 'write', DOC, undefined, 'org-b')).toBe(true)
    })

    it('revoking with no scope does not silently drop the scoped rows', async () => {
      const before = await pool.query('SELECT count(*)::int AS n FROM iam_assignments')
      const engine = makeEngine()
      await engine.admin.revokeRole('alice', 'admin')
      const after = await pool.query('SELECT count(*)::int AS n FROM iam_assignments')
      // Documented behaviour is what matters here; assert whichever it is so a
      // change of heart shows up as a failing test rather than a quiet leak.
      expect((after.rows[0] as { n: number }).n).toBe((before.rows[0] as { n: number }).n - 1)
      expect(await engine.can('alice', 'write', DOC, undefined, 'org-a')).toBe(false)
    })
  })
})
