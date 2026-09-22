/**
 * E2E on real Postgres: an inherited role carries its own declared scope, else the assignment row's scope.
 * Both evaluators run in development; a disagreement routed to `onError` is asserted absent.
 */
import { and, eq, or } from 'drizzle-orm'
import { drizzle } from 'drizzle-orm/node-postgres'
import { Pool } from 'pg'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { IamDrizzleAdapter } from '../../../adapters/drizzle'
import { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from '../../../adapters/drizzle/pg'
import { applyPgSchema, assertE2eReachable, databaseUrl, isolatedDatabaseUrl } from '../../../test/e2e-env'
import { IamEngine } from '../../engine'
import { MAX_INHERITANCE_DEPTH } from '../rbac'

const BASE_URL = databaseUrl()
const URL = await isolatedDatabaseUrl('scope_inheritance')
if (BASE_URL !== undefined && URL === undefined) {
  throw new Error(
    '[e2e-scope] DUCKIAM_E2E_DATABASE_URL is set but an isolated database could not be created. ' +
      'Refusing to skip: a skipped suite is not a passing suite.',
  )
}
assertE2eReachable('scope-inheritance', URL)
const suite = URL ? describe : describe.skip

type Action = 'read' | 'write' | 'admin'
type Resource = 'doc'

const TABLES = { assignments: iamAssignments, attrs: iamSubjectAttrs, policies: iamPolicies, roles: iamRoles }
const OPS = { and, eq, or }
const DOC = { attributes: {}, type: 'doc' as const }

/**
 * Reads one verdict from a `permissions()` map, whose template-literal key type a plain string can't index.
 * A missing or non-boolean entry returns `undefined` and fails the comparison.
 */
function verdictFor(map: object, key: string): boolean | undefined {
  const value = Object.hasOwn(map, key) ? Reflect.get(map, key) : undefined
  return typeof value === 'boolean' ? value : undefined
}

suite('E2E scope: cross-scope inheritance on real Postgres', () => {
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

  function makeEngine(opts: { scopeMode?: 'flat' | 'hierarchical' } = {}) {
    return new IamEngine<Action, Resource, string, string, 'development'>({
      adapter: new IamDrizzleAdapter<Action, Resource, string, string>({ db, ops: OPS, tables: TABLES }),
      hooks: {
        onError: (err) => {
          engineErrors.push(err.message)
        },
      },
      mode: 'development',
      scopeMode: opts.scopeMode ?? 'flat',
    })
  }

  async function seedRole(role: {
    id: string
    inherits?: string[]
    permissions?: unknown[]
    scope?: string | null
  }): Promise<void> {
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

  /** Insert a hand-written ABAC policy row (the shape an operator would author). */
  async function seedPolicy(id: string, rules: unknown[]): Promise<void> {
    await pool.query(
      `INSERT INTO iam_policies (id, name, algorithm, rules) VALUES ($1, $2, 'allow-overrides', $3::jsonb)`,
      [id, id, JSON.stringify(rules)],
    )
  }

  describe('a role assigned at org-a that inherits a role declared at org-b', () => {
    beforeEach(async () => {
      // `lead` declares no scope of its own; `b-admin` declares org-b.
      await seedRole({ id: 'b-admin', permissions: [{ action: 'read', resource: 'doc' }], scope: 'org-b' })
      await seedRole({ id: 'lead', inherits: ['b-admin'], permissions: [{ action: 'write', resource: 'doc' }] })
      await seedAssignment('u1', 'lead', 'org-a')
    })

    it('the inherited role is tagged with its OWN declared scope, not the assignment row scope', async () => {
      const engine = makeEngine()
      expect(await engine.getEffectiveRoles('u1', 'org-a')).toEqual(['lead'])
      expect(await engine.getEffectiveRoles('u1', 'org-b')).toEqual(['b-admin'])
      expect(await engine.getEffectiveRoles('u1', undefined)).toEqual([])
    })

    it("the assigned role's own permissions do NOT follow it to org-b (commit 282d6f67)", async () => {
      const engine = makeEngine()
      expect(await engine.can('u1', 'write', DOC, undefined, 'org-a')).toBe(true)
      expect(await engine.can('u1', 'write', DOC, undefined, 'org-b')).toBe(false)
      expect(engineErrors).toEqual([])
    })

    it("the inherited role's permission is NOT visible at the assignment scope", async () => {
      const engine = makeEngine()
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-a')).toBe(false)
    })

    // NOTE: consistent with the catalog, but the shape an operator most likely gets wrong, so it is pinned.
    it('the inherited role IS visible in org-b, from a grant only ever made in org-a', async () => {
      const engine = makeEngine()
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-b')).toBe(true)
      expect(engineErrors).toEqual([])
    })

    it('answers the same for an unscoped assignment of the same role', async () => {
      await seedAssignment('u2', 'lead', null)
      const engine = makeEngine()
      // Scoped and unscoped assignment must agree about the INHERITED role's reach.
      expect(await engine.can('u2', 'read', DOC, undefined, 'org-b')).toBe(true)
      expect(await engine.can('u2', 'read', DOC, undefined, 'org-a')).toBe(false)
      // They differ, correctly, about the assigned role's own global permission.
      expect(await engine.can('u2', 'write', DOC, undefined, 'org-b')).toBe(true)
      expect(await engine.can('u1', 'write', DOC, undefined, 'org-b')).toBe(false)
    })

    it('permissions() batch matches can() for every scope in this catalog', async () => {
      const engine = makeEngine()
      const scopes = ['org-a', 'org-b', 'org-c']
      const checks = scopes.flatMap((scope) => [
        { action: 'read' as const, resource: 'doc' as const, scope },
        { action: 'write' as const, resource: 'doc' as const, scope },
      ])
      const batch = await engine.permissions('u1', checks)
      for (const c of checks) {
        const key = `@${c.scope}:${c.action}:${c.resource}`
        const single = await engine.can('u1', c.action, DOC, undefined, c.scope)
        expect({ key, value: verdictFor(batch, key) }).toEqual({ key, value: single })
      }
      expect(engineErrors).toEqual([])
    })
  })

  describe('a role DECLARING org-a that inherits an unscoped role', () => {
    beforeEach(async () => {
      await seedRole({ id: 'base', permissions: [{ action: 'read', resource: 'doc' }] })
      await seedRole({
        id: 'a-lead',
        inherits: ['base'],
        permissions: [{ action: 'write', resource: 'doc' }],
        scope: 'org-a',
      })
    })

    it('a scoped assignment confines the inherited unscoped permission to the assignment scope', async () => {
      await seedAssignment('u1', 'a-lead', 'org-a')
      const engine = makeEngine()
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-a')).toBe(true)
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-b')).toBe(false)
      expect(await engine.getEffectiveRoles('u1', 'org-a')).toEqual(['a-lead', 'base'])
      expect(await engine.getEffectiveRoles('u1', 'org-b')).toEqual([])
    })

    // The inherited permission uses `base`'s absent scope, so it grants everywhere while `a-lead`'s own `write` stays
    // in org-a. Whether that asymmetry is intended is a product question.
    it('an unscoped assignment lets the inherited permission escape the declared scope', async () => {
      await seedAssignment('u2', 'a-lead', null)
      const engine = makeEngine()
      expect(await engine.can('u2', 'write', DOC, undefined, 'org-a')).toBe(true)
      expect(await engine.can('u2', 'write', DOC, undefined, 'org-b')).toBe(false)
      // The inherited permission is NOT confined by `a-lead.scope`.
      expect(await engine.can('u2', 'read', DOC, undefined, 'org-a')).toBe(true)
      expect(await engine.can('u2', 'read', DOC, undefined, 'org-b')).toBe(true)
      expect(await engine.can('u2', 'read', DOC, undefined, undefined)).toBe(true)
      expect(engineErrors).toEqual([])
    })
  })

  describe('which way inheritance moves a grant through the scope tree', () => {
    // `resolveSubject` retags inherited `org-lead` with its declared parent scope; not a hierarchy walk, so flat too.
    it('a grant made only at org-a.team-1 answers at org-a when the inherited role declares org-a', async () => {
      await seedRole({ id: 'org-lead', permissions: [{ action: 'admin', resource: 'doc' }], scope: 'org-a' })
      await seedRole({ id: 'team-lead', inherits: ['org-lead'], permissions: [{ action: 'write', resource: 'doc' }] })
      await seedAssignment('u1', 'team-lead', 'org-a.team-1')

      for (const scopeMode of ['flat', 'hierarchical'] as const) {
        const engine = makeEngine({ scopeMode })
        expect({ mode: scopeMode, roles: await engine.getEffectiveRoles('u1', 'org-a') }).toEqual({
          mode: scopeMode,
          roles: ['org-lead'],
        })
        expect({ mode: scopeMode, v: await engine.can('u1', 'admin', DOC, undefined, 'org-a') }).toEqual({
          mode: scopeMode,
          v: true,
        })
        // The assigned role's own permission correctly does NOT move up.
        expect({ mode: scopeMode, v: await engine.can('u1', 'write', DOC, undefined, 'org-a') }).toEqual({
          mode: scopeMode,
          v: false,
        })
      }
      expect(engineErrors).toEqual([])
    })

    // The same retag widens one `org-a` grant to all of `org.*` when the inherited role declares `org`.
    it('an inherited role declared at a root scope widens the grant to that whole subtree', async () => {
      await seedRole({ id: 'platform', permissions: [{ action: 'read', resource: 'doc' }], scope: 'org' })
      await seedRole({ id: 'a-lead', inherits: ['platform'] })
      await seedAssignment('u1', 'a-lead', 'org-a')
      const engine = makeEngine({ scopeMode: 'hierarchical' })
      expect(await engine.can('u1', 'read', DOC, undefined, 'org')).toBe(true)
      expect(await engine.can('u1', 'read', DOC, undefined, 'org.anything')).toBe(true)
      expect(await engine.can('u1', 'read', DOC, undefined, 'org.someone-elses-tenant.deep')).toBe(true)
      // Not a prefix match: 'org-a' is not under 'org'.
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-a')).toBe(false)
      expect(engineErrors).toEqual([])
    })

    it("an inherited role declaring scope '*' grants at the assignment scope, and is separately held at the literal '*'", async () => {
      await seedRole({ id: 'global', permissions: [{ action: 'read', resource: 'doc' }], scope: '*' })
      await seedRole({ id: 'a-lead', inherits: ['global'] })
      await seedAssignment('u1', 'a-lead', 'org-a')
      const engine = makeEngine()
      // `'*'` on the ROLE axis means global, so the inherited permission carries
      // no scope condition and answers wherever `a-lead` is held.
      expect(await engine.getEffectiveRoles('u1', 'org-a')).toEqual(['a-lead'])
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-a')).toBe(true)
      // The retag also files it under the literal `'*'`, and `enrichSubjectWithScopedRoles` compares plain strings,
      // so a request scope of `'*'` is handed a role held at no real scope.
      expect(await engine.getEffectiveRoles('u1', '*')).toEqual(['global'])
      expect(await engine.can('u1', 'read', DOC, undefined, '*')).toBe(true)
      // No other tenant, and no unscoped request, sees any of it.
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-b')).toBe(false)
      expect(await engine.can('u1', 'read', DOC, undefined, undefined)).toBe(false)
      expect(engineErrors).toEqual([])
    })

    // `iamAssertAssignableScope` refuses a `'*'` assignment on write. An existing row is a literal scope, not global,
    // and must stay revocable, which is why `'*'` stays legal on a `'lookup'`.
    it("an ASSIGNMENT at scope '*' is refused on the write path, and an existing row stays literal", async () => {
      await seedRole({ id: 'admin', permissions: [{ action: 'read', resource: 'doc' }] })
      const engine = makeEngine()

      await expect(engine.admin.assignRole('u1', 'admin', '*')).rejects.toThrow(/must not be "\*"/)
      // Refused, not half-written: nothing landed for u1.
      expect(await engine.getEffectiveRoles('u1', '*')).toEqual([])

      // A pre-existing or directly written row is matched as the literal tenant `*`.
      await seedAssignment('u2', 'admin', '*')
      expect(await engine.can('u2', 'read', DOC, undefined, '*')).toBe(true)
      expect(await engine.can('u2', 'read', DOC, undefined, 'org-a')).toBe(false)
      expect(await engine.can('u2', 'read', DOC, undefined, undefined)).toBe(false)
      expect(await makeEngine({ scopeMode: 'hierarchical' }).can('u2', 'read', DOC, undefined, 'org-a')).toBe(false)

      // ...and it can still be deleted, which is why the guard exempts a lookup.
      await engine.admin.revokeRole('u2', 'admin', '*')
      expect(await engine.can('u2', 'read', DOC, undefined, '*')).toBe(false)
    })
  })

  describe('inheritance shape', () => {
    it('a diamond whose inner role declares its own scope resolves to that scope from every path', async () => {
      await seedRole({ id: 'inner', permissions: [{ action: 'read', resource: 'doc' }], scope: 'org-z' })
      await seedRole({ id: 'left', inherits: ['inner'], scope: 'org-a' })
      await seedRole({ id: 'right', inherits: ['inner'], scope: 'org-b' })
      await seedRole({ id: 'top', inherits: ['left', 'right'] })
      await seedAssignment('u1', 'top', 'org-x')
      const engine = makeEngine()
      expect([...(await engine.getEffectiveRoles('u1', 'org-z'))].sort()).toEqual(['inner'])
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-z')).toBe(true)
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-x')).toBe(false)
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-a')).toBe(false)
      expect(engineErrors).toEqual([])
    })

    // Unscoped `inner` falls back to the row's org-x, but each scoped parent holds its permission in its own scope.
    it('an unscoped inner role reached through two differently-scoped parents grants in all three', async () => {
      await seedRole({ id: 'inner', permissions: [{ action: 'read', resource: 'doc' }] })
      await seedRole({ id: 'left', inherits: ['inner'], scope: 'org-a' })
      await seedRole({ id: 'right', inherits: ['inner'], scope: 'org-b' })
      await seedRole({ id: 'top', inherits: ['left', 'right'] })
      await seedAssignment('u1', 'top', 'org-x')
      const engine = makeEngine()
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-x')).toBe(true)
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-a')).toBe(true)
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-b')).toBe(true)
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-q')).toBe(false)
      expect(engineErrors).toEqual([])
    })

    it('a two-role cycle terminates and both roles resolve at the assignment scope', async () => {
      await seedRole({ id: 'a', inherits: ['b'], permissions: [{ action: 'read', resource: 'doc' }] })
      await seedRole({ id: 'b', inherits: ['a'], permissions: [{ action: 'write', resource: 'doc' }] })
      await seedAssignment('u1', 'a', 'org-a')
      const engine = makeEngine()
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-a')).toBe(true)
      expect(await engine.can('u1', 'write', DOC, undefined, 'org-a')).toBe(true)
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-b')).toBe(false)
      expect(engineErrors).toEqual([])
    })

    it('a cycle across two scopes does not merge the two scopes', async () => {
      await seedRole({ id: 'a', inherits: ['b'], permissions: [{ action: 'read', resource: 'doc' }], scope: 'org-a' })
      await seedRole({ id: 'b', inherits: ['a'], permissions: [{ action: 'write', resource: 'doc' }], scope: 'org-b' })
      await seedAssignment('u1', 'a', 'org-a')
      const engine = makeEngine()
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-a')).toBe(true)
      expect(await engine.can('u1', 'write', DOC, undefined, 'org-a')).toBe(false)
      expect(await engine.can('u1', 'write', DOC, undefined, 'org-b')).toBe(true)
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-b')).toBe(false)
      expect(engineErrors).toEqual([])
    })

    it('self-inheritance terminates and changes nothing', async () => {
      await seedRole({ id: 'a', inherits: ['a'], permissions: [{ action: 'read', resource: 'doc' }] })
      await seedAssignment('u1', 'a', 'org-a')
      const engine = makeEngine()
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-a')).toBe(true)
      expect(await engine.getEffectiveRoles('u1', 'org-a')).toEqual(['a'])
    })

    it('inheriting a role that does not exist grants nothing on its own', async () => {
      await seedRole({ id: 'r', inherits: ['ghost'], permissions: [{ action: 'read', resource: 'doc' }] })
      await seedAssignment('u1', 'r', 'org-a')
      const engine = makeEngine()
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-a')).toBe(true)
      expect(await engine.can('u1', 'write', DOC, undefined, 'org-a')).toBe(false)
    })

    // SECURITY: a dangling inherited id (`DANGLING_INHERIT`) must not reach `subject.roles`.
    it('a nonexistent inherited role id does not appear in subject.roles and cannot satisfy an ABAC policy', async () => {
      await seedRole({ id: 'r', inherits: ['ghost'] })
      await seedAssignment('u1', 'r', null)
      await seedPolicy('p-ghost', [
        {
          actions: ['admin'],
          conditions: { all: [{ field: 'subject.roles', operator: 'contains', value: 'ghost' }] },
          effect: 'allow',
          id: 'ghost-rule',
          priority: 10,
          resources: ['doc'],
        },
      ])
      const engine = makeEngine()
      expect([...(await engine.getEffectiveRoles('u1'))].sort()).toEqual(['r'])
      expect(await engine.can('u1', 'admin', DOC)).toBe(false)
      expect(engineErrors).toEqual([])
    })

    it('deleting a role removes its id from subject.roles even while another role inherits it', async () => {
      await seedRole({ id: 'ghost', permissions: [{ action: 'read', resource: 'doc' }] })
      await seedRole({ id: 'r', inherits: ['ghost'] })
      await seedAssignment('u1', 'r', null)
      await seedPolicy('p-ghost', [
        {
          actions: ['admin'],
          conditions: { all: [{ field: 'subject.roles', operator: 'contains', value: 'ghost' }] },
          effect: 'allow',
          id: 'ghost-rule',
          priority: 10,
          resources: ['doc'],
        },
      ])
      const engine = makeEngine()
      expect(await engine.can('u1', 'read', DOC)).toBe(true)
      expect(await engine.can('u1', 'admin', DOC)).toBe(true)

      await engine.admin.deleteRole('ghost')

      // The permissions the deleted role carried are gone, as they must be.
      expect(await engine.can('u1', 'read', DOC)).toBe(false)
      // ...and so is the role ID, so a policy keyed on it stops matching too.
      expect([...(await engine.getEffectiveRoles('u1'))].sort()).toEqual(['r'])
      expect(await engine.can('u1', 'admin', DOC)).toBe(false)
      expect(engineErrors).toEqual([])
    })
  })

  describe('inheritance depth', () => {
    /** Build `count` roles r0 -> r1 -> ... each inheriting the next. */
    async function seedChain(count: number, perms: Record<number, unknown[]>): Promise<void> {
      for (let i = 0; i < count; i++) {
        await seedRole({
          id: `r${i}`,
          inherits: i + 1 < count ? [`r${i + 1}`] : [],
          permissions: perms[i] ?? [],
        })
      }
    }

    it('a permission at depth 31 (inside the cap, compiled table still active) is granted', async () => {
      // 32 roles keeps the catalog inside IAM_MAX_COMPILED_ROLES, so both the
      // compiled table and the interpreter answer this one.
      await seedChain(32, { 31: [{ action: 'read', resource: 'doc' }] })
      await seedAssignment('u1', 'r0', 'org-a')
      const engine = makeEngine()
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-a')).toBe(true)
      expect(engineErrors).toEqual([])
    })

    // NOTE: observed, not desired. `rolesToPolicy` walks from every role, and r33 is 32 deep from the held r1. Emitting
    // only own permissions would lose per-path scope (two scoped tests above), so every fix is breaking.
    it(`a permission past MAX_INHERITANCE_DEPTH (${MAX_INHERITANCE_DEPTH}) is still granted although the role is not held`, async () => {
      await seedChain(34, {
        32: [{ action: 'read', resource: 'doc' }],
        33: [{ action: 'write', resource: 'doc' }],
      })
      await seedAssignment('u1', 'r0', 'org-a')
      const engine = makeEngine()
      const roles = await engine.getEffectiveRoles('u1', 'org-a')
      expect(roles).toContain('r32')
      // Dropped from the resolved set, exactly as documented...
      expect(roles).not.toContain('r33')
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-a')).toBe(true)
      // ...and its permission is granted anyway, via the depth-32 path from r1.
      expect(await engine.can('u1', 'write', DOC, undefined, 'org-a')).toBe(true)
    })

    it('the depth cap does not let a past-cap role escape its declared scope', async () => {
      await seedChain(34, { 33: [{ action: 'write', resource: 'doc' }] })
      await pool.query(`UPDATE iam_roles SET scope = 'org-b' WHERE id = 'r33'`)
      await seedAssignment('u1', 'r0', 'org-a')
      const engine = makeEngine()
      expect(await engine.can('u1', 'write', DOC, undefined, 'org-a')).toBe(false)
      // r33 never enters the resolved set, so nothing is held at org-b either.
      expect(await engine.getEffectiveRoles('u1', 'org-b')).toEqual([])
      expect(await engine.can('u1', 'write', DOC, undefined, 'org-b')).toBe(false)
    })

    it('a deep chain whose tail declares another tenant does not leak into that tenant early', async () => {
      await seedChain(10, {})
      await pool.query(`UPDATE iam_roles SET scope = 'org-b', permissions = $1::jsonb WHERE id = 'r9'`, [
        JSON.stringify([{ action: 'read', resource: 'doc' }]),
      ])
      await seedAssignment('u1', 'r0', 'org-a')
      const engine = makeEngine()
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-a')).toBe(false)
      expect(await engine.can('u1', 'read', DOC, undefined, 'org-b')).toBe(true)
      expect(await engine.getEffectiveRoles('u1', 'org-b')).toEqual(['r9'])
    })
  })
})
