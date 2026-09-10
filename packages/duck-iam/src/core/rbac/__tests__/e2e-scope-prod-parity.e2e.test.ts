/**
 * E2E on real Postgres: production (compiled table alone) and development (table cross-checked against the
 * interpreter, fail-closed on a split) must agree on scope-heavy RBAC catalogs.
 */
import { and, eq, or } from 'drizzle-orm'
import { drizzle } from 'drizzle-orm/node-postgres'
import { Pool } from 'pg'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { IamDrizzleAdapter } from '../../../adapters/drizzle'
import { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from '../../../adapters/drizzle/pg'
import { applyPgSchema, assertE2eReachable, databaseUrl, isolatedDatabaseUrl } from '../../../test/e2e-env'
import { IamEngine } from '../../engine'

const BASE_URL = databaseUrl()
const URL = await isolatedDatabaseUrl('scope_prod_parity')
if (BASE_URL !== undefined && URL === undefined) {
  throw new Error(
    '[e2e-scope] DUCKIAM_E2E_DATABASE_URL is set but an isolated database could not be created. ' +
      'Refusing to skip: a skipped suite is not a passing suite.',
  )
}
assertE2eReachable('scope-prod-parity', URL)
const suite = URL ? describe : describe.skip

type Action = 'read' | 'write' | 'admin'
type Resource = 'doc'

const TABLES = { assignments: iamAssignments, attrs: iamSubjectAttrs, policies: iamPolicies, roles: iamRoles }
const OPS = { and, eq, or }
const DOC = { attributes: {}, type: 'doc' as const }

const ACTIONS: Action[] = ['read', 'write', 'admin']
const SCOPES: (string | undefined)[] = [
  undefined,
  '',
  '*',
  'org-a',
  'org-b',
  'org-ab',
  'org',
  'org-a.team-1',
  'org-a.team-1.repo-9',
  'org-a.',
  '.org-a',
  'org-a..team-1',
  'ORG-A',
]

interface RoleSeed {
  id: string
  inherits?: string[]
  permissions?: unknown[]
  scope?: string | null
}

suite('E2E scope: production vs development parity on real Postgres', () => {
  let pool: Pool
  let db: ReturnType<typeof drizzle>
  let devErrors: string[]

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
    devErrors = []
  })

  function adapter() {
    return new IamDrizzleAdapter<Action, Resource, string, string>({ db, ops: OPS, tables: TABLES })
  }

  function devEngine(scopeMode: 'flat' | 'hierarchical', scopeCombine: 'union' | 'override') {
    return new IamEngine<Action, Resource, string, string, 'development'>({
      adapter: adapter(),
      hooks: {
        onError: (err) => {
          devErrors.push(err.message)
        },
      },
      mode: 'development',
      scopeCombine,
      scopeMode,
    })
  }

  function prodEngine(scopeMode: 'flat' | 'hierarchical', scopeCombine: 'union' | 'override') {
    return new IamEngine<Action, Resource, string, string, 'production'>({
      adapter: adapter(),
      mode: 'production',
      scopeCombine,
      scopeMode,
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

  async function verdicts(
    engine: IamEngine<Action, Resource, string, string, 'development' | 'production'>,
    subjectId: string,
  ): Promise<Record<string, boolean>> {
    const out: Record<string, boolean> = {}
    for (const scope of SCOPES) {
      for (const action of ACTIONS) {
        out[`${action}@${scope ?? '<none>'}`] = await engine.can(subjectId, action, DOC, undefined, scope)
      }
    }
    return out
  }

  /** Runs the action x scope grid through both modes and scope modes; any dev `onError` is an engine disagreement. */
  async function assertParity(subjectId: string): Promise<Record<string, boolean>> {
    let devAll: Record<string, boolean> = {}
    for (const scopeMode of ['flat', 'hierarchical'] as const) {
      for (const scopeCombine of ['union', 'override'] as const) {
        const dev = await verdicts(devEngine(scopeMode, scopeCombine), subjectId)
        const prod = await verdicts(prodEngine(scopeMode, scopeCombine), subjectId)
        expect({ prod, scopeCombine, scopeMode }).toEqual({ prod: dev, scopeCombine, scopeMode })
        if (scopeMode === 'flat' && scopeCombine === 'union') devAll = dev
      }
    }
    // A table/interpreter split reaches `onError` as an evaluation error.
    expect(devErrors.filter((m) => m.includes('disagree'))).toEqual([])
    expect(devErrors).toEqual([])
    return devAll
  }

  it('agrees on a plain scoped assignment', async () => {
    await seedRole({ id: 'admin', permissions: [{ action: 'write', resource: 'doc' }] })
    await seedAssignment('u1', 'admin', 'org-a')
    const dev = await assertParity('u1')
    expect(dev['write@org-a']).toBe(true)
    expect(dev['write@org-b']).toBe(false)
  })

  it('agrees when the role declares a scope and the assignment is global', async () => {
    await seedRole({ id: 'admin', permissions: [{ action: 'write', resource: 'doc' }], scope: 'org-a' })
    await seedAssignment('u1', 'admin', null)
    const dev = await assertParity('u1')
    expect(dev['write@org-a']).toBe(true)
    expect(dev['write@<none>']).toBe(false)
  })

  it('agrees when the permission declares its own scope, overriding the role scope', async () => {
    await seedRole({
      id: 'admin',
      permissions: [
        { action: 'write', resource: 'doc', scope: 'org-b' },
        { action: 'read', resource: 'doc' },
      ],
      scope: 'org-a',
    })
    await seedAssignment('u1', 'admin', null)
    const dev = await assertParity('u1')
    // permission scope wins over role scope
    expect(dev['write@org-b']).toBe(true)
    expect(dev['write@org-a']).toBe(false)
    // and the role scope still applies to the permission that declares none
    expect(dev['read@org-a']).toBe(true)
    expect(dev['read@org-b']).toBe(false)
  })

  it("agrees when a permission declares scope '*' inside a scoped role", async () => {
    await seedRole({
      id: 'admin',
      permissions: [{ action: 'write', resource: 'doc', scope: '*' }],
      scope: 'org-a',
    })
    await seedAssignment('u1', 'admin', null)
    const dev = await assertParity('u1')
    for (const scope of SCOPES) expect({ scope, v: dev[`write@${scope ?? '<none>'}`] }).toEqual({ scope, v: true })
  })

  it('agrees on cross-scope inheritance (org-a assignment, org-b declared parent)', async () => {
    await seedRole({ id: 'b-admin', permissions: [{ action: 'read', resource: 'doc' }], scope: 'org-b' })
    await seedRole({ id: 'lead', inherits: ['b-admin'], permissions: [{ action: 'write', resource: 'doc' }] })
    await seedAssignment('u1', 'lead', 'org-a')
    const dev = await assertParity('u1')
    expect(dev['read@org-b']).toBe(true)
    expect(dev['write@org-b']).toBe(false)
    expect(dev['write@org-a']).toBe(true)
  })

  it('agrees on a wildcard permission inside a scoped role (the residual RBAC path)', async () => {
    // A wildcarded action keeps the role in `rbacResidual` rather than a cell,
    // which is a different code path in the compiled table.
    await seedRole({ id: 'admin', permissions: [{ action: '*', resource: 'doc' }], scope: 'org-a' })
    await seedAssignment('u1', 'admin', 'org-a')
    const dev = await assertParity('u1')
    expect(dev['read@org-a']).toBe(true)
    expect(dev['admin@org-a']).toBe(true)
    expect(dev['read@org-b']).toBe(false)
  })

  it('agrees on a wildcard resource with a scoped assignment', async () => {
    await seedRole({ id: 'admin', permissions: [{ action: 'read', resource: '*' }] })
    await seedAssignment('u1', 'admin', 'org-a')
    const dev = await assertParity('u1')
    expect(dev['read@org-a']).toBe(true)
    expect(dev['read@org-b']).toBe(false)
  })

  it('agrees on a conditioned scoped permission', async () => {
    await seedRole({
      id: 'admin',
      permissions: [
        {
          action: 'write',
          conditions: { all: [{ field: 'subject.id', operator: 'eq', value: 'u1' }] },
          resource: 'doc',
          scope: 'org-a',
        },
      ],
    })
    await seedAssignment('u1', 'admin', 'org-a')
    await seedAssignment('u2', 'admin', 'org-a')
    const dev = await assertParity('u1')
    expect(dev['write@org-a']).toBe(true)
    devErrors = []
    const other = await assertParity('u2')
    expect(other['write@org-a']).toBe(false)
  })

  it('agrees on a deep scoped hierarchy with several assignments', async () => {
    await seedRole({ id: 'root', permissions: [{ action: 'read', resource: 'doc' }], scope: 'org' })
    await seedRole({ id: 'a', inherits: ['root'], permissions: [{ action: 'write', resource: 'doc' }] })
    await seedRole({ id: 'b', inherits: ['a'], permissions: [{ action: 'admin', resource: 'doc' }], scope: 'org-b' })
    await seedAssignment('u1', 'b', 'org-a')
    await seedAssignment('u1', 'a', 'org-a.team-1')
    await assertParity('u1')
  })

  // Past `IAM_MAX_COMPILED_ROLES` both modes drop to the interpreter, a second code path entered just by adding roles.
  it('agrees, and answers the same scoped questions, on either side of the 32-role compiled-table limit', async () => {
    const small: RoleSeed[] = [
      { id: 'b-admin', permissions: [{ action: 'read', resource: 'doc' }], scope: 'org-b' },
      { id: 'lead', inherits: ['b-admin'], permissions: [{ action: 'write', resource: 'doc' }], scope: 'org-a' },
    ]
    for (const r of small) await seedRole(r)
    await seedAssignment('u1', 'lead', 'org-a')
    const withTable = await assertParity('u1')

    // Pad the catalog past the limit without changing what `u1` holds.
    for (let i = 0; i < 40; i++) {
      await seedRole({ id: `filler-${i}`, permissions: [{ action: 'admin', resource: 'doc' }], scope: `org-f${i}` })
    }
    // Guard: prove the catalog crossed the limit, or both runs take the same code path.
    const n = await pool.query('SELECT count(*)::int AS n FROM iam_roles')
    expect((n.rows[0] as { n: number }).n).toBeGreaterThan(32)
    devErrors = []
    const withoutTable = await assertParity('u1')
    expect(withoutTable).toEqual(withTable)
    expect(withTable['write@org-a']).toBe(true)
    expect(withTable['read@org-b']).toBe(true)
    expect(withTable['admin@org-a']).toBe(false)
  })

  it('agrees when the catalog mixes an ABAC policy with scoped roles', async () => {
    await seedRole({ id: 'admin', permissions: [{ action: 'write', resource: 'doc' }], scope: 'org-a' })
    await seedAssignment('u1', 'admin', 'org-a')
    await pool.query(
      `INSERT INTO iam_policies (id, name, algorithm, rules) VALUES ('p1', 'p1', 'allow-overrides', $1::jsonb)`,
      [
        JSON.stringify([
          {
            actions: ['read'],
            conditions: { all: [{ field: 'scope', operator: 'eq', value: 'org-a' }] },
            effect: 'allow',
            id: 'r1',
            priority: 10,
            resources: ['doc'],
          },
        ]),
      ],
    )
    const dev = await assertParity('u1')
    expect(dev['read@org-a']).toBe(true)
    expect(dev['read@org-b']).toBe(false)
  })
})
