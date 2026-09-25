// E2E on real Postgres: the >32-role fallback, table TTL against another connection's write, and divergence replays.
// Catalogs go in via raw SQL; drizzle re-validates on read and drops rejects, so cases assert their roles loaded.
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { and, eq, or } from 'drizzle-orm'
import { drizzle } from 'drizzle-orm/node-postgres'
import { Pool } from 'pg'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { IamDrizzleAdapter } from '../../../adapters/drizzle'
import { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from '../../../adapters/drizzle/pg'
import { applyPgSchema, assertE2eReachable, isolatedDatabaseUrl } from '../../../test/e2e-env'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'

const exec = promisify(execFile)

async function dockerReachable(): Promise<boolean> {
  try {
    await exec('docker', ['info', '--format', '{{.ServerVersion}}'], { timeout: 5_000 })
    return true
  } catch {
    return false
  }
}

const URL = await isolatedDatabaseUrl('verdict-fallback')
if (URL === undefined && (await dockerReachable())) {
  // Docker is up, so `globalSetup` should have provisioned Postgres; a skip here would hide a broken harness.
  throw new Error(
    '[e2e-verdict] docker is reachable but DUCKIAM_E2E_DATABASE_URL is unset or the database is unusable. ' +
      'This suite must not skip under those conditions - fix the harness (src/test/e2e-containers.ts) instead.',
  )
}
assertE2eReachable('verdict-pg-fallback', URL)
const suite = URL ? describe : describe.skip

const TABLES = { assignments: iamAssignments, attrs: iamSubjectAttrs, policies: iamPolicies, roles: iamRoles }
const OPS = { and, eq, or }

const ROLE_LIMIT_WARNING = 'IAM_ROLE_LIMIT_EXCEEDED'
const DISAGREE_MARKER = 'compiled table and interpreter disagree'

suite('E2E compiled-table fallback and TTL on real Postgres', () => {
  let pool: Pool
  /** A genuinely separate connection pool, so a write here is another process as far as the engine is concerned. */
  let writer: Pool
  let db: ReturnType<typeof drizzle>

  beforeAll(async () => {
    pool = new Pool({ connectionString: URL })
    await applyPgSchema(pool)
    writer = new Pool({ connectionString: URL })
    db = drizzle(pool)
  })

  afterAll(async () => {
    await pool.end()
    await writer.end()
  })

  beforeEach(async () => {
    await pool.query('TRUNCATE iam_assignments, iam_subject_attrs, iam_roles, iam_policies CASCADE')
  })

  function adapter(): IamDrizzleAdapter<string, string, string, string> {
    return new IamDrizzleAdapter<string, string, string, string>({ db, ops: OPS, tables: TABLES })
  }

  async function insertRole(
    client: Pool,
    role: { id: string; permissions: unknown[]; inherits?: string[]; scope?: string },
  ): Promise<void> {
    await client.query(
      'INSERT INTO iam_roles (id, name, permissions, inherits, scope) VALUES ($1, $2, $3::jsonb, $4::jsonb, $5) ' +
        'ON CONFLICT (id) DO UPDATE SET permissions = EXCLUDED.permissions, inherits = EXCLUDED.inherits, scope = EXCLUDED.scope',
      [role.id, role.id, JSON.stringify(role.permissions), JSON.stringify(role.inherits ?? []), role.scope ?? null],
    )
  }

  async function assign(subjectId: string, roleId: string, scope?: string): Promise<void> {
    await pool.query(
      'INSERT INTO iam_assignments (id, subject_id, role_id, scope) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING',
      [`${subjectId}:${roleId}:${scope ?? ''}`, subjectId, roleId, scope ?? null],
    )
  }

  async function setAttributes(subjectId: string, data: Record<string, unknown>): Promise<void> {
    await pool.query('INSERT INTO iam_subject_attrs (subject_id, data) VALUES ($1, $2::jsonb)', [
      subjectId,
      JSON.stringify(data),
    ])
  }

  /** Seed `count` roles; only `role-0` grants anything, `role-1` inherits it. */
  async function seedManyRoles(count: number): Promise<void> {
    for (let i = 0; i < count; i++) {
      await insertRole(pool, {
        id: `role-${i}`,
        inherits: i === 1 ? ['role-0'] : [],
        permissions: i === 0 ? [{ action: 'read', resource: 'doc' }] : [],
      })
    }
  }

  /** Capture `console.warn` for the duration of `body`, returning the lines it emitted. */
  async function captureWarnings<T>(body: () => Promise<T>): Promise<{ result: T; warnings: string[] }> {
    const warnings: string[] = []
    const real = console.warn
    console.warn = (...args: unknown[]) => warnings.push(args.map((a) => String(a)).join(' '))
    try {
      return { result: await body(), warnings }
    } finally {
      console.warn = real
    }
  }

  it('the harness is really talking to Postgres', async () => {
    const r = await pool.query('SELECT version() AS v')
    expect(String((r.rows[0] as { v: string }).v)).toContain('PostgreSQL')
    // The adapter reads what raw SQL wrote, so every catalog below round-trips through the store.
    await insertRole(pool, { id: 'probe', permissions: [{ action: 'read', resource: 'doc' }] })
    const roles = await adapter().listRoles()
    expect(roles.map((r2) => r2.id)).toEqual(['probe'])
    expect(roles[0]?.permissions).toEqual([{ action: 'read', resource: 'doc' }])
  })

  describe.each([33, 64, 65])('with %i roles loaded from Postgres', (count) => {
    it('both modes answer correctly through the interpreter fallback', async () => {
      await seedManyRoles(count)
      await assign('granted', 'role-0')
      await assign('inheritor', 'role-1')
      await assign('other', 'role-2')

      const production = new IamEngine({ adapter: adapter(), mode: 'production' })
      const development = new IamEngine({ adapter: adapter(), mode: 'development' })
      const { warnings } = await captureWarnings(async () => {
        for (const subject of ['granted', 'inheritor', 'other', 'nobody']) {
          const expected = subject === 'granted' || subject === 'inheritor'
          // Repeated calls tell a once-per-engine warning apart from a once-per-request one.
          for (let i = 0; i < 3; i++) {
            expect(
              await production.can(subject, 'read', { attributes: {}, type: 'doc' }),
              `production ${subject}`,
            ).toBe(expected)
            const dev = await development.check(subject, 'read', { attributes: {}, type: 'doc' })
            expect(dev.allowed, `development ${subject}`).toBe(expected)
            expect(dev.failure, `development ${subject} must not be an evaluation failure`).toBeUndefined()
          }
        }
      })

      const limitWarnings = warnings.filter((w) => w.includes(ROLE_LIMIT_WARNING))
      // One engine, one warning - across 12 requests each. Two engines here, so two lines.
      // The count/limit no longer ride the bare-code message; `healthCheck reports the table unavailable`
      // below pins those via structured meta instead.
      expect(limitWarnings).toHaveLength(2)
      production.dispose()
      development.dispose()
    })

    it('healthCheck reports the table unavailable while staying ok', async () => {
      await seedManyRoles(count)
      const engine = new IamEngine({ adapter: adapter(), mode: 'production' })
      const health = await captureWarnings(() => engine.healthCheck())
      expect(health.result.ok).toBe(true)
      expect(health.result.adapter).toBe('ok')
      expect(health.result.compiledTable).toEqual({
        available: false,
        limit: 32,
        reason: 'role-limit-exceeded',
        roleCount: count,
      })
      engine.dispose()
    })
  })

  it('32 roles still compile: healthCheck reports no fallback and emits no warning', async () => {
    await seedManyRoles(32)
    await assign('granted', 'role-0')
    const engine = new IamEngine({ adapter: adapter(), mode: 'production' })
    const { result, warnings } = await captureWarnings(async () => {
      const allowed = await engine.can('granted', 'read', { attributes: {}, type: 'doc' })
      return { allowed, health: await engine.healthCheck() }
    })
    expect(result.allowed).toBe(true)
    expect(result.health.ok).toBe(true)
    expect(result.health.compiledTable).toBeUndefined()
    expect(warnings.filter((w) => w.includes(ROLE_LIMIT_WARNING))).toEqual([])
    engine.dispose()
  })

  it('the compiled table expires on cacheTTL and picks up another connection write', async () => {
    await insertRole(pool, { id: 'r', permissions: [{ action: 'read', resource: 'doc' }] })
    await assign('u1', 'r')

    // 1s TTL and no invalidator (the default shape), so only the TTL can converge the table with the store.
    const engine = new IamEngine({ adapter: adapter(), cacheTTL: 1, mode: 'production' })
    expect(await engine.can('u1', 'read', { attributes: {}, type: 'doc' })).toBe(true)

    // Revoke on the OTHER pool. Nothing tells this engine.
    await writer.query(`UPDATE iam_roles SET permissions = '[]'::jsonb WHERE id = 'r'`)

    // Inside the TTL the engine may be stale; asserted so the window is a stated property.
    expect(await engine.can('u1', 'read', { attributes: {}, type: 'doc' })).toBe(true)

    await new Promise((resolve) => setTimeout(resolve, 1_300))
    expect(await engine.can('u1', 'read', { attributes: {}, type: 'doc' }), 'table did not expire on cacheTTL').toBe(
      false,
    )
    engine.dispose()
  })

  it('a grant ADDED on another connection also appears once the TTL elapses', async () => {
    await insertRole(pool, { id: 'r', permissions: [] })
    await assign('u1', 'r')
    const engine = new IamEngine({ adapter: adapter(), cacheTTL: 1, mode: 'production' })
    expect(await engine.can('u1', 'read', { attributes: {}, type: 'doc' })).toBe(false)

    await writer.query(
      `UPDATE iam_roles SET permissions = '[{"action":"read","resource":"doc"}]'::jsonb WHERE id = 'r'`,
    )
    await new Promise((resolve) => setTimeout(resolve, 1_300))
    expect(await engine.can('u1', 'read', { attributes: {}, type: 'doc' })).toBe(true)
    engine.dispose()
  })

  describe('table/interpreter divergences reproduce from a real store', () => {
    /** Both modes over the catalog currently in Postgres, with disagreements captured. */
    async function bothModes(request: {
      subjectId: string
      action: string
      resource: string
    }): Promise<{ production: boolean; development: boolean; disagreements: string[] }> {
      const disagreements: string[] = []
      const production = new IamEngine({ adapter: adapter(), mode: 'production' })
      const development = new IamEngine({
        adapter: adapter(),
        hooks: {
          onError: (err) => {
            if (err.message.includes(DISAGREE_MARKER)) disagreements.push(err.message)
          },
        },
        mode: 'development',
      })
      const realError = console.error
      console.error = (...args: unknown[]) => {
        if (
          !args
            .map((a) => String(a))
            .join(' ')
            .includes(DISAGREE_MARKER)
        )
          realError(...args)
      }
      try {
        const prod = await production.can(request.subjectId, request.action, { attributes: {}, type: request.resource })
        const dev = await development.check(request.subjectId, request.action, {
          attributes: {},
          type: request.resource,
        })
        return { development: dev.allowed, disagreements, production: prod }
      } finally {
        console.error = realError
        production.dispose()
        development.dispose()
      }
    }

    it('a VALID role permission whose condition throws on request data: table allows, interpreter denies', async () => {
      // The catalog is valid; the request throws, because a 3000-unit `blob` exceeds MAX_REGEX_INPUT_LENGTH (2048).
      // SECURITY: no catalog validation can stop this, and padding an attribute is attacker-reachable.
      await insertRole(pool, { id: 'clean', permissions: [{ action: 'read', resource: 'doc' }] })
      await insertRole(pool, {
        id: 'rotten',
        inherits: ['clean'],
        permissions: [
          {
            action: 'read',
            conditions: { all: [{ field: 'subject.attributes.blob', operator: 'matches', value: '^a+b' }] },
            resource: 'doc',
          },
        ],
      })
      await assign('u1', 'rotten')
      await setAttributes('u1', { blob: 'a'.repeat(3000) })

      // Guard against a vacuous pass: the adapter drops roles `validateRole` rejects on read.
      const loaded = await adapter().listRoles()
      expect(loaded.map((r) => r.id).sort(), 'the adapter dropped a role - this case would be vacuous').toEqual([
        'clean',
        'rotten',
      ])

      const v = await bothModes({ action: 'read', resource: 'doc', subjectId: 'u1' })
      expect(v.disagreements, `disagreement: ${v.disagreements[0] ?? ''}`).toEqual([])
      expect(v.production, 'production must not allow what development denies').toBe(v.development)
      // Two deny-everything engines would also agree. The inherited unconditional `clean` grant must still allow,
      // since the permission whose `matches` throws contributes nothing rather than revoking it.
      expect(v.production, 'the agreed verdict itself').toBe(true)
    })

    it('the condition-depth divergence is contained at the store: drizzle refuses the row', async () => {
      // `validateRole` rejects nesting at MAX_CONDITION_DEPTH, and this adapter re-validates on read.
      // WARN: relaxing read-time validation would let a hand-written over-deep row reach the engine.
      let conditions: AccessControl.IConditionGroup = {
        all: [{ field: 'subject.attributes.level', operator: 'gte', value: 0 }],
      }
      for (let i = 1; i < 10; i++) conditions = { all: [conditions] }
      await insertRole(pool, { id: 'r', permissions: [{ action: 'read', conditions, resource: 'doc' }] })
      await assign('u1', 'r')
      await setAttributes('u1', { level: 3 })

      const reported: string[] = []
      const realError = console.error
      const realWarn = console.warn
      const capture = (...args: unknown[]) => reported.push(args.map((a) => String(a)).join(' '))
      console.error = capture
      console.warn = capture
      try {
        await expect(adapter().listRoles()).rejects.toThrow('IAM_UNREADABLE_ROLE')
      } finally {
        console.error = realError
        console.warn = realWarn
      }
      expect(reported.join(' '), 'the refusal must name the row, not just fail').toContain(
        'Condition nesting exceeds MAX_CONDITION_DEPTH',
      )

      // And with the read refused, both modes agree - on deny.
      const v = await bothModes({ action: 'read', resource: 'doc', subjectId: 'u1' })
      expect(v.disagreements).toEqual([])
      expect(v.production).toBe(false)
      expect(v.development).toBe(false)
    })
  })
})
