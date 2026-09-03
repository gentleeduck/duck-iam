/**
 * E2E: `IamEngine.withTransaction` against REAL Postgres on the REAL shipped schema.
 *
 * Proves the two things in-process tests cannot: that a rolled-back grant
 * leaves no assignment row AND never reaches the shared cache, and that a read
 * inside the transaction sees the transaction's own uncommitted grant.
 *
 * Skips when DUCKIAM_E2E_DATABASE_URL is unset; `globalSetup` provisions a
 * container when docker is available.
 */
import { and, eq, or } from 'drizzle-orm'
import { drizzle } from 'drizzle-orm/node-postgres'
import { Pool } from 'pg'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { IamDrizzleAdapter } from '../../../adapters/drizzle'
import { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from '../../../adapters/drizzle/pg'
import { applyPgSchema, isolatedDatabaseUrl } from '../../../test/e2e-env'
import { IamEngine } from '../engine'

const URL = await isolatedDatabaseUrl('transaction')
const suite = URL ? describe : describe.skip

type Role = 'admin' | 'viewer'

const TABLES = { assignments: iamAssignments, attrs: iamSubjectAttrs, policies: iamPolicies, roles: iamRoles }
// `isNull` is omitted deliberately: it is needed only by `updateAssignmentScope`,
// which nothing here calls, and drizzle's own `isNull` does not satisfy the
// adapter's declared `(col: unknown) => SQLWrapper` without a cast.
// `or` IS supplied: it is what collapses `revokeRoleMany` into one DELETE, and
// the batch cases below would silently exercise the per-row fallback without it.
const OPS = { and, eq, or }

suite('E2E IamEngine.withTransaction on real Postgres', () => {
  let pool: Pool
  let db: ReturnType<typeof drizzle>
  let engine: IamEngine<string, string, Role, string>

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
    engine = new IamEngine<string, string, Role, string>({
      adapter: new IamDrizzleAdapter<string, string, Role, string>({ db, ops: OPS, tables: TABLES }),
    })
    // `iam_assignments.role_id` is a real foreign key, so the role has to exist
    // before anything can be granted it.
    await engine.admin.saveRole({ id: 'admin', name: 'admin', permissions: [] })
  })

  async function assignmentCount(): Promise<number> {
    const r = await pool.query('SELECT count(*)::int AS n FROM iam_assignments')
    return (r.rows[0] as { n: number }).n
  }

  /**
   * Runs `body` on a transaction that always rolls back, re-throwing anything
   * the body threw that is not our own sentinel - so a failed assertion inside
   * the transaction surfaces instead of being swallowed by the rollback.
   */
  async function rollsBack(body: (tx: unknown) => Promise<void>): Promise<void> {
    const sentinel = new Error('__rollback__')
    await db
      .transaction(async (tx) => {
        await body(tx)
        throw sentinel
      })
      .catch((err: unknown) => {
        if (err !== sentinel) throw err
      })
  }

  it('rollback leaves no assignment row', async () => {
    await rollsBack(async (tx) => {
      const perms = engine.withTransaction(tx)
      await perms.admin.assignRole('u1', 'admin')

      // Written on the transaction, and invisible to the outer connection.
      expect(await perms.getEffectiveRoles('u1')).toContain('admin')
      expect(await assignmentCount()).toBe(0)
    })

    expect(await assignmentCount()).toBe(0)
  })

  it('a bound read sees the transaction own uncommitted grant', async () => {
    await rollsBack(async (tx) => {
      const perms = engine.withTransaction(tx)
      await perms.admin.assignRole('u2', 'admin')

      expect(await perms.getEffectiveRoles('u2')).toContain('admin')
      expect(await engine.getEffectiveRoles('u2')).not.toContain('admin')
    })
  })

  it('after a rollback the shared engine still answers no', async () => {
    await rollsBack(async (tx) => {
      const perms = engine.withTransaction(tx)
      await perms.admin.assignRole('u3', 'admin')
    })

    expect(await engine.getEffectiveRoles('u3')).not.toContain('admin')
  })

  it('a rolled-back grant never reaches the shared cache', async () => {
    // Warm the shared cache with "u5 has no roles", so a leaked invalidation
    // would be the only thing that could change the answer below.
    expect(await engine.getEffectiveRoles('u5')).toEqual([])

    await rollsBack(async (tx) => {
      const perms = engine.withTransaction(tx)
      await perms.admin.assignRole('u5', 'admin')
      expect(perms.pending.size).toBe(1)
    })

    expect(await engine.getEffectiveRoles('u5')).toEqual([])
  })

  it('commit plus flush makes the grant visible on the shared engine', async () => {
    // Warm the shared cache first, so only the flush can make it visible.
    expect(await engine.getEffectiveRoles('u4')).toEqual([])

    let pending: { flush(): Promise<void> } | undefined
    await db.transaction(async (tx) => {
      const perms = engine.withTransaction(tx)
      await perms.admin.assignRole('u4', 'admin')
      pending = perms.pending
    })

    expect(await assignmentCount()).toBe(1)
    await pending?.flush()

    expect(await engine.getEffectiveRoles('u4')).toContain('admin')
  })

  describe('batch role writes through the set-based drizzle statements', () => {
    beforeEach(async () => {
      await engine.admin.saveRole({ id: 'viewer', name: 'viewer', permissions: [] })
    })

    it('assignRoles grants every triple', async () => {
      const result = await engine.admin.assignRoles([
        { roleId: 'admin', subjectId: 'b1' },
        { roleId: 'viewer', scope: 'org-1', subjectId: 'b2' },
      ])

      expect(result.applied).toBe(2)
      expect(await assignmentCount()).toBe(2)
      expect(await engine.getEffectiveRoles('b1')).toContain('admin')
      expect(await engine.getEffectiveRoles('b2', 'org-1')).toContain('viewer')
    })

    it('assignRoles is idempotent, like the single-row grant', async () => {
      const rows = [{ roleId: 'admin' as const, subjectId: 'b3' }]
      await engine.admin.assignRoles(rows)
      const again = await engine.admin.assignRoles(rows)

      // The duplicate is skipped by the conflict clause, not reported as a
      // miss - the grant is in place either way.
      expect(again.applied).toBe(1)
      expect(await assignmentCount()).toBe(1)
    })

    it('revokeRoles removes every triple in the list and nothing else', async () => {
      await engine.admin.assignRoles([
        { roleId: 'admin', subjectId: 'b4' },
        { roleId: 'viewer', subjectId: 'b5' },
        { roleId: 'admin', subjectId: 'b6' },
      ])

      await engine.admin.revokeRoles([
        { roleId: 'admin', subjectId: 'b4' },
        { roleId: 'viewer', subjectId: 'b5' },
      ])

      expect(await assignmentCount()).toBe(1)
      expect(await engine.getEffectiveRoles('b6')).toContain('admin')
    })

    it('a revoke row with no scope clears the role in every scope', async () => {
      await engine.admin.assignRoles([
        { roleId: 'admin', scope: 'org-1', subjectId: 'b7' },
        { roleId: 'admin', scope: 'org-2', subjectId: 'b7' },
      ])

      await engine.admin.revokeRoles([{ roleId: 'admin', subjectId: 'b7' }])

      expect(await assignmentCount()).toBe(0)
    })

    it('a rolled-back batch leaves no rows and never reaches the shared cache', async () => {
      expect(await engine.getEffectiveRoles('b8')).toEqual([])

      await rollsBack(async (tx) => {
        const perms = engine.withTransaction(tx)
        await perms.admin.assignRoles([
          { roleId: 'admin', subjectId: 'b8' },
          { roleId: 'viewer', subjectId: 'b9' },
        ])

        expect(await perms.getEffectiveRoles('b8')).toContain('admin')
        // One buffered invalidation per distinct subject, none applied yet.
        expect(perms.pending.size).toBe(2)
        expect(await assignmentCount()).toBe(0)
      })

      expect(await assignmentCount()).toBe(0)
      expect(await engine.getEffectiveRoles('b8')).toEqual([])
    })
  })

  it('a role saved and rolled back leaves no row', async () => {
    await rollsBack(async (tx) => {
      const perms = engine.withTransaction(tx)
      await perms.admin.saveRole({ id: 'viewer', name: 'viewer', permissions: [] })

      expect(await perms.admin.getRole('viewer')).not.toBeNull()
    })

    expect(await engine.admin.getRole('viewer')).toBeNull()
  })
})
