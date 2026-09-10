// E2E: `IamEngine.withTransaction` on real Postgres and the shipped schema.
// A rolled-back grant leaves no row and never reaches the shared cache; a read in the transaction sees its own grant.
import { and, eq, isNull, or } from 'drizzle-orm'
import { drizzle } from 'drizzle-orm/node-postgres'
import { Pool } from 'pg'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { IamDrizzleAdapter } from '../../../adapters/drizzle'
import { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from '../../../adapters/drizzle/pg'
import { applyPgSchema, assertE2eReachable, isolatedDatabaseUrl } from '../../../test/e2e-env'
import type { Batch } from '../../batch'
import { IamEngine } from '../engine'

/** The `changed` flag of every outcome, in input order. */
function changedFlags<TRow>(result: Batch.Result<TRow, Batch.Change>): (boolean | undefined | null)[] {
  return result.outcomes.map((o) => (o.ok ? o.value.changed : null))
}

const URL = await isolatedDatabaseUrl('transaction')
assertE2eReachable('engine-transaction-pg', URL)
const suite = URL ? describe : describe.skip

type Role = 'admin' | 'viewer'

const TABLES = { assignments: iamAssignments, attrs: iamSubjectAttrs, policies: iamPolicies, roles: iamRoles }
// The full drizzle operator bundle, so the adapter runs its deployment statements.
// NOTE: without `or` batch revokes go one DELETE per row; without `isNull` scope moves fall back to revoke + assign.
const OPS = { and, eq, isNull, or }

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
    // `iam_assignments.role_id` is a real foreign key, so the role must exist before it is granted.
    await engine.admin.saveRole({ id: 'admin', name: 'admin', permissions: [] })
  })

  async function assignmentCount(): Promise<number> {
    const r = await pool.query('SELECT count(*)::int AS n FROM iam_assignments')
    return (r.rows[0] as { n: number }).n
  }

  /** Runs `body` in a transaction that always rolls back; anything but the sentinel is re-thrown. */
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
    // Warm the shared cache with "no roles", so only a leaked invalidation could change the answer below.
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
      const first = await engine.admin.assignRoles(rows)
      const again = await engine.admin.assignRoles(rows)

      // The conflict clause skips the duplicate as applied; only `changed` shows the second call wrote nothing.
      expect(again.applied).toBe(1)
      expect(changedFlags(first)).toEqual([true])
      expect(changedFlags(again)).toEqual([false])
      expect(await assignmentCount()).toBe(1)
    })

    it('a half-new batch reports changed per row, in input order', async () => {
      await engine.admin.assignRoles([{ roleId: 'admin', subjectId: 'c1' }])

      const result = await engine.admin.assignRoles([
        { roleId: 'viewer', subjectId: 'c2' },
        { roleId: 'admin', subjectId: 'c1' },
        { roleId: 'admin', scope: 'org-1', subjectId: 'c1' },
      ])

      // All three are applied, but only the first and third are new; `(c1, admin)` unscoped does not cover `org-1`.
      expect(result.applied).toBe(3)
      expect(changedFlags(result)).toEqual([true, false, true])
      expect(await assignmentCount()).toBe(3)
    })

    it('credits a write once when the batch names it twice', async () => {
      // One INSERT happened, so only the first row is credited. Runs the `or` path: one statement for the list.
      const result = await engine.admin.assignRoles([
        { roleId: 'admin', subjectId: 'c5' },
        { roleId: 'admin', subjectId: 'c5' },
      ])

      expect(result.applied).toBe(2)
      expect(changedFlags(result)).toEqual([true, false])
      expect(await assignmentCount()).toBe(1)
    })

    it('credits a subsuming revoke, not the narrower row it already covers', async () => {
      await engine.admin.assignRoles([{ roleId: 'admin', scope: 'org-1', subjectId: 'c6' }])

      // The unscoped first row revokes every scope, so it already covers the second row's grant.
      const result = await engine.admin.revokeRoles([
        { roleId: 'admin', subjectId: 'c6' },
        { roleId: 'admin', scope: 'org-1', subjectId: 'c6' },
      ])

      expect(changedFlags(result)).toEqual([true, false])
      expect(await assignmentCount()).toBe(0)
    })

    it('hands each outcome back the row it answers', async () => {
      const rows = [
        { roleId: 'admin' as const, subjectId: 'c7' },
        { roleId: 'viewer' as const, scope: 'org-1', subjectId: 'c8' },
      ]
      const result = await engine.admin.assignRoles(rows)

      // Each outcome carries its input row by reference, so identical rows stay distinct.
      expect(result.outcomes.map((o) => o.row)).toEqual(rows)
      expect(result.outcomes[0]?.row).toBe(rows[0])
    })

    it('revokeRoles reports changed only for triples that were granted', async () => {
      await engine.admin.assignRoles([{ roleId: 'admin', subjectId: 'c3' }])

      const result = await engine.admin.revokeRoles([
        { roleId: 'admin', subjectId: 'c3' },
        { roleId: 'viewer', subjectId: 'c4' },
      ])

      expect(result.applied).toBe(2)
      expect(changedFlags(result)).toEqual([true, false])
      expect(await assignmentCount()).toBe(0)
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

      const result = await engine.admin.revokeRoles([{ roleId: 'admin', subjectId: 'b7' }])

      // One row removed two grants: it matches on subject and role, not on a scope it never named.
      expect(changedFlags(result)).toEqual([true])
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
