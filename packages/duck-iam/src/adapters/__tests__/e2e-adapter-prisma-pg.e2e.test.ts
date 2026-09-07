/**
 * E2E: `IamPrismaAdapter` against REAL Postgres.
 *
 * `prisma.test.ts` runs the compliance matrix against `makePrismaMock()`. That
 * fake is the origin of the archetype bug this whole exercise exists for: it
 * ignored `where`, so the test named after the scoped/unscoped split never
 * exercised the split. Everything the adapter believes about `scope: null`,
 * about `NOT`, about a composite unique index over a nullable column and about
 * two writers racing is therefore still unverified.
 *
 * WHAT THIS IS NOT: `@prisma/client` is not a dependency of this package and
 * nothing here installs one. The delegate below is a *SQL-backed* implementation
 * of `IamPrisma.ILike` - every read and write is a real statement against a real
 * server, with real NULL semantics, a real unique index and real concurrency -
 * but the translation from Prisma's filter object to SQL is written here rather
 * than by Prisma. Each translation rule is documented at its implementation and
 * the one rule where Prisma's own behaviour is version-dependent (`NOT` over a
 * nullable column) is tested under BOTH readings, so a conclusion never rests
 * on the guess.
 *
 * The table shapes mirror the reference Prisma schema, notably
 * `@@unique([subjectId, roleId, scope])`, which in Postgres is NULLS DISTINCT -
 * the exact property the adapter's `assignRole` comment says it works around.
 */
import { execFile } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { connect } from 'node:net'
import { promisify } from 'node:util'
import { Pool } from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { runAdapterCompliance } from '../__compliance__/compliance'
import { type IamPrisma, IamPrismaAdapter } from '../prisma'

const exec = promisify(execFile)

async function docker(args: string[], timeout = 60_000): Promise<string> {
  const { stdout } = await exec('docker', args, { encoding: 'utf8', timeout })
  return stdout.trim()
}

async function dockerIsUp(): Promise<boolean> {
  try {
    await docker(['info', '--format', '{{.ServerVersion}}'], 5_000)
    return true
  } catch {
    return false
  }
}

async function waitFor(what: string, probe: () => Promise<boolean>, budgetMs = 60_000): Promise<void> {
  const deadline = Date.now() + budgetMs
  while (Date.now() < deadline) {
    if (await probe()) return
    await new Promise((r) => setTimeout(r, 200))
  }
  throw new Error(`${what} was not ready within ${budgetMs}ms`)
}

const CONTAINER = `duck-iam-adapterconf-prisma-${randomBytes(4).toString('hex')}`

async function startPostgres(): Promise<string> {
  await docker([
    'run',
    '-d',
    '--name',
    CONTAINER,
    '--label',
    'duck-iam-e2e-owned',
    '-p',
    '0:5432',
    '-e',
    'POSTGRES_USER=duckiam',
    '-e',
    'POSTGRES_PASSWORD=duckiam',
    '-e',
    'POSTGRES_DB=duckiam_prisma',
    'postgres:16-alpine',
  ])
  await waitFor(`${CONTAINER} accepting queries`, async () => {
    try {
      await docker(['exec', CONTAINER, 'psql', '-U', 'duckiam', '-d', 'duckiam_prisma', '-c', 'SELECT 1'], 10_000)
      return true
    } catch {
      return false
    }
  })
  const published = await docker(['port', CONTAINER, '5432'])
  const port = Number(published.split('\n')[0]?.split(':').pop())
  if (!Number.isInteger(port) || port <= 0) throw new Error(`no published port: ${published}`)
  await waitFor(`127.0.0.1:${port}`, async () => {
    return await new Promise<boolean>((resolve) => {
      const socket = connect({ host: '127.0.0.1', port })
      const done = (ok: boolean) => {
        socket.destroy()
        resolve(ok)
      }
      socket.once('connect', () => done(true))
      socket.once('error', () => done(false))
      socket.setTimeout(1_000, () => done(false))
    })
  })
  return `postgres://duckiam:duckiam@127.0.0.1:${port}/duckiam_prisma`
}

/** The reference Prisma models, as Postgres sees them. */
const SCHEMA = `
CREATE TABLE IF NOT EXISTS access_policy (
  id text PRIMARY KEY, name text NOT NULL, description text,
  version integer NOT NULL DEFAULT 1, algorithm text NOT NULL,
  rules jsonb NOT NULL, targets jsonb
);
CREATE TABLE IF NOT EXISTS access_role (
  id text PRIMARY KEY, name text NOT NULL, description text,
  permissions jsonb NOT NULL, inherits jsonb NOT NULL DEFAULT '[]'::jsonb,
  scope text, metadata jsonb
);
-- AccessAssignment.role is a required relation with onDelete: Cascade, which
-- Prisma migrates to exactly this foreign key. Without it this database would
-- accept a grant naming a role that does not exist - a write the contract
-- refuses on all six adapters.
CREATE TABLE IF NOT EXISTS access_assignment (
  id bigserial PRIMARY KEY, subject_id text NOT NULL, role_id text NOT NULL, scope text,
  CONSTRAINT fk_access_assignment_role FOREIGN KEY (role_id) REFERENCES access_role (id) ON DELETE CASCADE
);
-- NULLS NOT DISTINCT, matching the drizzle pg schema and the migration
-- schema.prisma now tells consumers to apply. The @@unique Prisma generates is
-- a plain unique index, and a plain unique index treats NULLs as distinct, so
-- two unscoped grants of the same role do not collide and the adapter's
-- read-then-write - which cannot be atomic on its own - let a concurrent pile
-- of identical rows through. Prisma cannot spell this, so it is a migration
-- the consumer runs; this DDL transcribes it.
CREATE UNIQUE INDEX IF NOT EXISTS uq_access_assignment ON access_assignment (subject_id, role_id, scope) NULLS NOT DISTINCT;
CREATE TABLE IF NOT EXISTS access_subject_attr (subject_id text PRIMARY KEY, data jsonb NOT NULL);
`

// ---------------------------------------------------------------------------
// A SQL-backed implementation of the delegate surface the adapter declares.
// ---------------------------------------------------------------------------

type Sql = { text: string; values: unknown[] }

/** camelCase field name to the column the reference schema gives it. */
function column(field: string): string {
  return field.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`)
}

/**
 * Translate a Prisma `where` object into SQL.
 *
 * Rules implemented, each one a documented Prisma behaviour:
 *  - `{ field: null }`            -> `col IS NULL`
 *  - `{ field: value }`           -> `col = $n`
 *  - `{ NOT: { field: null } }`   -> `col IS NOT NULL`
 *  - `{ NOT: { field: value } }`  -> depends on `notIncludesNull`; see below.
 *
 * Prisma's handling of `NOT` over a *nullable* column has changed across major
 * versions: older clients emitted a bare `col <> $n`, which silently drops rows
 * where the column is NULL; current ones include them. The adapter's
 * `updateAssignmentScope` builds exactly such a filter, so both readings are
 * exercised rather than one being assumed.
 */
function buildWhere(where: Record<string, unknown>, values: unknown[], notIncludesNull: boolean): string {
  const clauses: string[] = []
  for (const [field, value] of Object.entries(where)) {
    if (field === 'NOT') {
      if (typeof value !== 'object' || value === null) continue
      for (const [nf, nv] of Object.entries(value as Record<string, unknown>)) {
        const col = column(nf)
        if (nv === null) {
          clauses.push(`${col} IS NOT NULL`)
          continue
        }
        values.push(nv)
        clauses.push(
          notIncludesNull ? `(${col} IS NULL OR ${col} <> $${values.length})` : `${col} <> $${values.length}`,
        )
      }
      continue
    }
    const col = column(field)
    if (value === null || value === undefined) {
      clauses.push(`${col} IS NULL`)
      continue
    }
    values.push(value)
    clauses.push(`${col} = $${values.length}`)
  }
  return clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : ''
}

function rowsToObjects<T>(rows: Record<string, unknown>[], fields: readonly string[]): T[] {
  return rows.map((row) => {
    const out: Record<string, unknown> = {}
    for (const f of fields) out[f] = row[column(f)] ?? null
    return out as T
  })
}

const POLICY_FIELDS = ['id', 'name', 'description', 'version', 'algorithm', 'rules', 'targets'] as const
const ROLE_FIELDS = ['id', 'name', 'description', 'permissions', 'inherits', 'scope', 'metadata'] as const
const ASSIGNMENT_FIELDS = ['subjectId', 'roleId', 'scope'] as const

/**
 * The delegate the adapter is constructed with. Every method is a real
 * statement; nothing is answered from memory.
 */
function sqlPrisma(pool: Pool, notIncludesNull: boolean): IamPrisma.ILike {
  async function query(sql: Sql): Promise<Record<string, unknown>[]> {
    const res = await pool.query(sql.text, sql.values)
    return res.rows as Record<string, unknown>[]
  }

  function upsertSql(table: string, key: string, data: Record<string, unknown>): Sql {
    const fields = Object.keys(data)
    const cols = fields.map(column)
    const values = fields.map((f) => data[f])
    const placeholders = cols.map((_, i) => `$${i + 1}`)
    const updates = cols.filter((c) => c !== column(key)).map((c, i) => `${c} = EXCLUDED.${c}`)
    return {
      text: `INSERT INTO ${table} (${cols.join(', ')}) VALUES (${placeholders.join(', ')})
             ON CONFLICT (${column(key)}) DO UPDATE SET ${updates.join(', ')} RETURNING *`,
      values: values.map((v) => (v !== null && typeof v === 'object' ? JSON.stringify(v) : v)),
    }
  }

  /** The first row of a result the caller has already established is non-empty. */
  function firstRow<TRow>(rows: Record<string, unknown>[], fields: readonly string[], what: string): TRow {
    const mapped = rowsToObjects<TRow>(rows, fields)[0]
    if (mapped === undefined) throw new Error(`${what} returned no row`)
    return mapped
  }

  function store<TRow, TWhere extends Record<string, unknown>>(table: string, key: string, fields: readonly string[]) {
    return {
      deleteMany: async (args: { where: TWhere }) => {
        const values: unknown[] = []
        const where = buildWhere(args.where, values, notIncludesNull)
        const res = await pool.query(`DELETE FROM ${table} ${where}`, values)
        return { count: res.rowCount ?? 0 }
      },
      findMany: async (_args?: unknown): Promise<TRow[]> =>
        rowsToObjects<TRow>(await query({ text: `SELECT * FROM ${table}`, values: [] }), fields),
      findUnique: async (args: { where: TWhere }): Promise<TRow | null> => {
        const values: unknown[] = []
        const where = buildWhere(args.where, values, notIncludesNull)
        const rows = await query({ text: `SELECT * FROM ${table} ${where} LIMIT 1`, values })
        if (rows.length === 0) return null
        return firstRow<TRow>(rows, fields, `${table}.findUnique`)
      },
      upsert: async (args: {
        where: TWhere
        create: Record<string, unknown>
        update: Record<string, unknown>
      }): Promise<TRow> => firstRow<TRow>(await query(upsertSql(table, key, args.create)), fields, `${table}.upsert`),
    }
  }

  const policies = store<IamPrisma.IPolicyRow, { id: string }>('access_policy', 'id', POLICY_FIELDS)
  const roles = store<IamPrisma.IRoleRow, { id: string }>('access_role', 'id', ROLE_FIELDS)
  const attrs = store<IamPrisma.IAttrRow, { subjectId: string }>('access_subject_attr', 'subjectId', [
    'subjectId',
    'data',
  ])

  return {
    accessAssignment: {
      create: async (args: { data: Record<string, unknown> }) => {
        const fields = Object.keys(args.data)
        const cols = fields.map(column)
        const placeholders = cols.map((_, i) => `$${i + 1}`)
        try {
          const rows = await query({
            text: `INSERT INTO access_assignment (${cols.join(', ')}) VALUES (${placeholders.join(', ')}) RETURNING *`,
            values: fields.map((f) => args.data[f]),
          })
          return firstRow<IamPrisma.IAssignmentRow>(rows, ASSIGNMENT_FIELDS, 'accessAssignment.create')
        } catch (err) {
          // Prisma does not hand the driver's error through: a unique
          // violation reaches the caller as a PrismaClientKnownRequestError
          // with `code: 'P2002'`. The adapter is written against that code, so
          // a shim that leaked pg's `23505` would be testing a client nobody
          // runs.
          if (err !== null && typeof err === 'object' && Reflect.get(err, 'code') === '23505') {
            throw Object.assign(new Error('Unique constraint failed'), { code: 'P2002' })
          }
          // Same reasoning for the foreign key: pg's `23503` reaches a Prisma
          // caller as `P2003`.
          if (err !== null && typeof err === 'object' && Reflect.get(err, 'code') === '23503') {
            throw Object.assign(new Error('Foreign key constraint failed on the field: `roleId`'), { code: 'P2003' })
          }
          throw err
        }
      },
      deleteMany: async (args: { where: Record<string, unknown> }) => {
        const values: unknown[] = []
        const where = buildWhere(args.where, values, notIncludesNull)
        const res = await pool.query(`DELETE FROM access_assignment ${where}`, values)
        return { count: res.rowCount ?? 0 }
      },
      findMany: async (args: {
        take?: number
        where: { subjectId: string; roleId?: string; scope?: string | null }
      }): Promise<IamPrisma.IAssignmentRow[]> => {
        const values: unknown[] = []
        const where = buildWhere(args.where, values, notIncludesNull)
        const limit = args.take === undefined ? '' : ` LIMIT ${Number(args.take)}`
        return rowsToObjects<IamPrisma.IAssignmentRow>(
          await query({ text: `SELECT * FROM access_assignment ${where}${limit}`, values }),
          ASSIGNMENT_FIELDS,
        )
      },
      updateMany: async (args: { data: Record<string, unknown>; where: Record<string, unknown> }) => {
        const values: unknown[] = []
        const sets = Object.entries(args.data).map(([f, v]) => {
          values.push(v)
          return `${column(f)} = $${values.length}`
        })
        const where = buildWhere(args.where, values, notIncludesNull)
        const res = await pool.query(`UPDATE access_assignment SET ${sets.join(', ')} ${where}`, values)
        return { count: res.rowCount ?? 0 }
      },
    },
    accessPolicy: policies,
    accessRole: roles,
    accessSubjectAttr: {
      findUnique: attrs.findUnique,
      upsert: attrs.upsert,
    },
  }
}

const DOCKER_UP = await dockerIsUp()
let bootError: string | undefined
let URL_: string | undefined
if (DOCKER_UP) {
  try {
    URL_ = await startPostgres()
    const boot = new Pool({ connectionString: URL_ })
    await boot.query(SCHEMA)
    await boot.end()
  } catch (err) {
    bootError = err instanceof Error ? err.message : String(err)
  }
}

afterAll(async () => {
  if (DOCKER_UP) await docker(['rm', '-f', '-v', CONTAINER]).catch(() => '')
})

describe('E2E harness reachability (prisma/pg)', () => {
  it('provisions a Postgres database whenever docker is available', () => {
    if (!DOCKER_UP) {
      expect(URL_, 'docker is down, so no e2e database is expected').toBeUndefined()
      return
    }
    expect(bootError, 'docker is up but the container failed to start').toBeUndefined()
    expect(URL_, 'docker is up but no database was provisioned - the suite would have skipped').toBeDefined()
  })
})

async function truncate(pool: Pool): Promise<void> {
  await pool.query('TRUNCATE access_assignment, access_subject_attr, access_role, access_policy')
}

// ---------------------------------------------------------------------------
// The shared matrix, against real SQL.
// ---------------------------------------------------------------------------
if (URL_) {
  const pool = new Pool({ connectionString: URL_, max: 8 })
  runAdapterCompliance('IamPrismaAdapter @ real Postgres', async () => {
    await truncate(pool)
    return new IamPrismaAdapter<string, string, string, string>(sqlPrisma(pool, true))
  })
  afterAll(async () => {
    await pool.end()
  })
}

const suite = URL_ ? describe : describe.skip

suite('IamPrismaAdapter against real SQL', () => {
  let pool: Pool
  let adapter: IamPrismaAdapter<string, string, string, string>

  beforeAll(() => {
    pool = new Pool({ connectionString: URL_ as string, max: 8 })
  })

  afterAll(async () => {
    await pool.end()
  })

  async function reset(notIncludesNull = true): Promise<void> {
    await truncate(pool)
    // `fk_access_assignment_role` refuses a grant naming a role that does not
    // exist, so the roles these cases grant - through the adapter or by raw
    // INSERT - are stored first.
    await pool.query(
      `INSERT INTO access_role (id, name, permissions) VALUES ('editor','Editor','[]'::jsonb), ('viewer','Viewer','[]'::jsonb), ('auditor','Auditor','[]'::jsonb)`,
    )
    adapter = new IamPrismaAdapter<string, string, string, string>(sqlPrisma(pool, notIncludesNull))
  }

  async function assignmentCount(): Promise<number> {
    const r = await pool.query('SELECT count(*)::int AS n FROM access_assignment')
    return (r.rows[0] as { n: number }).n
  }

  describe('the scoped/unscoped split, against a WHERE the server actually evaluates', () => {
    it('getSubjectRoles filters in SQL and getSubjectScopedRoles in JS - and they agree', async () => {
      await reset()
      await adapter.assignRole('u1', 'editor')
      await adapter.assignRole('u1', 'viewer', 'org-1')
      await adapter.assignRole('u1', 'auditor', 'org-2')

      // `getSubjectRoles` sends `scope: null` to the server; the scoped read
      // fetches every row and splits in JavaScript. Two code paths, one answer.
      expect((await adapter.getSubjectRoles('u1')).sort()).toEqual(['editor'])
      expect((await adapter.getSubjectScopedRoles('u1')).map((s) => `${s.role}@${s.scope}`).sort()).toEqual([
        'auditor@org-2',
        'viewer@org-1',
      ])
      expect(await assignmentCount()).toBe(3)
    })

    it('a row whose scope is SQL NULL is global; a row whose scope is a string is not', async () => {
      await reset()
      await pool.query(`INSERT INTO access_assignment (subject_id, role_id, scope) VALUES ('u1','editor',NULL)`)
      await pool.query(`INSERT INTO access_assignment (subject_id, role_id, scope) VALUES ('u1','editor','org-1')`)
      expect(await adapter.getSubjectRoles('u1')).toEqual(['editor'])
      expect(await adapter.getSubjectScopedRoles('u1')).toEqual([{ role: 'editor', scope: 'org-1' }])
    })

    it('a row whose scope is the EMPTY STRING is neither global nor rejected', async () => {
      await reset()
      // The reference Prisma schema has no CHECK constraint, so unlike the
      // drizzle pg schema this row can exist. `assignRole` refuses to create
      // one; nothing stops a migration or another writer.
      await pool.query(`INSERT INTO access_assignment (subject_id, role_id, scope) VALUES ('u1','editor','')`)
      const global = await adapter.getSubjectRoles('u1')
      const scoped = await adapter.getSubjectScopedRoles('u1')
      // The contract has exactly two buckets. A row in neither is a grant that
      // exists in the table and in no answer the engine can see; a row in both
      // is a scoped grant honoured globally. Either is a divergence.
      expect(
        global.length + scoped.length,
        `empty-scope row landed in ${global.length} global + ${scoped.length} scoped buckets`,
      ).toBe(1)
    })

    it('an empty-string scope grant is refused, not stored', async () => {
      await reset()
      await expect(adapter.assignRole('u1', 'editor', '')).rejects.toThrow(/empty string/)
      expect(await assignmentCount()).toBe(0)
    })

    it('revokeRole without a scope removes the unscoped row and every scoped one', async () => {
      await reset()
      await adapter.assignRole('u1', 'editor')
      await adapter.assignRole('u1', 'editor', 'org-1')
      await adapter.assignRole('u1', 'editor', 'org-2')
      await adapter.revokeRole('u1', 'editor')
      expect(await assignmentCount()).toBe(0)
    })

    it('revokeRole with a scope leaves the unscoped row alone', async () => {
      await reset()
      await adapter.assignRole('u1', 'editor')
      await adapter.assignRole('u1', 'editor', 'org-1')
      await adapter.revokeRole('u1', 'editor', 'org-1')
      expect(await adapter.getSubjectRoles('u1')).toEqual(['editor'])
      expect(await adapter.getSubjectScopedRoles('u1')).toEqual([])
    })
  })

  describe('two writers on two connections', () => {
    it('twenty concurrent identical unscoped grants leave exactly one row', async () => {
      await reset()
      const second = new Pool({ connectionString: URL_ as string, max: 8 })
      try {
        const b = new IamPrismaAdapter<string, string, string, string>(sqlPrisma(second, true))
        // `assignRole` is a read-then-write (`findMany` then `create`), because
        // a composite unique key over a nullable column cannot be addressed by
        // `upsert` - and a read cannot make a write atomic, so the index is
        // what actually decides this. Under the plain index Prisma generates,
        // NULLs are distinct, the duplicate is not caught, and twenty of these
        // left three rows. The index is now NULLS NOT DISTINCT, so the losers
        // of the race get P2002 and the adapter reads that as "already
        // granted".
        const results = await Promise.allSettled(
          Array.from({ length: 20 }, (_, i) => (i % 2 === 0 ? adapter : b).assignRole('u1', 'editor')),
        )
        const failed = results.filter((r) => r.status === 'rejected').length
        expect(await assignmentCount(), `${failed} of 20 grants were rejected`).toBe(1)
      } finally {
        await second.end()
      }
    }, 30_000)

    it('twenty concurrent identical SCOPED grants leave exactly one row', async () => {
      await reset()
      const second = new Pool({ connectionString: URL_ as string, max: 8 })
      try {
        const b = new IamPrismaAdapter<string, string, string, string>(sqlPrisma(second, true))
        // The scoped case always had a working unique index behind it, so the
        // loser of the race got a constraint violation rather than a second
        // row - and the adapter let it reject, nine times out of twenty here.
        // A repeat grant of a role the subject already holds is not a failure;
        // the adapter's own docstring calls repeat grants idempotent, and every
        // other adapter treats one as a no-op.
        const results = await Promise.allSettled(
          Array.from({ length: 20 }, (_, i) => (i % 2 === 0 ? adapter : b).assignRole('u1', 'editor', 'org-1')),
        )
        const failed = results.filter((r) => r.status === 'rejected').length
        expect(await assignmentCount()).toBe(1)
        expect(failed, 'a repeat grant of a role the subject already holds was rejected').toBe(0)
      } finally {
        await second.end()
      }
    }, 30_000)

    it('duplicate unscoped rows do not change the answer to getSubjectRoles', async () => {
      await reset()
      // A table that predates the NULLS NOT DISTINCT migration can already
      // hold the pile the old read-then-write let through, and applying the
      // migration is the consumer's move to make on their own schedule. The
      // index is dropped here to produce exactly that state - the reads must
      // still answer one role, and the revoke must still clear all of it.
      await pool.query('DROP INDEX uq_access_assignment')
      try {
        for (let i = 0; i < 5; i++) {
          await pool.query(`INSERT INTO access_assignment (subject_id, role_id, scope) VALUES ('u1','editor',NULL)`)
        }
        expect(await assignmentCount()).toBe(5)
        expect(await adapter.getSubjectRoles('u1')).toEqual(['editor'])
        await adapter.revokeRole('u1', 'editor')
        expect(await assignmentCount()).toBe(0)
      } finally {
        await pool.query(
          'CREATE UNIQUE INDEX uq_access_assignment ON access_assignment (subject_id, role_id, scope) NULLS NOT DISTINCT',
        )
      }
    })
  })

  describe('updateAssignmentScope over a nullable column', () => {
    // The adapter used to filter the target scope with `NOT: { scope:
    // fromScope }`, and Prisma's SQL for that has differed across versions on
    // whether NULL rows are included - an outcome that depends on which
    // reading the installed client emits is a bug waiting on a dependency
    // bump. Under the excluding reading the collapse-onto-global case left two
    // rows, because `NOT (scope = 'org-1')` is NULL, not true, for the very
    // rows being selected. The adapter no longer asks the database that
    // question at all; both readings are still run so it stays that way.
    for (const notIncludesNull of [true, false]) {
      const label = notIncludesNull ? 'NOT includes NULL rows' : 'NOT excludes NULL rows'

      it(`moves an unscoped grant to a scope (${label})`, async () => {
        await reset(notIncludesNull)
        await adapter.assignRole('u1', 'editor')
        expect(await adapter.updateAssignmentScope('u1', 'editor', undefined, 'org-1')).toBe(true)
        expect(await adapter.getSubjectRoles('u1')).toEqual([])
        expect(await adapter.getSubjectScopedRoles('u1')).toEqual([{ role: 'editor', scope: 'org-1' }])
      })

      it(`moves a scoped grant to global (${label})`, async () => {
        await reset(notIncludesNull)
        await adapter.assignRole('u1', 'editor', 'org-1')
        expect(await adapter.updateAssignmentScope('u1', 'editor', 'org-1', undefined)).toBe(true)
        expect(await adapter.getSubjectRoles('u1')).toEqual(['editor'])
        expect(await adapter.getSubjectScopedRoles('u1')).toEqual([])
      })

      it(`collapses onto an already-granted target scope (${label})`, async () => {
        await reset(notIncludesNull)
        await adapter.assignRole('u1', 'editor')
        await adapter.assignRole('u1', 'editor', 'org-1')
        expect(await adapter.updateAssignmentScope('u1', 'editor', undefined, 'org-1')).toBe(true)
        expect(await assignmentCount()).toBe(1)
        expect(await adapter.getSubjectRoles('u1')).toEqual([])
        expect(await adapter.getSubjectScopedRoles('u1')).toEqual([{ role: 'editor', scope: 'org-1' }])
      })

      it(`collapses onto an already-held GLOBAL grant (${label})`, async () => {
        await reset(notIncludesNull)
        await adapter.assignRole('u1', 'editor')
        await adapter.assignRole('u1', 'editor', 'org-1')
        // Moving the scoped row to global, where a global row already exists.
        // This is the case the `NOT` filter broke: the delete meant to clear
        // the way skipped the NULL-scoped row it was aimed at, and the update
        // then produced a second one.
        expect(await adapter.updateAssignmentScope('u1', 'editor', 'org-1', undefined)).toBe(true)
        expect(await assignmentCount()).toBe(1)
        expect(await adapter.getSubjectRoles('u1')).toEqual(['editor'])
      })

      it(`returns false when no source row matches (${label})`, async () => {
        await reset(notIncludesNull)
        await adapter.assignRole('u1', 'editor', 'org-2')
        expect(await adapter.updateAssignmentScope('u1', 'editor', 'org-9', 'org-1')).toBe(false)
        // A stale fromScope must not delete the grant the caller is moving onto.
        expect(await adapter.getSubjectScopedRoles('u1')).toEqual([{ role: 'editor', scope: 'org-2' }])
      })
    }
  })

  describe('corrupt rows must not read as absent', () => {
    it('a data column holding JSON null throws rather than answering {}', async () => {
      await reset()
      await pool.query(`INSERT INTO access_subject_attr (subject_id, data) VALUES ('u1','null'::jsonb)`)
      // The drizzle adapter answers `{}` for this exact row. Two backends, two
      // answers, and `{}` is the one that retires every deny rule testing an
      // attribute.
      await expect(adapter.getSubjectAttributes('u1')).rejects.toThrow(/corrupted attributes/)
    })

    it('a data column holding a JSON array throws', async () => {
      await reset()
      await pool.query(`INSERT INTO access_subject_attr (subject_id, data) VALUES ('u1','[1,2]'::jsonb)`)
      await expect(adapter.getSubjectAttributes('u1')).rejects.toThrow(/corrupted attributes/)
    })

    it('a policy row whose rules column is JSON null is refused, not dropped', async () => {
      await reset()
      await pool.query(
        `INSERT INTO access_policy (id, name, algorithm, rules) VALUES ('p1','Broken','deny-overrides','null'::jsonb)`,
      )
      // Dropping it is the fail-open: `rules: null` read loosely looks like a
      // policy with no rules, which under deny-overrides denies nothing, and
      // returning `null` from `getPolicy` makes a corrupt row indistinguishable
      // from a deleted one. Neither answer is safe when the row may have been
      // the rule saying NO.
      await expect(adapter.getPolicy('p1')).rejects.toThrow(/cannot be read/)
      await expect(adapter.listPolicies()).rejects.toThrow(/cannot be read/)
    })

    it('a role row whose permissions column is a JSON object is dropped', async () => {
      await reset()
      await pool.query(`INSERT INTO access_role (id, name, permissions) VALUES ('r1','Broken','{"action":"*"}'::jsonb)`)
      expect(await adapter.getRole('r1')).toBeNull()
    })

    it('a stored __proto__ attribute key makes the row unreadable rather than half-read', async () => {
      await reset()
      await pool.query(
        `INSERT INTO access_subject_attr (subject_id, data) VALUES ('u1','{"__proto__":{"tier":"gold"},"team":"A"}'::jsonb)`,
      )
      // Assigning the key would set the bag's prototype and answer `gold` for
      // a subject nobody granted it; owning it as a plain key would leave
      // whatever it was meant to hold absent, which retires every deny rule
      // testing that attribute. The row is refused instead.
      await expect(adapter.getSubjectAttributes('u1')).rejects.toThrow(/corrupted attributes/)
    })
  })

  describe('round-trip fidelity', () => {
    it('a policy keeps its scalar types across a real jsonb column', async () => {
      await reset()
      await adapter.savePolicy({
        algorithm: 'deny-overrides',
        description: 'D',
        id: 'p1',
        name: 'P',
        rules: [
          { actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'r1', priority: 10, resources: ['post'] },
        ],
        targets: { actions: ['read'] },
        version: 7,
      })
      const got = await adapter.getPolicy('p1')
      expect(typeof got?.version).toBe('number')
      expect(got?.version).toBe(7)
      expect(typeof got?.rules[0]?.priority).toBe('number')
      expect(got?.targets).toEqual({ actions: ['read'] })
    })

    it('a role keeps inherits and metadata across a real jsonb column', async () => {
      await reset()
      await adapter.saveRole({
        id: 'r1',
        inherits: ['base'],
        metadata: { level: 3 },
        name: 'R',
        permissions: [{ action: 'read', resource: 'post' }],
        scope: 'org-1',
      })
      const got = await adapter.getRole('r1')
      expect(got?.inherits).toEqual(['base'])
      expect(got?.metadata).toEqual({ level: 3 })
      expect(got?.scope).toBe('org-1')
    })
  })
})
