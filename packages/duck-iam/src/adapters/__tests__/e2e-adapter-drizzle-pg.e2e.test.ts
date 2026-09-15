/**
 * E2E: `IamDrizzleAdapter` on real Postgres with the shipped schema: the compliance matrix, plus what the array mock
 * cannot express (driver-only rows, two connections, column-type fidelity, grant windows against a real clock).
 */
import { execFile } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { connect } from 'node:net'
import { promisify } from 'node:util'
import { and, eq, isNull, or, type SQLWrapper } from 'drizzle-orm'
import { drizzle } from 'drizzle-orm/node-postgres'
import { Pool } from 'pg'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { IamEngine } from '../../core/engine'
import type { IamPrimitives } from '../../core/types'
import { applyPgSchema, dockerIsUp as sharedDockerIsUp } from '../../test/e2e-env'
import { runAdapterCompliance } from '../__compliance__/compliance'
import { OPTIONAL_SUPPORT } from '../__compliance__/optional-support'
import { IamDrizzleAdapter } from '../drizzle'
import { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from '../drizzle/pg'
import { IamMemoryAdapter } from '../memory'

// The shared matrix sets no per-case timeout, and a real container round trip can exceed vitest's 5s default.
// 30s is still a bound: a CRUD round trip that needs longer is hung, not slow.
vi.setConfig({ testTimeout: 30_000 })

const exec = promisify(execFile)

async function docker(args: string[], timeout = 60_000): Promise<string> {
  const { stdout } = await exec('docker', args, { encoding: 'utf8', timeout })
  return stdout.trim()
}

/** The shared probe from `src/test/e2e-env.ts`: one budget, so a busy daemon is not mistaken for an absent one. */
const dockerIsUp = sharedDockerIsUp

async function waitFor(what: string, probe: () => Promise<boolean>, budgetMs = 60_000): Promise<void> {
  const deadline = Date.now() + budgetMs
  while (Date.now() < deadline) {
    if (await probe()) return
    await new Promise((r) => setTimeout(r, 200))
  }
  throw new Error(`${what} was not ready within ${budgetMs}ms`)
}

/** A privately named suite-owned Postgres; `src/test/e2e-containers.ts` sweeps these only once abandoned. */
const PG_CONTAINER = `duck-iam-adapterconf-pg-${randomBytes(4).toString('hex')}`

async function startPostgres(): Promise<string> {
  await docker([
    'run',
    '-d',
    '--name',
    PG_CONTAINER,
    '--label',
    'duck-iam-e2e-owned',
    '-p',
    '0:5432',
    '-e',
    'POSTGRES_USER=duckiam',
    '-e',
    'POSTGRES_PASSWORD=duckiam',
    '-e',
    'POSTGRES_DB=duckiam_e2e',
    'postgres:18.4-alpine3.24',
  ])
  await waitFor(`${PG_CONTAINER} accepting queries`, async () => {
    try {
      await docker(['exec', PG_CONTAINER, 'psql', '-U', 'duckiam', '-d', 'duckiam_e2e', '-c', 'SELECT 1'], 10_000)
      return true
    } catch {
      return false
    }
  })
  const published = await docker(['port', PG_CONTAINER, '5432'])
  const port = Number(published.split('\n')[0]?.split(':').pop())
  if (!Number.isInteger(port) || port <= 0) throw new Error(`no published port: ${published}`)
  // The in-container probe proves the server is up, not that docker's port
  // forwarding is accepting yet.
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
  return `postgres://duckiam:duckiam@127.0.0.1:${port}/duckiam_e2e`
}

/** Create a database on our own server and return its URL. */
async function makeDatabase(baseUrl: string, name: string): Promise<string> {
  const admin = new Pool({ connectionString: baseUrl })
  try {
    await admin.query(`CREATE DATABASE ${name}`)
  } finally {
    await admin.end()
  }
  const url = new URL(baseUrl)
  url.pathname = `/${name}`
  return url.toString()
}

const DOCKER_UP = await dockerIsUp()
let bootError: string | undefined
let STRICT_URL: string | undefined
if (DOCKER_UP) {
  try {
    STRICT_URL = await makeDatabase(await startPostgres(), 'strict')
  } catch (err) {
    bootError = err instanceof Error ? err.message : String(err)
  }
}

afterAll(async () => {
  if (DOCKER_UP) await docker(['rm', '-f', '-v', PG_CONTAINER]).catch(() => '')
})

const TABLES = { assignments: iamAssignments, attrs: iamSubjectAttrs, policies: iamPolicies, roles: iamRoles }
/** Drizzle's own operators, passed straight through; `ops` is typed against drizzle, so no wrappers are needed. */
const OPS = { and, eq, isNull, or }

// Guard against a skipped suite passing vacuously: if docker answers, a missing database is a failure.
describe('E2E harness reachability (drizzle/pg)', () => {
  it('provisions a Postgres database whenever docker is available', () => {
    // CI provisions the backend up front, so there it is required regardless of the probe.
    if (process.env.CI) {
      expect(bootError, 'the container failed to start in CI, where it is provisioned').toBeUndefined()
      expect(STRICT_URL, 'no e2e Postgres in CI, where the workflow provisions one - the suite skipped').toBeDefined()
      return
    }
    if (!DOCKER_UP) {
      expect(STRICT_URL, 'docker is down, so no e2e database is expected').toBeUndefined()
      return
    }
    expect(bootError, 'docker is up but the container failed to start').toBeUndefined()
    expect(STRICT_URL, 'docker is up but no e2e Postgres was provisioned - the suite would have skipped').toBeDefined()
  })
})

type Adapter = IamDrizzleAdapter<string, string, string, string>

function makePool(url: string): Pool {
  return new Pool({ connectionString: url, max: 8 })
}

async function truncate(pool: Pool): Promise<void> {
  await pool.query('TRUNCATE iam_assignments, iam_subject_attrs, iam_roles, iam_policies CASCADE')
}

function makeAdapter(pool: Pool): Adapter {
  return new IamDrizzleAdapter<string, string, string, string>({ db: drizzle(pool), ops: OPS, tables: TABLES })
}

/**
 * The whole error chain of a rejected call, as one string.
 * INFO: drizzle wraps driver errors in `Failed query: ...` and hangs the real one off `cause`.
 */
async function failureChain(run: () => Promise<unknown>): Promise<string> {
  try {
    await run()
  } catch (err) {
    const parts: string[] = []
    let node: unknown = err
    for (let depth = 0; depth < 8 && node instanceof Error; depth++) {
      parts.push(node.message, JSON.stringify({ constraint: (node as { constraint?: string }).constraint }))
      node = node.cause
    }
    return parts.join(' | ')
  }
  return '<resolved>'
}

// ---------------------------------------------------------------------------
// 1. The shipped schema, unmodified.
// ---------------------------------------------------------------------------
if (STRICT_URL) {
  const strictPool = makePool(STRICT_URL)
  await applyPgSchema(strictPool)
  runAdapterCompliance(
    'IamDrizzleAdapter @ real Postgres (shipped schema)',
    async () => {
      await truncate(strictPool)
      return makeAdapter(strictPool)
    },
    { supports: OPTIONAL_SUPPORT.IamDrizzleAdapter },
  )
  afterAll(async () => {
    await strictPool.end()
  })
}

// ---------------------------------------------------------------------------
// 2. Cases the array-backed mock cannot produce.
// ---------------------------------------------------------------------------
const suite = STRICT_URL ? describe : describe.skip

suite('IamDrizzleAdapter against rows only a real driver returns', () => {
  let pool: Pool
  let adapter: Adapter

  beforeAll(async () => {
    pool = makePool(STRICT_URL as string)
    await applyPgSchema(pool)
  })

  afterAll(async () => {
    await pool.end()
  })

  async function reset(): Promise<void> {
    await truncate(pool)
    adapter = makeAdapter(pool)
  }

  async function seedRole(id: string, name = id): Promise<void> {
    await pool.query(`INSERT INTO iam_roles (id, name, permissions) VALUES ($1, $2, '[]'::jsonb)`, [id, name])
  }

  // All six adapters refuse a grant of an unstored role; names need not be unique, since every lookup is by `id`.
  describe('the assignments-to-roles foreign key, now shared by all six', () => {
    it('assignRole to a role that does not exist is refused here and on memory', async () => {
      await reset()
      const mem = new IamMemoryAdapter<string, string, string, string>()
      await expect(mem.assignRole('u1', 'ghost')).rejects.toThrow(/role that is not stored/)
      expect(await mem.getSubjectRoles('u1')).toEqual([])

      // Same call, same contract, same outcome - the database says it with the
      // FK, memory says it with a check, and neither stores the row.
      expect(await failureChain(() => adapter.assignRole('u1', 'ghost'))).toMatch(/fk_iam_assignments_role/)
      const rows = await pool.query('SELECT count(*)::int AS n FROM iam_assignments')
      expect((rows.rows[0] as { n: number }).n).toBe(0)
    })

    it('two policies with the same name and different ids now coexist', async () => {
      await reset()
      const base = { algorithm: 'deny-overrides' as const, name: 'Same Name', rules: [] }
      await adapter.savePolicy({ ...base, id: 'p1' })
      await adapter.savePolicy({ ...base, id: 'p2' })
      expect((await adapter.listPolicies()).map((p) => p.id).sort()).toEqual(['p1', 'p2'])
    })

    it('two unscoped roles with the same name now coexist', async () => {
      await reset()
      await adapter.saveRole({ id: 'r1', name: 'Same', permissions: [] })
      await adapter.saveRole({ id: 'r2', name: 'Same', permissions: [] })
      expect((await adapter.listRoles()).map((r) => r.id).sort()).toEqual(['r1', 'r2'])
    })

    it('the caller reads why the grant failed on the top-level message', async () => {
      await reset()
      // The adapter translates the FK violation into the refusal memory, file and redis raise,
      // keeping drizzle's `Failed query` error as `cause`.
      let top = ''
      let cause: unknown
      try {
        await adapter.assignRole('u1', 'ghost')
      } catch (err) {
        top = err instanceof Error ? err.message : String(err)
        cause = err instanceof Error ? err.cause : undefined
      }
      expect(top).toMatch(/cannot assign a role that is not stored/)
      // The driver error is not discarded: whoever wants the constraint name
      // can still reach it.
      expect(String(cause)).toMatch(/Failed query/)
    })

    it('the schema refuses an empty-string scope, matching the adapter guard', async () => {
      await reset()
      await seedRole('editor')
      await expect(
        pool.query(`INSERT INTO iam_assignments (id, subject_id, role_id, scope) VALUES ('a1','u1','editor','')`),
      ).rejects.toThrow(/ch_iam_assignments_scope_not_blank/)
    })
  })

  describe('SQL NULL vs a scope string: the two read paths must agree', () => {
    it('an unscoped grant is global on both reads, a scoped one on neither', async () => {
      await reset()
      await seedRole('editor')
      await seedRole('viewer')
      await adapter.assignRole('u1', 'editor')
      await adapter.assignRole('u1', 'viewer', 'org-1')

      const global = await adapter.getSubjectRoles('u1')
      const scoped = await adapter.getSubjectScopedRoles('u1')
      expect(global).toEqual(['editor'])
      expect(scoped).toEqual([{ role: 'viewer', scope: 'org-1' }])
      // No row may be reported by both, and none may be lost by both.
      const rows = await pool.query('SELECT count(*)::int AS n FROM iam_assignments')
      expect(global.length + scoped.length).toBe((rows.rows[0] as { n: number }).n)
    })

    it('a scope whose text starts with a space stays scoped on both reads', async () => {
      await reset()
      await seedRole('editor')
      // ' x' passes ch_..._scope_not_blank (it has a non-space char) and is a
      // scope like any other. It must never read back as a global grant.
      await pool.query(`INSERT INTO iam_assignments (id, subject_id, role_id, scope) VALUES ('a1','u1','editor',' x')`)
      expect(await adapter.getSubjectRoles('u1')).toEqual([])
      expect(await adapter.getSubjectScopedRoles('u1')).toEqual([{ role: 'editor', scope: ' x' }])
    })

    it('revokeRole without a scope removes the unscoped and every scoped row', async () => {
      await reset()
      await seedRole('editor')
      await adapter.assignRole('u1', 'editor')
      await adapter.assignRole('u1', 'editor', 'org-1')
      await adapter.assignRole('u1', 'editor', 'org-2')
      await adapter.revokeRole('u1', 'editor')
      expect(await adapter.getSubjectRoles('u1')).toEqual([])
      expect(await adapter.getSubjectScopedRoles('u1')).toEqual([])
    })
  })

  describe('timestamps the driver can return but the fake never does', () => {
    it('expires_at = infinity leaves the grant live', async () => {
      await reset()
      await seedRole('editor')
      // INFO: node-postgres parses Postgres `infinity` to the number Infinity, not a Date.
      await pool.query(
        `INSERT INTO iam_assignments (id, subject_id, role_id, expires_at) VALUES ('a1','u1','editor','infinity')`,
      )
      expect(await adapter.getSubjectRoles('u1')).toEqual(['editor'])
    })

    it('starts_at = -infinity leaves the grant live', async () => {
      await reset()
      await seedRole('editor')
      await pool.query(
        `INSERT INTO iam_assignments (id, subject_id, role_id, starts_at) VALUES ('a1','u1','editor','-infinity')`,
      )
      expect(await adapter.getSubjectRoles('u1')).toEqual(['editor'])
    })

    it('starts_at = infinity (a grant that never starts) denies', async () => {
      await reset()
      await seedRole('editor')
      await pool.query(
        `INSERT INTO iam_assignments (id, subject_id, role_id, starts_at) VALUES ('a1','u1','editor','infinity')`,
      )
      expect(await adapter.getSubjectRoles('u1')).toEqual([])
    })

    it('expires_at = -infinity (expired at the dawn of time) denies', async () => {
      await reset()
      await seedRole('editor')
      await pool.query(
        `INSERT INTO iam_assignments (id, subject_id, role_id, expires_at) VALUES ('a1','u1','editor','-infinity')`,
      )
      expect(await adapter.getSubjectRoles('u1')).toEqual([])
    })

    it('an expiry past the JS Date range still reads as live', async () => {
      await reset()
      await seedRole('editor')
      // Year 250000 fits timestamptz but not `Date` (+-8.64e15 ms); the grant is live today, so this must not deny.
      await pool.query(
        `INSERT INTO iam_assignments (id, subject_id, role_id, expires_at) VALUES ('a1','u1','editor','250000-01-01 00:00:00+00')`,
      )
      expect(await adapter.getSubjectRoles('u1')).toEqual(['editor'])
    })

    it('a live scoped grant with bounds round-trips through both reads', async () => {
      await reset()
      await seedRole('editor')
      const startsAt = new Date(Date.now() - 60_000)
      const expiresAt = new Date(Date.now() + 3_600_000)
      await adapter.assignRole('u1', 'editor', 'org-1', {
        attributes: { n: 3, ok: true, tier: 'gold' },
        expiresAt,
        startsAt,
      })
      expect(await adapter.getSubjectScopedRoles('u1')).toEqual([
        { attributes: { n: 3, ok: true, tier: 'gold' }, role: 'editor', scope: 'org-1' },
      ])
    })
  })

  describe('malformed rows must never produce an allow', () => {
    it('a policy whose rules column holds JSON null is refused, not read as rule-less', async () => {
      await reset()
      await pool.query(`INSERT INTO iam_policies (id, name, rules) VALUES ('p1','Broken','null'::jsonb)`)
      // SECURITY: the row may have been a deny, and `null` would look like a deleted policy.
      // Roles are allow-only, so a corrupt role can be dropped; a policy cannot.
      await expect(adapter.getPolicy('p1')).rejects.toThrow(/cannot be read/)
      await expect(adapter.listPolicies()).rejects.toThrow(/cannot be read/)
    })

    it('a role whose permissions column holds a JSON string is dropped', async () => {
      await reset()
      await pool.query(`INSERT INTO iam_roles (id, name, permissions) VALUES ('r1','Broken','"nope"'::jsonb)`)
      expect(await adapter.getRole('r1')).toBeNull()
      expect(await adapter.listRoles()).toEqual([])
    })

    it('a role whose permissions column holds a wildcard-granting non-array is dropped', async () => {
      await reset()
      // The shape a hand-written migration produces: an object instead of the
      // array of permissions. Nothing may read this as "grants everything".
      await pool.query(
        `INSERT INTO iam_roles (id, name, permissions) VALUES ('r1','Broken','{"action":"*","resource":"*"}'::jsonb)`,
      )
      expect(await adapter.getRole('r1')).toBeNull()
    })

    it('subject attributes that are a JSON array throw rather than reading as empty', async () => {
      await reset()
      await pool.query(`INSERT INTO iam_subject_attrs (subject_id, data) VALUES ('u1','[1,2]'::jsonb)`)
      await expect(adapter.getSubjectAttributes('u1')).rejects.toThrow(/corrupted attributes/)
    })

    it('subject attributes that are JSON null throw rather than reading as empty', async () => {
      await reset()
      await pool.query(`INSERT INTO iam_subject_attrs (subject_id, data) VALUES ('u1','null'::jsonb)`)
      // SECURITY: `{}` here would retire every deny rule that tests an attribute.
      await expect(adapter.getSubjectAttributes('u1')).rejects.toThrow(/corrupted attributes/)
    })

    it('a stored __proto__ attribute key makes the row unreadable rather than half-read', async () => {
      await reset()
      await pool.query(
        `INSERT INTO iam_subject_attrs (subject_id, data) VALUES ('u1','{"__proto__":{"tier":"gold"},"team":"A"}'::jsonb)`,
      )
      // SECURITY: assigning the key sets the prototype, and owning it hides the value a deny rule tests,
      // so the bag is refused and the operator gets a row to repair.
      await expect(adapter.getSubjectAttributes('u1')).rejects.toThrow(/corrupted attributes/)
    })

    it('a __proto__ attribute written through the adapter is refused at the write', async () => {
      await reset()
      // An own `__proto__` property, as `JSON.parse` produces; `defineProperty` keeps the fixture typed,
      // where plain assignment would set the prototype instead.
      const hostile: IamPrimitives.Attributes = { team: 'A' }
      Object.defineProperty(hostile, '__proto__', {
        configurable: true,
        enumerable: true,
        value: { tier: 'gold' },
        writable: true,
      })
      // Refused at the write, while the caller still has the request in hand.
      await expect(adapter.setSubjectAttributes('u1', hostile)).rejects.toThrow(/must not contain a __proto__ key/)
      expect(await adapter.getSubjectAttributes('u1')).toEqual({})
    })
  })

  describe('a malformed attributes row reaching a real decision', () => {
    /** Deny-overrides catalog: staff may read posts unless `subject.attributes.clearance` is `low`. */
    async function seedCatalog(a: Adapter): Promise<IamEngine<string, string, string, string>> {
      await a.saveRole({ id: 'staff', name: 'Staff', permissions: [{ action: 'read', resource: 'post' }] })
      await a.savePolicy({
        algorithm: 'deny-overrides',
        id: 'p-clearance',
        name: 'Clearance',
        rules: [
          {
            actions: ['read'],
            conditions: { all: [{ field: 'subject.attributes.clearance', operator: 'eq', value: 'low' }] },
            effect: 'deny',
            id: 'deny-low',
            priority: 100,
            resources: ['post'],
          },
          {
            actions: ['read'],
            conditions: { all: [] },
            effect: 'allow',
            id: 'allow-all',
            priority: 1,
            resources: ['post'],
          },
        ],
      })
      return new IamEngine<string, string, string, string>({ adapter: a })
    }

    it('the deny rule fires for an intact clearance row', async () => {
      await reset()
      const engine = await seedCatalog(adapter)
      await adapter.assignRole('u1', 'staff')
      await adapter.setSubjectAttributes('u1', { clearance: 'low' })
      expect(await engine.can('u1', 'read', { attributes: {}, type: 'post' })).toBe(false)
    })

    it('a data column holding JSON null must not retire that deny rule', async () => {
      await reset()
      const engine = await seedCatalog(adapter)
      await adapter.assignRole('u1', 'staff')
      // `data` is NOT NULL, but `'null'::jsonb` is a non-NULL value an import or hand migration can produce.
      await pool.query(`INSERT INTO iam_subject_attrs (subject_id, data) VALUES ('u1','null'::jsonb)`)
      // SECURITY: a corrupt row must deny or throw, never grant.
      expect(await engine.can('u1', 'read', { attributes: {}, type: 'post' })).toBe(false)
    })

    it('a data column holding a JSON array denies rather than granting', async () => {
      await reset()
      const engine = await seedCatalog(adapter)
      await adapter.assignRole('u1', 'staff')
      await pool.query(`INSERT INTO iam_subject_attrs (subject_id, data) VALUES ('u1','["clearance"]'::jsonb)`)
      expect(await engine.can('u1', 'read', { attributes: {}, type: 'post' })).toBe(false)
    })

    it('a clearance hidden behind a stored __proto__ key still denies', async () => {
      await reset()
      const engine = await seedCatalog(adapter)
      await adapter.assignRole('u1', 'staff')
      await pool.query(
        `INSERT INTO iam_subject_attrs (subject_id, data) VALUES ('u1','{"__proto__":{"clearance":"low"}}'::jsonb)`,
      )
      // The attribute IS in the row. Reading it into a bag that inherits rather
      // than owns it makes the deny rule miss.
      expect(await engine.can('u1', 'read', { attributes: {}, type: 'post' })).toBe(false)
    })
  })

  describe('round-trip fidelity through real column types', () => {
    it('a policy keeps its scalar types and gains no columns', async () => {
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
      expect(got).not.toBeNull()
      expect(Object.keys(got ?? {}).sort()).toEqual([
        'algorithm',
        'description',
        'id',
        'name',
        'rules',
        'targets',
        'version',
      ])
      // `version` is an int4; a driver that stringified it would flip
      // `version > 1` comparisons everywhere downstream.
      expect(typeof got?.version).toBe('number')
      expect(got?.version).toBe(7)
      expect(typeof got?.rules[0]?.priority).toBe('number')
      expect(got?.rules[0]?.priority).toBe(10)
    })

    it('a role keeps inherits/metadata types and never leaks created_at', async () => {
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
      expect(typeof (got?.metadata as Record<string, unknown>)?.level).toBe('number')
      expect(Object.keys(got ?? {})).not.toContain('createdAt')
      expect(Object.keys(got ?? {})).not.toContain('created_at')
    })

    it('a role reads back with the same key set on Postgres as on memory', async () => {
      await reset()
      const role = { id: 'r1', name: 'R', permissions: [] }
      await adapter.saveRole(role)
      const mem = new IamMemoryAdapter<string, string, string, string>()
      await mem.saveRole(role)

      const fromPg = await adapter.getRole('r1')
      const fromMemory = await mem.getRole('r1')
      // A key holding `undefined` still counts in `Object.keys`, so both backends must return the same key set.
      expect(Object.keys(fromPg ?? {}).sort()).toEqual(Object.keys(fromMemory ?? {}).sort())
    })
  })

  describe('ids the fake never sees', () => {
    const HOSTILE: [string, string][] = [
      ['a colon (the permission-key separator)', 'a:b'],
      ['an at sign', 'a@b'],
      ['a slash', 'a/b'],
      ['a newline', 'a\nb'],
      ['unicode', 'ロール-✓'],
      ['an emoji', 'role-🚀'],
      ['a NUL byte', 'a\\u0000b'],
      ['four thousand characters', `r-${'x'.repeat(4000)}`],
    ]

    it.each(HOSTILE)('either round-trips or refuses a role id containing %s', async (_label, id) => {
      await reset()
      const refusal = await adapter.saveRole({ id, name: `n-${id}`, permissions: [] }).then(
        () => null,
        (err: unknown) => String(err),
      )
      if (refusal !== null) {
        expect(await adapter.getRole(id).catch(() => null)).toBeNull()
        return
      }
      expect((await adapter.getRole(id))?.id).toBe(id)
      await adapter.assignRole('u1', id)
      expect(await adapter.getSubjectRoles('u1')).toEqual([id])
      await adapter.revokeRole('u1', id)
      expect(await adapter.getSubjectRoles('u1')).toEqual([])
    })

    it('a role id of __proto__ is listed by listRoles, not only by getRole', async () => {
      await reset()
      await adapter.saveRole({ id: '__proto__', name: 'P', permissions: [] })
      expect((await adapter.getRole('__proto__'))?.id).toBe('__proto__')
      expect((await adapter.listRoles()).map((r) => r.id)).toEqual(['__proto__'])
    })
  })

  describe('two connections at once', () => {
    it('twenty concurrent identical unscoped grants leave exactly one row', async () => {
      await reset()
      await seedRole('editor')
      const second = makePool(STRICT_URL as string)
      try {
        const a = makeAdapter(pool)
        const b = makeAdapter(second)
        await Promise.all(Array.from({ length: 20 }, (_, i) => (i % 2 === 0 ? a : b).assignRole('u1', 'editor')))
        const rows = await pool.query('SELECT count(*)::int AS n FROM iam_assignments')
        expect((rows.rows[0] as { n: number }).n).toBe(1)
        expect(await a.getSubjectRoles('u1')).toEqual(['editor'])
      } finally {
        await second.end()
      }
    }, 30_000)

    it('a grant racing a revoke leaves the store and both read paths agreeing', async () => {
      await reset()
      await seedRole('editor')
      const second = makePool(STRICT_URL as string)
      try {
        const a = makeAdapter(pool)
        const b = makeAdapter(second)
        for (let i = 0; i < 10; i++) {
          await a.assignRole('u1', 'editor')
          await Promise.all([b.revokeRole('u1', 'editor'), a.assignRole('u1', 'editor')])
          const rows = await pool.query('SELECT count(*)::int AS n FROM iam_assignments')
          const n = (rows.rows[0] as { n: number }).n
          expect(await a.getSubjectRoles('u1')).toEqual(n === 0 ? [] : ['editor'])
          await a.revokeRole('u1', 'editor')
        }
      } finally {
        await second.end()
      }
    }, 30_000)

    it('concurrent setSubjectAttributes from two connections does not lose the row', async () => {
      await reset()
      const second = makePool(STRICT_URL as string)
      try {
        const a = makeAdapter(pool)
        const b = makeAdapter(second)
        const results = await Promise.allSettled([
          a.setSubjectAttributes('u1', { team: 'A' }),
          b.setSubjectAttributes('u1', { plan: 'pro' }),
        ])
        // A lost update is acceptable (read-modify-write with no lock); both
        // writers failing and leaving NO row is not.
        const rejected = results.filter((r) => r.status === 'rejected')
        const attrs = await a.getSubjectAttributes('u1')
        expect(
          Object.keys(attrs).length,
          `both writers failed: ${rejected.map((r) => String((r as PromiseRejectedResult).reason)).join('; ')}`,
        ).toBeGreaterThan(0)
      } finally {
        await second.end()
      }
    }, 30_000)
  })

  describe('updateAssignmentScope against a real unique index', () => {
    it('moving an unscoped grant onto an already-granted scope collapses to one row', async () => {
      await reset()
      await seedRole('editor')
      await adapter.assignRole('u1', 'editor')
      await adapter.assignRole('u1', 'editor', 'org-1')
      expect(await adapter.updateAssignmentScope('u1', 'editor', undefined, 'org-1')).toBe(true)
      expect(await adapter.getSubjectRoles('u1')).toEqual([])
      expect(await adapter.getSubjectScopedRoles('u1')).toEqual([{ role: 'editor', scope: 'org-1' }])
    })

    it('moving a scoped grant to global is visible on the global read', async () => {
      await reset()
      await seedRole('editor')
      await adapter.assignRole('u1', 'editor', 'org-1')
      expect(await adapter.updateAssignmentScope('u1', 'editor', 'org-1', undefined)).toBe(true)
      expect(await adapter.getSubjectRoles('u1')).toEqual(['editor'])
      expect(await adapter.getSubjectScopedRoles('u1')).toEqual([])
    })

    it('returns false when the source row is not there', async () => {
      await reset()
      await seedRole('editor')
      expect(await adapter.updateAssignmentScope('u1', 'editor', 'org-9', 'org-1')).toBe(false)
    })
  })

  // Grant windows from a real `timestamptz` to a cached decision; drizzle is the only adapter that stores them.
  // NOTE: real clock, no fake timers - the driver and the server keep their own time.
  describe('time-boxed grants end to end', () => {
    const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))

    async function seedReader(): Promise<void> {
      await adapter.saveRole({ id: 'reader', name: 'Reader', permissions: [{ action: 'read', resource: 'post' }] })
      await adapter.saveRole({ id: 'writer', name: 'Writer', permissions: [{ action: 'write', resource: 'post' }] })
    }

    const POST = { attributes: {}, type: 'post' } as const

    it('reads a millisecond-precise expiry back off the wire unchanged', async () => {
      await reset()
      await seedReader()
      // `.123` checks millisecond precision survives: `timestamptz` keeps microseconds, JS keeps milliseconds.
      const expiresAt = new Date(Date.now() + 3_600_000 + 123)
      await adapter.assignRole('u1', 'reader', undefined, { expiresAt })
      expect(await adapter.getSubjectGrantBoundary('u1')).toBe(expiresAt.getTime())
    })

    it('reads a bound written in a non-UTC offset as the instant it names', async () => {
      await reset()
      await seedReader()
      // The literal carries +09; the boundary is an instant, not a wall clock,
      // so the answer must be the same number a UTC literal would produce.
      await pool.query(
        `INSERT INTO iam_assignments (id, subject_id, role_id, expires_at)
         VALUES ('a1','u1','reader','2099-03-01 12:00:00+09')`,
      )
      expect(await adapter.getSubjectGrantBoundary('u1')).toBe(Date.UTC(2099, 2, 1, 3, 0, 0))
    })

    it('does not report `infinity` as a boundary - nothing happens at it', async () => {
      await reset()
      await seedReader()
      await pool.query(
        `INSERT INTO iam_assignments (id, subject_id, role_id, expires_at) VALUES ('a1','u1','reader','infinity')`,
      )
      expect(await adapter.getSubjectRoles('u1')).toEqual(['reader'])
      expect(await adapter.getSubjectGrantBoundary('u1')).toBeNull()
    })

    it('does not report a bound the server has already passed', async () => {
      await reset()
      await seedReader()
      await adapter.assignRole('u1', 'reader', undefined, {
        expiresAt: new Date(Date.now() - 1_000),
        startsAt: new Date(Date.now() - 3_600_000),
      })
      expect(await adapter.getSubjectRoles('u1')).toEqual([])
      expect(await adapter.getSubjectGrantBoundary('u1')).toBeNull()
    })

    it('takes the earliest bound across global and scoped grants alike', async () => {
      await reset()
      await seedReader()
      const soon = new Date(Date.now() + 120_000)
      const later = new Date(Date.now() + 3_600_000)
      await adapter.assignRole('u1', 'reader', undefined, { expiresAt: later })
      await adapter.assignRole('u1', 'writer', 'org-1', { expiresAt: soon })
      await adapter.assignRole('u1', 'writer', 'org-2', { startsAt: later })
      expect(await adapter.getSubjectGrantBoundary('u1')).toBe(soon.getTime())
    })

    it('stops granting when the row expires, not a cacheTTL later', async () => {
      await reset()
      await seedReader()
      // A 60s cache over a grant with ~1s to live: the grant boundary must cut the cached allow short.
      const engine = new IamEngine<string, string, string, string>({ adapter, cacheTTL: 60 })
      await adapter.assignRole('u1', 'reader', undefined, { expiresAt: new Date(Date.now() + 1_200) })

      expect(await engine.can('u1', 'read', POST)).toBe(true)
      expect(await engine.can('u1', 'read', POST)).toBe(true) // served from cache
      await sleep(1_600)
      expect(await engine.can('u1', 'read', POST)).toBe(false)
      // and the store agrees, so the deny is the row's, not a cleared cache's
      expect(await adapter.getSubjectRoles('u1')).toEqual([])
    }, 30_000)

    it('starts granting when the row opens, not a cacheTTL later', async () => {
      await reset()
      await seedReader()
      const engine = new IamEngine<string, string, string, string>({ adapter, cacheTTL: 60 })
      await adapter.assignRole('u1', 'reader', undefined, { startsAt: new Date(Date.now() + 1_200) })

      expect(await engine.can('u1', 'read', POST)).toBe(false)
      await sleep(1_600)
      expect(await engine.can('u1', 'read', POST)).toBe(true)
    }, 30_000)

    it('drops only the window that closed and keeps the one still open', async () => {
      await reset()
      await seedReader()
      const engine = new IamEngine<string, string, string, string>({ adapter, cacheTTL: 60 })
      await adapter.assignRole('u1', 'writer', undefined, { expiresAt: new Date(Date.now() + 1_200) })
      await adapter.assignRole('u1', 'reader', undefined, { expiresAt: new Date(Date.now() + 3_600_000) })

      expect(await engine.can('u1', 'write', POST)).toBe(true)
      expect(await engine.can('u1', 'read', POST)).toBe(true)
      await sleep(1_600)
      expect(await engine.can('u1', 'write', POST)).toBe(false)
      expect(await engine.can('u1', 'read', POST)).toBe(true)
    }, 30_000)

    it('refuses an empty window in the adapter, before the driver sees it', async () => {
      await reset()
      await seedReader()
      // The adapter's own message, not drizzle's wrapped CHECK violation, which does not exist
      // when the caller brings their own table.
      await expect(
        adapter.assignRole('u1', 'reader', undefined, {
          expiresAt: new Date(Date.now()),
          startsAt: new Date(Date.now() + 60_000),
        }),
      ).rejects.toThrow(/startsAt >= expiresAt/)
      const rows = await pool.query('SELECT count(*)::int AS n FROM iam_assignments')
      expect((rows.rows[0] as { n: number }).n).toBe(0)
    })

    it('and the shipped schema refuses it too, for the row the adapter never sends', async () => {
      await reset()
      await seedReader()
      expect(
        await failureChain(() =>
          pool.query(
            `INSERT INTO iam_assignments (id, subject_id, role_id, starts_at, expires_at)
             VALUES ('a1','u1','reader', now() + interval '1 hour', now())`,
          ),
        ),
      ).toMatch(/ch_iam_assignments_starts_before_expires/)
    })

    it('an unbounded grant is not re-read on every call', async () => {
      await reset()
      await seedReader()
      const engine = new IamEngine<string, string, string, string>({ adapter, cacheTTL: 60 })
      await adapter.assignRole('u1', 'reader')
      expect(await engine.can('u1', 'read', POST)).toBe(true)

      // No boundary keeps the full TTL: the allow surviving a revoke made behind the engine's back
      // proves the entry was cached, not shortened.
      await adapter.revokeRole('u1', 'reader')
      expect(await engine.can('u1', 'read', POST)).toBe(true)
      expect(await adapter.getSubjectRoles('u1')).toEqual([])
    }, 30_000)
  })

  // Seeded random grant windows, decided by the SQL filter and by a plain-JS reference model; any disagreement fails.
  // The seed is fixed, so a failure names a reproducible row set.
  describe('randomised window matrix against the real filter', () => {
    /** Deterministic PRNG - a failing run must be replayable from the seed. */
    function mulberry32(seed: number): () => number {
      let a = seed >>> 0
      return () => {
        a = (a + 0x6d2b79f5) >>> 0
        let t = Math.imul(a ^ (a >>> 15), 1 | a)
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296
      }
    }

    /**
     * A bound as the SQL literal Postgres stores and the number the reference model compares.
     * `at: null` is an absent bound; the infinities are modelled as limits, not instants.
     */
    interface IBound {
      readonly sql: string
      readonly at: number | null
      readonly label: string
    }

    const NO_BOUND: IBound = { at: null, label: 'NULL', sql: 'NULL' }

    function boundAt(offsetMs: number, now: number): IBound {
      const at = now + offsetMs
      return { at, label: `${offsetMs}ms`, sql: `'${new Date(at).toISOString()}'::timestamptz` }
    }

    const POS_INF: IBound = { at: Number.POSITIVE_INFINITY, label: 'infinity', sql: `'infinity'::timestamptz` }
    const NEG_INF: IBound = { at: Number.NEGATIVE_INFINITY, label: '-infinity', sql: `'-infinity'::timestamptz` }

    interface IGrant {
      readonly subject: string
      readonly role: string
      readonly scope: string | null
      readonly startsAt: IBound
      readonly expiresAt: IBound
    }

    /** The documented rule, restated: `[startsAt, expiresAt)` at `at`. */
    function isLive(g: IGrant, at: number): boolean {
      if (g.startsAt.at !== null && at < g.startsAt.at) return false
      if (g.expiresAt.at !== null && at >= g.expiresAt.at) return false
      return true
    }

    /** The next instant `isLive` could change for this subject, or null. */
    function nextBoundary(grants: IGrant[], at: number): number | null {
      let next: number | null = null
      for (const g of grants) {
        for (const b of [g.startsAt.at, g.expiresAt.at]) {
          if (b === null || !Number.isFinite(b) || b <= at) continue
          if (next === null || b < next) next = b
        }
      }
      return next
    }

    const SEED = 0x5eed_1a11
    const SCOPES: (string | null)[] = [null, 'org-1', 'org-2']
    const ROLES = ['r0', 'r1', 'r2', 'r3']
    const SUBJECTS = 24

    it('agrees with the reference model on every generated grant', async () => {
      await reset()
      for (const r of ROLES) await seedRole(r, `Role ${r}`)

      const rand = mulberry32(SEED)
      // Offsets are at least a minute from now, so clock movement between INSERT and SELECT cannot flip a row.
      const OFFSETS = [-7_200_000, -3_600_000, -600_000, -60_000, 60_000, 600_000, 3_600_000, 7_200_000]
      const pickBound = (): IBound => {
        const roll = rand()
        if (roll < 0.3) return NO_BOUND
        if (roll < 0.36) return POS_INF
        if (roll < 0.42) return NEG_INF
        const offset = OFFSETS[Math.floor(rand() * OFFSETS.length)]
        if (offset === undefined) throw new Error('offset table exhausted')
        return boundAt(offset, Date.now())
      }

      /** Redraws until `startsAt < expiresAt`, since empty windows are refused and tested separately. */
      const pickWindow = (): { startsAt: IBound; expiresAt: IBound } => {
        for (let attempt = 0; attempt < 50; attempt++) {
          const startsAt = pickBound()
          const expiresAt = pickBound()
          if (startsAt.at === null || expiresAt.at === null) return { expiresAt, startsAt }
          if (startsAt.at < expiresAt.at) return { expiresAt, startsAt }
        }
        return { expiresAt: NO_BOUND, startsAt: NO_BOUND }
      }

      const grants: IGrant[] = []
      const seen = new Set<string>()
      for (let s = 0; s < SUBJECTS; s++) {
        const subject = `u${s}`
        for (const role of ROLES) {
          for (const scope of SCOPES) {
            if (rand() < 0.45) continue
            const key = `${subject}|${role}|${scope}`
            if (seen.has(key)) continue
            seen.add(key)
            grants.push({ ...pickWindow(), role, scope, subject })
          }
        }
      }
      expect(grants.length, 'the generator produced nothing to test').toBeGreaterThan(60)

      const values = grants
        .map(
          (g, i) =>
            `('g${i}', '${g.subject}', '${g.role}', ${g.scope === null ? 'NULL' : `'${g.scope}'`}, ${g.startsAt.sql}, ${g.expiresAt.sql})`,
        )
        .join(',\n')
      await pool.query(
        `INSERT INTO iam_assignments (id, subject_id, role_id, scope, starts_at, expires_at) VALUES\n${values}`,
      )

      // One instant for both sides, so a disagreement is the filter's, not the clock's.
      const at = Date.now()
      const describeGrant = (g: IGrant) =>
        `${g.subject}/${g.role}/${g.scope ?? 'global'} [${g.startsAt.label}, ${g.expiresAt.label})`

      for (let s = 0; s < SUBJECTS; s++) {
        const subject = `u${s}`
        const mine = grants.filter((g) => g.subject === subject)
        const detail = `seed ${SEED}, subject ${subject}:\n${mine.map(describeGrant).join('\n')}`

        const expectedGlobal = [
          ...new Set(mine.filter((g) => g.scope === null && isLive(g, at)).map((g) => g.role)),
        ].sort()
        expect([...(await adapter.getSubjectRoles(subject))].sort(), detail).toEqual(expectedGlobal)

        const expectedScoped = mine
          .filter((g) => g.scope !== null && isLive(g, at))
          .map((g) => ({ role: g.role, scope: g.scope }))
          .sort((a, b) => `${a.role}${a.scope}`.localeCompare(`${b.role}${b.scope}`))
        const actualScoped = (await adapter.getSubjectScopedRoles(subject))
          .map((r) => ({ role: r.role, scope: r.scope }))
          .sort((a, b) => `${a.role}${a.scope}`.localeCompare(`${b.role}${b.scope}`))
        expect(actualScoped, detail).toEqual(expectedScoped)

        expect(await adapter.getSubjectGrantBoundary(subject), detail).toBe(nextBoundary(mine, at))
      }
    }, 60_000)

    it('the reference model itself is not vacuous', async () => {
      // Guard against a vacuous pass above: the generator must yield live and dead rows, bounded and unbounded.
      const rand = mulberry32(SEED)
      const now = Date.now()
      const sample: IGrant[] = []
      for (let i = 0; i < 400; i++) {
        const roll = () => {
          const r = rand()
          if (r < 0.3) return NO_BOUND
          if (r < 0.36) return POS_INF
          if (r < 0.42) return NEG_INF
          return boundAt(r < 0.7 ? -600_000 : 600_000, now)
        }
        sample.push({ expiresAt: roll(), role: 'r0', scope: null, startsAt: roll(), subject: `u${i}` })
      }
      expect(sample.some((g) => isLive(g, now))).toBe(true)
      expect(sample.some((g) => !isLive(g, now))).toBe(true)
      expect(sample.some((g) => nextBoundary([g], now) !== null)).toBe(true)
      expect(sample.some((g) => nextBoundary([g], now) === null)).toBe(true)
    })
  })
})
