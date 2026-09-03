/**
 * Shared setup for duck-iam end-to-end tests that run against REAL Postgres.
 *
 * Config comes from `.env.test` or from the containers `e2e-containers.ts`
 * provisions. When the URL is unset the matching suite skips itself, so
 * `bun run test` stays green with no database around.
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

let loaded = false

/** Load `.env.test` into `process.env` without adding a dotenv dependency. */
function loadEnvTest(): void {
  if (loaded) return
  loaded = true
  try {
    const raw = readFileSync(join(process.cwd(), '.env.test'), 'utf8')
    for (const line of raw.split('\n')) {
      const trimmed = line.trim()
      if (trimmed.length === 0 || trimmed.startsWith('#')) continue
      const eq = trimmed.indexOf('=')
      if (eq < 0) continue
      const key = trimmed.slice(0, eq).trim()
      if (process.env[key] === undefined) process.env[key] = trimmed.slice(eq + 1).trim()
    }
  } catch {
    // No .env.test - suites skip themselves via the getter below.
  }
}

export function databaseUrl(): string | undefined {
  loadEnvTest()
  return process.env.DUCKIAM_E2E_DATABASE_URL
}

/**
 * Create the shipped Postgres schema in the e2e database, so a suite provisions
 * its own tables instead of depending on one created by hand.
 *
 * The DDL mirrors `adapters/drizzle/pg/pg.schema.ts`; update
 * `src/test/pg-e2e-schema.sql` when that schema changes.
 */
export async function applyPgSchema(pool: { query(sql: string): Promise<{ rows: unknown[] }> }): Promise<void> {
  const probe = await pool.query(`SELECT to_regclass('public.iam_assignments') AS present`)
  const row = probe.rows[0] as { present: string | null } | undefined
  if (row?.present) return
  await pool.query(readFileSync(join(import.meta.dirname, 'pg-e2e-schema.sql'), 'utf8'))
}

/**
 * Create a dedicated database and return its URL.
 *
 * Suites that wipe tables between cases cannot share one database: vitest runs
 * files in parallel workers, so one suite's TRUNCATE lands in the middle of
 * another's fixtures. An owned database makes the isolation real rather than a
 * scheduling accident.
 *
 * `undefined` means "no e2e database": the caller turns that into
 * `describe.skip`. An unreachable server counts, and this is the one place that
 * distinction has to be made, because callers await this at module scope - a
 * throw here fails the file instead of skipping it, which is what stopped
 * Stryker's dry run (and therefore every mutation run) in a checkout with no
 * Postgres. The reason is printed rather than swallowed.
 */
export async function isolatedDatabaseUrl(name: string): Promise<string | undefined> {
  const base = databaseUrl()
  if (!base) return undefined
  const url = new URL(base)
  const dbName = `duckiam_e2e_${name}`.toLowerCase().replace(/[^a-z0-9_]/g, '_')
  const { Pool } = (await import('pg')) as typeof import('pg')
  const admin = new Pool({ connectionString: base })
  try {
    // CREATE DATABASE cannot run in a transaction and has no IF NOT EXISTS, so
    // drop first and let the "does not exist" pass on a clean run.
    await admin.query(`DROP DATABASE IF EXISTS ${dbName}`)
    await admin.query(`CREATE DATABASE ${dbName}`)
  } catch (err) {
    console.warn(`[@gentleduck/iam:test] e2e database unreachable, skipping "${name}": ${String(err)}`)
    return undefined
  } finally {
    await admin.end()
  }
  url.pathname = `/${dbName}`
  return url.toString()
}

/**
 * Fail a suite that is about to skip for a reason that is not a real one.
 *
 * Every e2e file gates itself on `URL ? describe : describe.skip`, which is
 * deliberate: Stryker's dry run and a fresh checkout with no docker both have
 * to get through the suite without a database. The cost is that a skip and a
 * *broken provisioner* look identical from the outside - and that is not
 * hypothetical. A container that failed to boot once took 51 compliance cases
 * out of a run, silently, and the only reason it was noticed at all was that a
 * generated inventory's numbers moved.
 *
 * So the rule is: if docker is up, having no backend is a failure, not a skip.
 * `e2e-adapter-drizzle-pg` has always asserted this for itself; this is that
 * guard, shared, so no suite can go quiet without saying so.
 *
 * Call it at module scope next to the `const suite = …` line. It registers its
 * own `describe`, so it runs even when the suite it guards is skipped - which
 * is the entire point.
 */
export function assertE2eReachable(suiteName: string, backend: string | number | undefined): void {
  describe(`E2E reachability (${suiteName})`, () => {
    it('has its backend whenever docker is available', async () => {
      if (!(await dockerIsUp())) {
        expect(backend, 'docker is down, so no e2e backend is expected here').toBeUndefined()
        return
      }
      expect(
        backend,
        `docker is up but "${suiteName}" has no backend, so the suite skipped instead of running. ` +
          'That is a provisioning failure, not a reason to be quiet.',
      ).toBeDefined()
    })
  })
}

/**
 * Is the docker daemon answering?
 *
 * Generous timeout on purpose: a five-second probe is fine on an idle machine
 * and wrong on one already running e2e containers, where the daemon is busy
 * enough to take longer - and reading "busy" as "absent" is what turns this
 * guard back into the silent skip it exists to prevent.
 */
async function dockerIsUp(): Promise<boolean> {
  const { execFile } = await import('node:child_process')
  const { promisify } = await import('node:util')
  try {
    await promisify(execFile)('docker', ['info', '--format', '{{.ServerVersion}}'], { timeout: 30_000 })
    return true
  } catch {
    return false
  }
}
