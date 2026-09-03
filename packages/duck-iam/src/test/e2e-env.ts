/**
 * Shared setup for duck-iam end-to-end tests that run against REAL Postgres.
 *
 * Config comes from `.env.test` or from the containers `e2e-containers.ts`
 * provisions. When the URL is unset the matching suite skips itself, so
 * `bun run test` stays green with no database around.
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

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
  } finally {
    await admin.end()
  }
  url.pathname = `/${dbName}`
  return url.toString()
}
