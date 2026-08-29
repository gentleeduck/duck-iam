/**
 * Shared setup for end-to-end tests that run against REAL infrastructure.
 *
 * Everything the audit proved so far was in-process against `FakeRedis` and
 * in-memory sqlite. Those are necessary and not sufficient: `FakeRedis` has
 * known bugs and its own header disclaims review, and no in-process test can
 * verify pub/sub fan-out between instances at all.
 *
 * Config comes from `.env.test` (see `.env.example`). When a URL is unset the
 * matching suite skips, so `bun run test` stays green with no containers.
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { randomToken } from '~/core/crypto'

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
    // No .env.test — suites skip themselves via the getters below.
  }
}

export function redisUrl(): string | undefined {
  loadEnvTest()
  return process.env.DUCKAUTH_E2E_REDIS_URL
}

export function databaseUrl(): string | undefined {
  loadEnvTest()
  return process.env.DUCKAUTH_E2E_DATABASE_URL
}

export function mysqlUrl(): string | undefined {
  loadEnvTest()
  return process.env.DUCKAUTH_E2E_MYSQL_URL
}

export function instanceCount(): number {
  loadEnvTest()
  const raw = process.env.DUCKAUTH_E2E_INSTANCES
  const n = raw !== undefined ? Number.parseInt(raw, 10) : 2
  return Number.isFinite(n) && n > 0 ? n : 2
}

/**
 * Unique key namespace per test run. Every e2e Redis key sits under this and is
 * dropped in teardown, so pointing at a shared dev Redis cannot collide with
 * another run or leave debris behind.
 */
export function e2ePrefix(): string {
  return `e2e:${Date.now().toString(36)}:${randomToken(4)}`
}

/** Delete every key under a prefix. Call in `afterAll`. */
export async function dropPrefix(
  redis: { keys(pattern: string): Promise<string[]>; del(...keys: string[]): Promise<number> },
  prefix: string,
): Promise<void> {
  const keys = await redis.keys(`${prefix}*`)
  if (keys.length > 0) await redis.del(...keys)
}

/**
 * Create the shipped Postgres schema in the e2e database, so the suite provisions
 * its own tables instead of depending on one cloned by hand from another repo.
 * The DDL is generated from `adapters/drizzle/pg/pg.schema.ts`; regenerate it with
 * `bun run e2e:schema` when that schema changes.
 */
export async function applyPgSchema(pool: { query(sql: string): Promise<{ rows: unknown[] }> }): Promise<void> {
  const probe = await pool.query(`SELECT to_regclass('public.auth_identities') AS present`)
  const row = probe.rows[0] as { present: string | null } | undefined
  if (row?.present) return
  await pool.query(readFileSync(join(import.meta.dirname, 'pg-e2e-schema.sql'), 'utf8'))
}

/**
 * Create a dedicated database and return its URL.
 *
 * Suites that wipe tables between cases cannot share the default e2e database:
 * vitest runs files in parallel workers, so one suite's TRUNCATE lands in the
 * middle of another's fixtures. An owned database makes the isolation real
 * rather than a scheduling accident.
 */
export async function isolatedDatabaseUrl(name: string): Promise<string | undefined> {
  const base = databaseUrl()
  if (!base) return undefined
  const url = new URL(base)
  const dbName = `duckauth_e2e_${name}`.toLowerCase().replace(/[^a-z0-9_]/g, '_')
  const { Pool } = (await import('pg')) as typeof import('pg')
  const admin = new Pool({ connectionString: base })
  try {
    // CREATE DATABASE cannot run in a transaction and has no IF NOT EXISTS, so
    // drop first and ignore the "does not exist" on a clean run.
    await admin.query(`DROP DATABASE IF EXISTS ${dbName}`)
    await admin.query(`CREATE DATABASE ${dbName}`)
  } finally {
    await admin.end()
  }
  url.pathname = `/${dbName}`
  return url.toString()
}
