/**
 * Shared setup for e2e tests against real Postgres, configured by `.env.test` or `e2e-containers.ts`.
 * With no URL a suite skips itself.
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

/** The e2e Postgres URL, or `undefined` so the suite skips. Loads `.env.test` once; existing env vars win. */
export function databaseUrl(): string | undefined {
  loadEnvTest()
  return process.env.DUCKIAM_E2E_DATABASE_URL
}

/**
 * Creates the Postgres schema in the e2e database if it is missing.
 * WARN: `pg-e2e-schema.sql` mirrors `adapters/drizzle/pg/pg.schema.ts` by hand; update it when that schema changes.
 */
export async function applyPgSchema(pool: { query(sql: string): Promise<{ rows: unknown[] }> }): Promise<void> {
  const probe = await pool.query(`SELECT to_regclass('public.iam_assignments') AS present`)
  const row = probe.rows[0] as { present: string | null } | undefined
  if (row?.present) return
  await pool.query(readFileSync(join(import.meta.dirname, 'pg-e2e-schema.sql'), 'utf8'))
}

/**
 * Creates a dedicated database and returns its URL; test files run in parallel and would TRUNCATE each other's rows.
 * NOTE: an unreachable server returns `undefined` (skip); callers await at module scope, where a throw fails the file.
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
 * Registers a check that fails when a suite has no backend while docker is up, or at all in CI.
 * Call at module scope next to `const suite = ...`; it registers its own `describe`, so it runs when the suite skips.
 */
export function assertE2eReachable(suiteName: string, backend: string | number | undefined): void {
  describe(`E2E reachability (${suiteName})`, () => {
    // NOTE: explicit timeout above the 30s probe; vitest's 5s default would time out on a busy daemon.
    it(
      'has its backend whenever docker is available',
      async () => {
        // CI provisions docker before vitest, so a backend is required there without consulting the probe.
        if (process.env.CI) {
          expect(
            backend,
            `"${suiteName}" has no backend in CI, where the workflow provisions one. ` +
              'The suite skipped instead of running.',
          ).toBeDefined()
          return
        }
        if (!(await dockerIsUp())) {
          expect(backend, 'docker is down, so no e2e backend is expected here').toBeUndefined()
          return
        }
        expect(
          backend,
          `docker is up but "${suiteName}" has no backend, so the suite skipped instead of running. ` +
            'That is a provisioning failure, not a reason to be quiet.',
        ).toBeDefined()
      },
      60_000,
    )
  })
}

let dockerProbe: Promise<boolean> | undefined

/**
 * Whether the docker daemon answers; memoised per worker so the guard and the suite gate share one verdict.
 * WARN: keep the timeout generous; a busy daemon takes over 5s, and busy must not read as absent.
 */
export function dockerIsUp(): Promise<boolean> {
  dockerProbe ??= (async () => {
    const { execFile } = await import('node:child_process')
    const { promisify } = await import('node:util')
    try {
      await promisify(execFile)('docker', ['info', '--format', '{{.ServerVersion}}'], { timeout: 30_000 })
      return true
    } catch {
      return false
    }
  })()
  return dockerProbe
}
