/** Shared setup for the end-to-end tests, which run against real infrastructure: `FakeRedis` and in-memory
 *  sqlite are necessary and not sufficient, and no in-process test can verify pub/sub fan-out between instances
 *  at all. Config comes from `.env.test`; an unset URL reads as `''`, which skips the matching suite. */
import { readFileSync } from 'node:fs'
import { createServer, type IncomingMessage } from 'node:http'
import { join } from 'node:path'
import { randomToken } from '~/core/crypto'
import { AuthError } from '~/core/errors'

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

export function redisUrl(): string {
  loadEnvTest()
  return process.env.DUCKAUTH_E2E_REDIS_URL ?? ''
}

export function databaseUrl(): string {
  loadEnvTest()
  return process.env.DUCKAUTH_E2E_DATABASE_URL ?? ''
}

export function mysqlUrl(): string {
  loadEnvTest()
  return process.env.DUCKAUTH_E2E_MYSQL_URL ?? ''
}

export function instanceCount(): number {
  loadEnvTest()
  const raw = process.env.DUCKAUTH_E2E_INSTANCES
  const n = raw !== undefined ? Number.parseInt(raw, 10) : 2
  return Number.isFinite(n) && n > 0 ? n : 2
}

/** A key namespace per run, dropped in teardown, so pointing at a shared dev Redis collides with nothing and
 *  leaves no debris. */
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

/** Create the shipped Postgres schema, so the suite provisions its own tables. The DDL is generated from
 *  `adapters/drizzle/pg/pg.schema.ts`; regenerate with `bun run e2e:schema` when that changes. */
export async function applyPgSchema(pool: { query(sql: string): Promise<{ rows: unknown[] }> }): Promise<void> {
  const probe = await pool.query(`SELECT to_regclass('public.auth_identities') AS present`)
  const row = probe.rows[0] as { present: string | null } | undefined
  if (row?.present) return
  await pool.query(readFileSync(join(import.meta.dirname, 'pg-e2e-schema.sql'), 'utf8'))
}

/** Create a dedicated database and answer its URL. A suite that wipes tables between cases cannot share the
 *  default one, vitest running files in parallel workers, so one TRUNCATE lands mid-fixture in another. */
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

/** Serve `handle` on a loopback port: its answer goes back as JSON, an `AuthError` as its own status and code,
 *  anything else as a 500. `listen` runs in the caller's async scope, and every request handler inherits it. */
export async function serve(
  handle: (req: IncomingMessage, headers: Headers) => Promise<unknown>,
): Promise<{ origin: string; close: () => Promise<void> }> {
  const server = createServer((req, res) => {
    const headers = new Headers()
    for (const [name, value] of Object.entries(req.headers)) if (typeof value === 'string') headers.set(name, value)
    const reply = (status: number, body: unknown) =>
      res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(body ?? null))
    handle(req, headers).then(
      (body) => reply(200, body),
      (err: unknown) =>
        err instanceof AuthError ? reply(err.status, { code: err.code }) : reply(500, { error: String(err) }),
    )
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  if (address === null || typeof address === 'string') throw new Error('the server is not on a port')
  return {
    close: () => {
      server.closeAllConnections()
      return new Promise((resolve) => server.close(() => resolve()))
    },
    origin: `http://127.0.0.1:${address.port}`,
  }
}
