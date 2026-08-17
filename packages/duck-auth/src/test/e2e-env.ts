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
  return `e2e:${Date.now().toString(36)}:${Math.random().toString(36).slice(2, 8)}`
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
 * DDL for the e2e Postgres database. Mirrors the shipped drizzle pg schema but
 * types `identity_id` as `text` rather than `uuid`, because the shared
 * conformance suite uses readable ids (`'u'`, `'v'`) rather than UUIDs.
 *
 * Tests that must exercise the REAL column types use `PG_DDL_STRICT` instead.
 */
export const PG_DDL = `
DROP TABLE IF EXISTS auth_sessions_e2e;
CREATE TABLE auth_sessions_e2e (
  id                  text PRIMARY KEY,
  identity_id         text,
  tenant_id           text,
  kind                text NOT NULL,
  aal                 integer NOT NULL,
  factors             jsonb NOT NULL DEFAULT '[]'::jsonb,
  csrf_hash           text,
  ip                  text,
  user_agent          text,
  fingerprint         text,
  created_at          timestamptz NOT NULL,
  rotated_at          timestamptz NOT NULL,
  expires_at          timestamptz NOT NULL,
  absolute_expires_at timestamptz NOT NULL,
  fresh               boolean NOT NULL,
  acting_as           jsonb
);
CREATE INDEX auth_sessions_e2e_identity ON auth_sessions_e2e (identity_id);
CREATE INDEX auth_sessions_e2e_expires ON auth_sessions_e2e (expires_at);
`
