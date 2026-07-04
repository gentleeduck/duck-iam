/**
 * Store-contract compliance matrix for the Drizzle SQLite adapter.
 *
 * Runs the shared `run*StoreCompliance` suites against a live in-memory
 * SQLite DB, proving the drizzle bridge + `createSqlStores` behave identically
 * to every other adapter (memory, redis, ...).
 *
 * Uses bun:sqlite via drizzle-orm/bun-sqlite so no extra peer-dep needs to be
 * installed. Skipped under Node (vitest in CI); Bun's test runner executes it.
 * The DDL intentionally omits CHECK constraints so the suite exercises store
 * behaviour, not dialect-level column checks.
 */

import { beforeAll, describe } from 'vitest'
import {
  runCredentialStoreCompliance,
  runIdentityStoreCompliance,
  runSessionStoreCompliance,
} from '../../../__compliance__'
import { createSqlStores } from '../../../sql/sql'
import { createDrizzleSqliteBridge } from '../sqlite'

const IS_BUN = typeof (globalThis as { Bun?: unknown }).Bun !== 'undefined'
// describe.skip when not bun, so vitest under Node never resolves bun:sqlite.
const onlyBun = IS_BUN ? describe : describe.skip

const DDL = `
CREATE TABLE auth_identities (
  id TEXT PRIMARY KEY, tenant_id TEXT, profile TEXT NOT NULL,
  providers TEXT NOT NULL DEFAULT '[]', version INTEGER NOT NULL DEFAULT 1,
  email_verified INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL, deleted_at INTEGER);
CREATE TABLE auth_credentials (
  id TEXT PRIMARY KEY, identity_id TEXT NOT NULL, tenant_id TEXT, kind TEXT NOT NULL,
  secret TEXT NOT NULL, metadata TEXT, version INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL, last_used_at INTEGER, expires_at INTEGER, revoked_at INTEGER);
CREATE TABLE auth_sessions (
  id TEXT PRIMARY KEY, identity_id TEXT, tenant_id TEXT, kind TEXT NOT NULL, aal INTEGER NOT NULL,
  factors TEXT NOT NULL DEFAULT '[]', csrf_hash TEXT, ip TEXT, user_agent TEXT, fingerprint TEXT,
  created_at INTEGER NOT NULL, rotated_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  absolute_expires_at INTEGER NOT NULL, fresh INTEGER NOT NULL, acting_as TEXT);
`

onlyBun('DrizzleSqlite compliance matrix', () => {
  // Fresh in-memory DB (+ tables) per store instance the compliance kit requests.
  let make: () => ReturnType<typeof createSqlStores<{ username: string; email: string }>>

  beforeAll(async () => {
    const { Database } = (await import('bun:sqlite' as string)) as {
      Database: new (path: string) => { exec(sql: string): void }
    }
    const { drizzle } = await import('drizzle-orm/bun-sqlite')
    make = () => {
      const sqlite = new Database(':memory:')
      sqlite.exec(DDL)
      // biome-ignore lint/suspicious/noExplicitAny: bun:sqlite Database is structurally the drizzle client.
      return createSqlStores<{ username: string; email: string }>(createDrizzleSqliteBridge(drizzle(sqlite as any)))
    }
  })

  runIdentityStoreCompliance(() => make().identities)
  runSessionStoreCompliance(() => make().sessions)
  runCredentialStoreCompliance(() => make().credentials)
})
