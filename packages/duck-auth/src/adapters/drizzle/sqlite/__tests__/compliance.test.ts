/**
 * Store-contract compliance matrix for the Drizzle SQLite adapter.
 *
 * Runs the shared `run*StoreCompliance` suites against a live in-memory
 * SQLite DB, proving the drizzle bridge + `createSqlStores` behave identically
 * to every other adapter (memory, redis, ...).
 *
 * Uses bun:sqlite via drizzle-orm/bun-sqlite so no extra peer-dep needs to be
 * installed. Skipped under Node (vitest in CI); Bun's test runner executes it.
 *
 * The DDL is the declared schema, constraints and all. It used to be a
 * hand-written copy that omitted them deliberately - "exercise store behaviour,
 * not dialect-level column checks" - but the effect was that the suite ran
 * against a schema no deployment has: no foreign keys, no unique indexes, no
 * checks. Store behaviour that only holds without those is not store behaviour
 * that holds. pg and mysql have always run their matrices against the real
 * thing; this now matches.
 */

import { createHash } from 'node:crypto'
import { beforeAll, describe } from 'vitest'
import { createSqlStores } from '~/adapters/sql/sql'
import { SQLITE_DDL as DDL } from '~/test/sqlite-schema'
import {
  runCredentialStoreCompliance,
  runIdentityStoreCompliance,
  runSessionStoreCompliance,
} from '~/test/store-compliance'
import { createDrizzleSqliteBridge } from '../sqlite'

const IS_BUN = typeof (globalThis as { Bun?: unknown }).Bun !== 'undefined'

/** `chk_auth_sessions_id_length` demands exactly 64 chars, as every real sid is. */
const sessionId = (label: string) => createHash('sha256').update(label).digest('hex')

/** Sessions and credentials carry a foreign key to `auth_identities.id`. */
const OWNER = 'owner-identity'
const OTHER = 'other-identity'

/**
 * The two rows the session and credential foreign keys point at. The matrix
 * plants fixed owner ids and never creates the identities itself, so a schema
 * that actually enforces the FK needs them seeded into every fresh database.
 */
function seedOwners(exec: (sql: string) => void): void {
  for (const [id, name] of [
    [OWNER, 'owner'],
    [OTHER, 'other'],
  ]) {
    exec(
      `INSERT INTO auth_identities (id, profile, providers, version, email_verified, created_at, updated_at)
       VALUES ('${id}', '{"email":"${name}@fk.local","username":"${name}"}', '[]', 1, 1, 0, 0)`,
    )
  }
}
// describe.skip when not bun, so vitest under Node never resolves bun:sqlite.

describe('DrizzleSqlite compliance matrix', () => {
  // Fresh in-memory DB (+ tables) per store instance the compliance kit requests.
  let make: () => ReturnType<typeof createSqlStores<{ username: string; email: string }>>

  beforeAll(async () => {
    // Runs on BOTH runtimes: this suite used to be skipped under vitest, which
    // meant the SQL bridge (shared by pg + mysql + sqlite) was never verified by
    // the project's own `bun run test`.
    //   Bun  -> bun:sqlite     via drizzle-orm/bun-sqlite
    //   Node -> node:sqlite    via drizzle-orm/better-sqlite3 (same prepare/exec
    //           shape, so the driver adapter accepts it structurally)
    if (IS_BUN) {
      const { Database } = (await import('bun:sqlite' as string)) as {
        Database: new (path: string) => { exec(sql: string): void }
      }
      const { drizzle } = await import('drizzle-orm/bun-sqlite')
      make = () => {
        const sqlite = new Database(':memory:')
        sqlite.exec(DDL)
        seedOwners((q) => sqlite.exec(q))
        // biome-ignore lint/suspicious/noExplicitAny: bun:sqlite Database is structurally the drizzle client.
        return createSqlStores<{ username: string; email: string }>(createDrizzleSqliteBridge(drizzle(sqlite as any)))
      }
      return
    }

    const { default: Database } = await import('better-sqlite3')
    const { drizzle } = await import('drizzle-orm/better-sqlite3')
    make = () => {
      const sqlite = new Database(':memory:')
      sqlite.exec(DDL)
      seedOwners((q) => sqlite.exec(q))
      // biome-ignore lint/suspicious/noExplicitAny: better-sqlite3 Database is structurally the drizzle client.
      return createSqlStores<{ username: string; email: string }>(createDrizzleSqliteBridge(drizzle(sqlite as any)))
    }
  })

  runIdentityStoreCompliance(() => make().identities)
  runSessionStoreCompliance(() => make().sessions, { identityId: OWNER, otherIdentityId: OTHER, sessionId })
  runCredentialStoreCompliance(() => make().credentials, { identityId: OWNER })
})
