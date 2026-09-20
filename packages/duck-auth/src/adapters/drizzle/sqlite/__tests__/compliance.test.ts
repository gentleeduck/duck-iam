/** Store-contract compliance matrix for the Drizzle SQLite adapter. */

import { createHash } from 'node:crypto'
import { beforeAll, describe } from 'vitest'
import type { Adapter } from '~/adapters/adapter'
import { SQLITE_DDL as DDL } from '~/test/sqlite-schema'
import {
  runAdapterRebindCompliance,
  runCredentialStoreCompliance,
  runIdentityStoreCompliance,
  runSessionStoreCompliance,
} from '~/test/store-compliance'
import { DrizzleSqliteAdapter } from '../sqlite'

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
      `INSERT INTO auth_identities (id, profile, version, email_verified, created_at, updated_at)
       VALUES ('${id}', '{"email":"${name}@fk.local","username":"${name}"}', 1, 1, 0, 0)`,
    )
  }
}

describe('DrizzleSqlite compliance matrix', () => {
  // Fresh in-memory DB (+ tables) per store instance the compliance kit requests.
  let make: () => Adapter.Me<{ username: string; email: string }>
  // The handle `make` last built, so the rebind check has one `withClient` accepts.
  let handle: unknown

  beforeAll(async () => {
    // Runs on BOTH runtimes: this suite used to be skipped under vitest, which
    // meant the sqlite adapter was never verified by the project's own `bun run test`.
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
        const db = drizzle(sqlite as any)
        handle = db
        return new DrizzleSqliteAdapter(db)
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
      const db = drizzle(sqlite as any)
      handle = db
      return new DrizzleSqliteAdapter(db)
    }
  })

  runIdentityStoreCompliance(() => make().identities)
  runAdapterRebindCompliance(
    () => make(),
    () => handle,
  )
  runSessionStoreCompliance(() => make().sessions, { identityId: OWNER, otherIdentityId: OTHER, sessionId })
  runCredentialStoreCompliance(() => make().credentials, { identityId: OWNER })
})
