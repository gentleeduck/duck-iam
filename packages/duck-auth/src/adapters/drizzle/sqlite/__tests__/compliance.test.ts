/** Store-contract compliance matrix for the Drizzle SQLite adapter. */

import { createHash } from 'node:crypto'
import Database from 'better-sqlite3'
import { drizzle } from 'drizzle-orm/better-sqlite3'
import { describe } from 'vitest'
import type { Adapter } from '~/adapters/adapter'
import { SQLITE_DDL as DDL } from '~/test/sqlite-schema'
import {
  runAdapterRebindCompliance,
  runCredentialStoreCompliance,
  runIdentityStoreCompliance,
  runSessionStoreCompliance,
} from '~/test/store-compliance'
import { DrizzleSqliteAdapter } from '../sqlite'

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
  // The handle `make` last built, so the rebind check has one `withClient` accepts.
  let handle: unknown

  /** A fresh in-memory database, tables and owners included, per store the kit asks for. */
  const make = (): Adapter.Me<{ username: string; email: string }> => {
    const sqlite = new Database(':memory:')
    sqlite.exec(DDL)
    seedOwners((q) => sqlite.exec(q))
    const db = drizzle(sqlite)
    handle = db
    return new DrizzleSqliteAdapter(db)
  }

  runIdentityStoreCompliance(() => make().identities)
  runAdapterRebindCompliance(
    () => make(),
    () => handle,
  )
  runSessionStoreCompliance(() => make().sessions, { identityId: OWNER, otherIdentityId: OTHER, sessionId })
  runCredentialStoreCompliance(() => make().credentials, { identityId: OWNER, otherIdentityId: OTHER })
})
