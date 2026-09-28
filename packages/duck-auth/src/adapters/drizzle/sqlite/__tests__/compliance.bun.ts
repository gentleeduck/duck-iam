/** The compliance matrix over bun:sqlite, run by `bun test` from the `test` script: vitest runs under node, where
 *  bun:sqlite does not exist, so `compliance.test.ts` covers better-sqlite3 alone. */

import { Database } from 'bun:sqlite'
import { createHash } from 'node:crypto'
import { drizzle } from 'drizzle-orm/bun-sqlite'
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

const sessionId = (label: string) => createHash('sha256').update(label).digest('hex')
const OWNER = 'owner-identity'
const OTHER = 'other-identity'

describe('DrizzleSqlite compliance matrix, over bun:sqlite', () => {
  let handle: unknown

  const make = (): Adapter.Me<{ username: string; email: string }> => {
    const sqlite = new Database(':memory:')
    sqlite.exec(DDL)
    for (const [id, name] of [
      [OWNER, 'owner'],
      [OTHER, 'other'],
    ]) {
      sqlite.exec(
        `INSERT INTO auth_identities (id, profile, version, email_verified, created_at, updated_at)
         VALUES ('${id}', '{"email":"${name}@fk.local","username":"${name}"}', 1, 1, 0, 0)`,
      )
    }
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
