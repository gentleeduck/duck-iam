/** The SQLite OIDC OP stores, against the shared contract every dialect answers. */

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { beforeAll, describe, expect, it } from 'vitest'
import { insertGcFixture, runOidcOpCompliance } from '~/test/oidc-op-compliance'
import { authCreateDrizzleSqliteOidcOpStores, authGcDrizzleSqliteOidcOp } from '../sqlite'

/** The generated schema, as pg and mysql read theirs. A hand-written copy is what granted `oidc_consents`
 *  a primary key the schema never declared, and `upsert`'s ON CONFLICT worked only because of it. */
const DDL = readFileSync(join(process.cwd(), 'src/test/oidc-sqlite-e2e-schema.sql'), 'utf8')

const IS_BUN = typeof (globalThis as { Bun?: unknown }).Bun !== 'undefined'

type Made = { db: unknown; stores: ReturnType<typeof authCreateDrizzleSqliteOidcOpStores> }

describe('DrizzleSqlite OIDC OP stores', () => {
  //   Bun  -> bun:sqlite     via drizzle-orm/bun-sqlite
  //   Node -> better-sqlite3 via drizzle-orm/better-sqlite3
  let make: () => Made

  beforeAll(async () => {
    if (IS_BUN) {
      const { Database } = (await import('bun:sqlite' as string)) as {
        Database: new (path: string) => { exec(sql: string): void }
      }
      const { drizzle } = await import('drizzle-orm/bun-sqlite')
      make = () => {
        const sqlite = new Database(':memory:')
        sqlite.exec(DDL)
        // biome-ignore lint/suspicious/noExplicitAny: bun:sqlite Database is structurally the drizzle client.
        const db = drizzle(sqlite as any)
        return { db, stores: authCreateDrizzleSqliteOidcOpStores(db) }
      }
      return
    }

    const { default: Database } = await import('better-sqlite3')
    const { drizzle } = await import('drizzle-orm/better-sqlite3')
    make = () => {
      const sqlite = new Database(':memory:')
      sqlite.exec(DDL)
      // biome-ignore lint/suspicious/noExplicitAny: better-sqlite3 Database is structurally the drizzle client.
      const db = drizzle(sqlite as any)
      return { db, stores: authCreateDrizzleSqliteOidcOpStores(db) }
    }
  })

  runOidcOpCompliance(() => make().stores)

  describe('authGcDrizzleSqliteOidcOp', () => {
    it('prunes the three kinds of dead row and counts them', async () => {
      const { db, stores } = make()
      const now = Date.now()
      await insertGcFixture(stores, now)

      expect(await authGcDrizzleSqliteOidcOp(db as never, now)).toBe(3)
    })
  })
})
