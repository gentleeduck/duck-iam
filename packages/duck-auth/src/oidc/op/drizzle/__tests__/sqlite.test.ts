/**
 * The SQLite OIDC OP stores, against the shared contract every dialect answers.
 *
 * This file used to be bun-gated and hold its own hand-written cases, so under Node - which is what
 * `bun run test` uses - the sqlite OP stores were the one dialect nothing ran at all.
 */

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { beforeAll, describe, expect, it } from 'vitest'
import { runOidcOpCompliance } from '~/test/oidc-op-compliance'
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
    it('prunes expired codes / access tokens / consumed refresh tokens', async () => {
      const { db, stores } = make()
      const now = Date.now()
      await stores.codes.insert({
        client_id: 'app',
        code: 'gc-code',
        code_challenge: null,
        code_challenge_method: null,
        exp: now - 1,
        identity_id: 'u',
        nonce: null,
        redirect_uri: 'x',
        scope: ['openid'],
        sid: 's',
        tenant_id: null,
      })
      await stores.accessTokens.insert({
        client_id: 'app',
        exp: now - 1,
        identity_id: 'u',
        scope: ['openid'],
        tenant_id: null,
        token_hash: 'gc-at',
      })
      await stores.refreshTokens.insert({
        client_id: 'app',
        consumedAt: now - 1,
        exp: now + 60_000,
        family_id: 'f',
        identity_id: 'u',
        scope: ['openid'],
        tenant_id: null,
        token_hash: 'gc-rt',
      })

      expect(await authGcDrizzleSqliteOidcOp(db as never, now)).toBe(3)
    })
  })
})
