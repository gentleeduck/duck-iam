/** E2E: the OIDC OP stores against REAL MySQL. */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { mysqlUrl } from '~/test/e2e-env'
import { insertGcFixture, runOidcOpCompliance } from '~/test/oidc-op-compliance'
import { authCreateDrizzleMysqlOidcOpStores, authGcDrizzleMysqlOidcOp } from '../mysql'

const URL = mysqlUrl()
const suite = URL ? describe : describe.skip

const TABLES = ['oidc_consents', 'oidc_refresh_tokens', 'oidc_access_tokens', 'oidc_codes', 'oidc_clients']

suite('OIDC OP stores on real MySQL', () => {
  let conn: import('mysql2/promise').Connection
  let stores: ReturnType<typeof authCreateDrizzleMysqlOidcOpStores>
  let db: Parameters<typeof authGcDrizzleMysqlOidcOp>[0]

  beforeAll(async () => {
    const mysql = await import('mysql2/promise')
    // multipleStatements so the generated DDL can be applied in one go.
    conn = await mysql.createConnection({ multipleStatements: true, uri: URL as string })
    await conn.query(readFileSync(join(process.cwd(), 'src/test/oidc-mysql-e2e-schema.sql'), 'utf8'))
    const { drizzle } = await import('drizzle-orm/mysql2')
    db = drizzle(conn) as never
    stores = authCreateDrizzleMysqlOidcOpStores(db)
  }, 60_000)

  afterAll(async () => {
    await conn?.end()
  })

  beforeEach(async () => {
    for (const t of TABLES) await conn.query(`TRUNCATE TABLE ${t}`)
  })

  runOidcOpCompliance(() => stores)

  describe('authGcDrizzleMysqlOidcOp', () => {
    it('prunes the three kinds of dead row and counts them', async () => {
      const now = Date.now()
      await insertGcFixture(stores, now)

      // MySQL has no RETURNING, so the count is read off the result envelope: a shape it failed to read
      // would report nothing pruned while pruning correctly, and a cron would look like it never ran.
      expect(await authGcDrizzleMysqlOidcOp(db, now)).toBe(3)
      expect(await stores.accessTokens.findByHash('gc-at', now)).toBeNull()
      expect(await stores.refreshTokens.findByHash('gc-rt', now)).toBeNull()
    })
  })
})
