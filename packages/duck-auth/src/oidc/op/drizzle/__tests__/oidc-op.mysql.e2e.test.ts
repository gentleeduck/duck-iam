/**
 * E2E: the OIDC OP stores against REAL MySQL.
 *
 * This flavour had no test of any kind. It also relies on ON DUPLICATE KEY for
 * `consents.upsert`, which silently appends a second row rather than replacing a
 * scope when the key it needs is not unique, so it is the dialect where that
 * failure is quietest.
 *
 * Skips when DUCKAUTH_E2E_MYSQL_URL is unset; `globalSetup` provisions a
 * container when docker is available.
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, beforeAll, beforeEach, describe } from 'vitest'
import { mysqlUrl } from '~/test/e2e-env'
import { runOidcOpCompliance } from '~/test/oidc-op-compliance'
import { authCreateDrizzleMysqlOidcOpStores } from '../mysql'

const URL = mysqlUrl()
const suite = URL ? describe : describe.skip

const TABLES = ['oidc_consents', 'oidc_refresh_tokens', 'oidc_access_tokens', 'oidc_codes', 'oidc_clients']

suite('OIDC OP stores on real MySQL', () => {
  let conn: import('mysql2/promise').Connection
  let stores: ReturnType<typeof authCreateDrizzleMysqlOidcOpStores>

  beforeAll(async () => {
    const mysql = await import('mysql2/promise')
    // multipleStatements so the generated DDL can be applied in one go.
    conn = await mysql.createConnection({ multipleStatements: true, uri: URL as string })
    await conn.query(readFileSync(join(process.cwd(), 'src/test/oidc-mysql-e2e-schema.sql'), 'utf8'))
    const { drizzle } = await import('drizzle-orm/mysql2')
    stores = authCreateDrizzleMysqlOidcOpStores(drizzle(conn) as never)
  }, 60_000)

  afterAll(async () => {
    await conn?.end()
  })

  beforeEach(async () => {
    for (const t of TABLES) await conn.query(`TRUNCATE TABLE ${t}`)
  })

  runOidcOpCompliance(() => stores)
})
