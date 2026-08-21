/**
 * E2E: the OIDC OP stores against REAL Postgres.
 *
 * Only the sqlite flavour had a test and it is bun-gated, so under Node nothing
 * ran, and the pg flavour had never been executed at all. The contract lives in
 * `~/test/oidc-op-compliance` so this dialect and mysql answer the same questions.
 *
 * Skips when DUCKAUTH_E2E_DATABASE_URL is unset; `globalSetup` provisions a
 * container when docker is available.
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { Pool } from 'pg'
import { afterAll, beforeAll, beforeEach, describe } from 'vitest'
import { isolatedDatabaseUrl } from '~/test/e2e-env'
import { runOidcOpCompliance } from '~/test/oidc-op-compliance'
import { authCreateDrizzlePgOidcOpStores } from '../pg'

const URL = await isolatedDatabaseUrl('oidc_pg')
const suite = URL ? describe : describe.skip

suite('OIDC OP stores on real Postgres', () => {
  let pool: Pool
  let stores: ReturnType<typeof authCreateDrizzlePgOidcOpStores>

  beforeAll(async () => {
    pool = new Pool({ connectionString: URL })
    await pool.query(readFileSync(join(process.cwd(), 'src/test/oidc-pg-e2e-schema.sql'), 'utf8'))
    const { drizzle } = await import('drizzle-orm/node-postgres')
    stores = authCreateDrizzlePgOidcOpStores(drizzle(pool) as never)
  }, 60_000)

  afterAll(async () => {
    await pool?.end()
  })

  beforeEach(async () => {
    await pool.query('TRUNCATE oidc_consents, oidc_refresh_tokens, oidc_access_tokens, oidc_codes, oidc_clients')
  })

  runOidcOpCompliance(() => stores)
})
