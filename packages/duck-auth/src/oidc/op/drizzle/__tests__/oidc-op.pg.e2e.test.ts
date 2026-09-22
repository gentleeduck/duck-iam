/** E2E: the OIDC OP stores against REAL Postgres. */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { Pool } from 'pg'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { isolatedDatabaseUrl } from '~/test/e2e-env'
import { insertGcFixture, runOidcOpCompliance } from '~/test/oidc-op-compliance'
import { authCreateDrizzlePgOidcOpStores, authGcDrizzlePgOidcOp } from '../pg'

const URL = await isolatedDatabaseUrl('oidc_pg')
const suite = URL ? describe : describe.skip

suite('OIDC OP stores on real Postgres', () => {
  let pool: Pool
  let stores: ReturnType<typeof authCreateDrizzlePgOidcOpStores>
  let db: Parameters<typeof authGcDrizzlePgOidcOp>[0]

  beforeAll(async () => {
    pool = new Pool({ connectionString: URL })
    await pool.query(readFileSync(join(process.cwd(), 'src/test/oidc-pg-e2e-schema.sql'), 'utf8'))
    const { drizzle } = await import('drizzle-orm/node-postgres')
    db = drizzle(pool) as never
    stores = authCreateDrizzlePgOidcOpStores(db)
  }, 60_000)

  afterAll(async () => {
    await pool?.end()
  })

  beforeEach(async () => {
    await pool.query('TRUNCATE oidc_consents, oidc_refresh_tokens, oidc_access_tokens, oidc_codes, oidc_clients')
  })

  runOidcOpCompliance(() => stores)

  describe('authGcDrizzlePgOidcOp', () => {
    it('prunes the three kinds of dead row and counts them', async () => {
      const now = Date.now()
      await insertGcFixture(stores, now)

      expect(await authGcDrizzlePgOidcOp(db, now)).toBe(3)
      expect(await stores.accessTokens.findByHash('gc-at', now)).toBeNull()
      expect(await stores.refreshTokens.findByHash('gc-rt', now)).toBeNull()
    })
  })
})
