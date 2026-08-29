/**
 * Store-contract compliance for the Drizzle MySQL adapter, against REAL MySQL.
 *
 * This adapter shipped with no test file of any kind. It is also the flavour that
 * diverges most from the others, by its own docblock: MySQL has no `RETURNING`, so
 * every mutation that must hand back the new row re-`SELECT`s it, and JSON lookups
 * use `->>'$.key'` and `JSON_CONTAINS` rather than pg's `->>` and `@>`. Each of
 * those is a hand-written variant of a query the other adapters get from drizzle,
 * and the re-select in particular is a place where a row can come back stale or
 * not at all.
 *
 * Skips when DUCKAUTH_E2E_MYSQL_URL is unset; `globalSetup` provisions a container
 * when docker is available.
 */
import { createHash, randomUUID } from 'node:crypto'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { mysqlUrl } from '~/test/e2e-env'
import {
  runCredentialStoreCompliance,
  runIdentityStoreCompliance,
  runSessionStoreCompliance,
} from '~/test/store-compliance'
import { credentialInput, identityInput, sessionInput } from '~/test/store-inputs'
import { drizzleMysqlStorage } from '../index'

const URL = mysqlUrl()
const suite = URL ? describe : describe.skip

type Profile = { username: string; email: string }

const sessionId = (label: string) => createHash('sha256').update(label).digest('hex')
const OWNER = randomUUID()
const OTHER = randomUUID()

suite('DrizzleMysql compliance matrix (real MySQL)', () => {
  let stores: ReturnType<typeof drizzleMysqlStorage<Profile>>
  let conn: import('mysql2/promise').Connection

  beforeAll(async () => {
    const mysql = await import('mysql2/promise')
    conn = await mysql.createConnection(URL as string)
    stores = drizzleMysqlStorage<Profile>(URL as string)
  }, 60_000)

  afterAll(async () => {
    await conn?.end()
  })

  beforeEach(async () => {
    // FK order matters, and MySQL has no CASCADE on TRUNCATE.
    await conn.query('SET FOREIGN_KEY_CHECKS = 0')
    for (const t of ['auth_events', 'auth_sessions', 'auth_credentials', 'auth_identities']) {
      await conn.query(`TRUNCATE TABLE ${t}`)
    }
    await conn.query('SET FOREIGN_KEY_CHECKS = 1')
    for (const [id, name] of [
      [OWNER, 'owner'],
      [OTHER, 'other'],
    ]) {
      await conn.query(
        `INSERT INTO auth_identities (id, profile, providers, version, email_verified, created_at, updated_at)
         VALUES (?, ?, ?, 1, 1, NOW(3), NOW(3))`,
        [id, JSON.stringify({ email: `${name}@fk.local`, username: name }), JSON.stringify([])],
      )
    }
  })

  runIdentityStoreCompliance<Profile>(() => stores.identities)
  runSessionStoreCompliance(() => stores.sessions, { identityId: OWNER, otherIdentityId: OTHER, sessionId })
  runCredentialStoreCompliance(() => stores.credentials, { identityId: OWNER })

  describe('the re-SELECT that stands in for RETURNING', () => {
    it('update hands back the row as it now is, not as it was', async () => {
      const created = await stores.identities.create(
        identityInput<Profile>({ profile: { email: 'ret@x.com', username: 'ret' } }),
      )
      const updated = await stores.identities.update(
        created.id,
        { profile: { email: 'ret@x.com', username: 'ret-updated' } },
        created.version,
      )
      expect(updated.profile.username).toBe('ret-updated')
      expect(updated.version).toBe(created.version + 1)
      // And the re-select must agree with what a fresh read sees.
      expect((await stores.identities.findById(created.id))?.profile.username).toBe('ret-updated')
    })

    it('restore hands back the un-deleted row', async () => {
      const created = await stores.identities.create(
        identityInput<Profile>({ profile: { email: 'restore@x.com', username: 'restore' } }),
      )
      await stores.identities.softDelete(created.id, 60_000)
      const restored = await stores.identities.restore(created.id)
      expect(restored.id).toBe(created.id)
      expect(await stores.identities.findById(created.id)).not.toBeNull()
    })

    it('credential rotate hands back the rotated row', async () => {
      const c = await stores.credentials.upsert(
        credentialInput({ identityId: OWNER, kind: 'password', metadata: {}, secret: 'h1' }),
        {},
      )
      const rotated = await stores.credentials.rotate(c.id, 'h2', c.version, {})
      expect(rotated.secret).toBe('h2')
      expect(rotated.version).toBe(c.version + 1)
    })
  })

  describe('JSON_CONTAINS and json path lookups', () => {
    it('findByProviderSub locates a linked identity', async () => {
      const created = await stores.identities.create(
        identityInput<Profile>({ profile: { email: 'link@x.com', username: 'link' } }),
      )
      await stores.identities.link(created.id, {
        addedAt: new Date(),
        providerId: 'oauth:authGoogle',
        providerSub: 'sub-mysql-1',
      })
      const found = await stores.identities.findByProviderSub('oauth:authGoogle', 'sub-mysql-1')
      expect(found?.id).toBe(created.id)
    })

    it('unlink removes only the named provider', async () => {
      const created = await stores.identities.create(
        identityInput<Profile>({ profile: { email: 'unlink@x.com', username: 'unlink' } }),
      )
      await stores.identities.link(created.id, { addedAt: new Date(), providerId: 'oauth:a', providerSub: 's-a' })
      await stores.identities.link(created.id, { addedAt: new Date(), providerId: 'oauth:b', providerSub: 's-b' })
      await stores.identities.unlink(created.id, 'oauth:a')

      expect(await stores.identities.findByProviderSub('oauth:a', 's-a')).toBeNull()
      expect((await stores.identities.findByProviderSub('oauth:b', 's-b'))?.id).toBe(created.id)
    })

    it('findByEmail reads through the json path', async () => {
      await stores.identities.create(identityInput<Profile>({ profile: { email: 'path@x.com', username: 'path' } }))
      expect((await stores.identities.findByEmail('path@x.com'))?.profile.email).toBe('path@x.com')
    })

    it('a soft-deleted identity is invisible to every lookup', async () => {
      const created = await stores.identities.create(
        identityInput<Profile>({ profile: { email: 'gone@x.com', username: 'gone' } }),
      )
      await stores.identities.link(created.id, { addedAt: new Date(), providerId: 'oauth:c', providerSub: 's-c' })
      await stores.identities.softDelete(created.id, 60_000)

      expect(await stores.identities.findById(created.id)).toBeNull()
      expect(await stores.identities.findByEmail('gone@x.com')).toBeNull()
      expect(await stores.identities.findByProviderSub('oauth:c', 's-c')).toBeNull()
    })

    it('preserves a nested profile through the json column', async () => {
      const profile = {
        email: 'nested@x.com',
        nested: { list: [1, 2, { deep: true }], unicode: 'naïve 🦆' },
        username: 'nested',
      } as unknown as Profile
      const created = await stores.identities.create(identityInput<Profile>({ profile }))
      expect((await stores.identities.findById(created.id))?.profile).toEqual(profile)
    })
  })

  describe('datetime(3) precision', () => {
    it('keeps millisecond precision on a session round trip', async () => {
      // datetime(3) is the whole reason the schema does not use plain datetime:
      // second-granularity timestamps would round an expiry the wrong way.
      const now = new Date()
      const id = sessionId('precision')
      await stores.sessions.create(
        sessionInput({
          aal: 1,
          absoluteExpiresAt: new Date(now.getTime() + 600_000),
          createdAt: now,
          expiresAt: new Date(now.getTime() + 60_000),
          factors: [{ completedAt: now, method: 'password' }],
          fresh: true,
          id,
          identityId: OWNER,
          kind: 'user',
          rotatedAt: now,
        }),
      )
      const read = await stores.sessions.getByHash(id)
      expect(read?.createdAt).toBeInstanceOf(Date)
      expect(read?.createdAt.getTime()).toBe(now.getTime())
      expect(read?.factors[0]?.completedAt).toBeInstanceOf(Date)
    })
  })

  describe('optimistic locking', () => {
    it('refuses the second of two updates from the same version', async () => {
      const created = await stores.identities.create(
        identityInput<Profile>({ profile: { email: 'lock@x.com', username: 'lock' } }),
      )
      await stores.identities.update(created.id, { emailVerified: true }, created.version)
      await expect(
        stores.identities.update(created.id, { emailVerified: false }, created.version),
      ).rejects.toMatchObject({ code: 'AUTH_STALE_WRITE' })
    })
  })

  describe('bulk behaviour at size', () => {
    it('lists and bulk-deletes every session for an identity', async () => {
      const now = new Date()
      const ids = Array.from({ length: 40 }, (_, i) => sessionId(`bulk-${i}`))
      for (const id of ids) {
        await stores.sessions.create(
          sessionInput({
            aal: 1,
            absoluteExpiresAt: new Date(now.getTime() + 600_000),
            createdAt: now,
            expiresAt: new Date(now.getTime() + 60_000),
            factors: [],
            fresh: true,
            id,
            identityId: OWNER,
            kind: 'user',
            rotatedAt: now,
          }),
        )
      }
      expect(await stores.sessions.listByIdentity(OWNER)).toHaveLength(40)
      await stores.sessions.deleteAllForIdentity(OWNER)
      expect(await stores.sessions.listByIdentity(OWNER)).toHaveLength(0)
    })
  })
})
