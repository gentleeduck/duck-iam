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
import { eq } from 'drizzle-orm'
import { drizzle as drizzleMysql } from 'drizzle-orm/mysql2'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { mysqlUrl } from '~/test/e2e-env'
import {
  runAdapterRebindCompliance,
  runCredentialStoreCompliance,
  runIdentityStoreCompliance,
  runSessionStoreCompliance,
} from '~/test/store-compliance'
import { credentialInput, identityInput, sessionInput } from '~/test/store-inputs'
import { authIdentities, authIdentityProviders, authSessions, DrizzleMysqlAdapter } from '../index'

const URL = mysqlUrl()
const suite = URL ? describe : describe.skip

type Profile = { username: string; email: string }

const sessionId = (label: string) => createHash('sha256').update(label).digest('hex')
const OWNER = randomUUID()
const OTHER = randomUUID()

suite('DrizzleMysql compliance matrix (real MySQL)', () => {
  let stores: DrizzleMysqlAdapter
  let conn: import('mysql2/promise').Connection
  // A real handle for the rebind check: `withClient` refuses anything that is not one.
  let handle: unknown

  beforeAll(async () => {
    const mysql = await import('mysql2/promise')
    conn = await mysql.createConnection(URL as string)
    handle = drizzleMysql(conn, { mode: 'default' })
    stores = new DrizzleMysqlAdapter(URL as string)
  }, 60_000)

  afterAll(async () => {
    await conn?.end()
  })

  beforeEach(async () => {
    // FK order matters, and MySQL has no CASCADE on TRUNCATE.
    await conn.query('SET FOREIGN_KEY_CHECKS = 0')
    for (const t of ['auth_sessions', 'auth_credentials', 'auth_identities']) {
      await conn.query(`TRUNCATE TABLE ${t}`)
    }
    await conn.query('SET FOREIGN_KEY_CHECKS = 1')
    for (const [id, name] of [
      [OWNER, 'owner'],
      [OTHER, 'other'],
    ]) {
      await conn.query(
        `INSERT INTO auth_identities (id, profile, version, email_verified, created_at, updated_at)
         VALUES (?, ?, 1, 1, NOW(3), NOW(3))`,
        [id, JSON.stringify({ email: `${name}@fk.local`, username: name })],
      )
    }
  })

  runIdentityStoreCompliance<Profile>(() => stores.identities)
  runAdapterRebindCompliance<Profile>(
    () => stores,
    () => handle,
  )
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
      expect((await stores.identities.find({ id: created.id }))?.profile.username).toBe('ret-updated')
    })

    it('restore hands back the un-deleted row', async () => {
      const created = await stores.identities.create(
        identityInput<Profile>({ profile: { email: 'restore@x.com', username: 'restore' } }),
      )
      await stores.identities.softDelete(created.id, 60_000)
      const restored = await stores.identities.restore(created.id)
      expect(restored?.id).toBe(created.id)
      expect(await stores.identities.find({ id: created.id })).not.toBeNull()
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
      const found = await stores.identities.find({ providerId: 'oauth:authGoogle', providerSub: 'sub-mysql-1' })
      expect(found?.id).toBe(created.id)
    })

    it('unlink removes only the named provider', async () => {
      const created = await stores.identities.create(
        identityInput<Profile>({ profile: { email: 'unlink@x.com', username: 'unlink' } }),
      )
      await stores.identities.link(created.id, { addedAt: new Date(), providerId: 'oauth:a', providerSub: 's-a' })
      await stores.identities.link(created.id, { addedAt: new Date(), providerId: 'oauth:b', providerSub: 's-b' })
      await stores.identities.unlink(created.id, 'oauth:a')

      expect(await stores.identities.find({ providerId: 'oauth:a', providerSub: 's-a' })).toBeNull()
      expect((await stores.identities.find({ providerId: 'oauth:b', providerSub: 's-b' }))?.id).toBe(created.id)
    })

    it('findByEmail reads through the json path', async () => {
      await stores.identities.create(identityInput<Profile>({ profile: { email: 'path@x.com', username: 'path' } }))
      expect((await stores.identities.find({ email: 'path@x.com' }))?.profile.email).toBe('path@x.com')
    })

    it('a soft-deleted identity is invisible to every lookup', async () => {
      const created = await stores.identities.create(
        identityInput<Profile>({ profile: { email: 'gone@x.com', username: 'gone' } }),
      )
      await stores.identities.link(created.id, { addedAt: new Date(), providerId: 'oauth:c', providerSub: 's-c' })
      await stores.identities.softDelete(created.id, 60_000)

      expect(await stores.identities.find({ id: created.id })).toBeNull()
      expect(await stores.identities.find({ email: 'gone@x.com' })).toBeNull()
      expect(await stores.identities.find({ providerId: 'oauth:c', providerSub: 's-c' })).toBeNull()
    })

    it('preserves a nested profile through the json column', async () => {
      const profile = {
        email: 'nested@x.com',
        nested: { list: [1, 2, { deep: true }], unicode: 'naïve 🦆' },
        username: 'nested',
      } as unknown as Profile
      const created = await stores.identities.create(identityInput<Profile>({ profile }))
      expect((await stores.identities.find({ id: created.id }))?.profile).toEqual(profile)
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

/**
 * As in the pg suite: the tables are a public export, so a direct
 * `db.select()` is a supported read that never goes through the adapter.
 * MySQL's `json` columns come back parsed, so the ISO string a `Date` was
 * written as arrived under a type promising `Date` until the columns carried
 * their own codec.
 */
suite('the exported tables hand back the types they declare (real MySQL)', () => {
  let conn: import('mysql2/promise').Connection
  let db: ReturnType<typeof drizzleMysql<Record<string, never>, import('mysql2/promise').Connection>>
  let stores: DrizzleMysqlAdapter
  const ID = randomUUID()

  beforeAll(async () => {
    const mysql = await import('mysql2/promise')
    conn = await mysql.createConnection(URL as string)
    db = drizzleMysql(conn)
    stores = new DrizzleMysqlAdapter(URL as string)
  }, 60_000)

  afterAll(async () => {
    await conn?.end()
  })

  beforeEach(async () => {
    await conn.query('SET FOREIGN_KEY_CHECKS = 0')
    for (const t of ['auth_sessions', 'auth_credentials', 'auth_identities']) {
      await conn.query(`TRUNCATE TABLE ${t}`)
    }
    await conn.query('SET FOREIGN_KEY_CHECKS = 1')
    await conn.query(
      `INSERT INTO auth_identities (id, profile, version, email_verified, created_at, updated_at)
       VALUES (?, ?, 1, 1, NOW(3), NOW(3))`,
      [ID, JSON.stringify({ email: 'tbl@fk.local', username: 'tbl' })],
    )
  })

  it('gives auth_identity_providers.added_at as a Date on a direct select', async () => {
    const addedAt = new Date('2026-01-02T03:04:05.000Z')
    await stores.identities.link(ID, { addedAt, providerId: 'google', providerSub: 'sub-1' })

    // A real `datetime(3)` now, not a date inside a JSON column: what is under test is the driver handing
    // back a Date, and at millisecond precision rather than truncated to the second.
    const [row] = await db.select().from(authIdentityProviders).where(eq(authIdentityProviders.identityId, ID))
    expect(row?.addedAt).toBeInstanceOf(Date)
    expect(row?.addedAt?.getTime()).toBe(addedAt.getTime())
  })

  it('gives factors[].completedAt and both actingAs dates as Dates on a direct select', async () => {
    const completedAt = new Date('2026-01-02T03:04:05.000Z')
    const startedAt = new Date('2026-01-02T03:00:00.000Z')
    const expiresAt = new Date('2026-01-02T04:00:00.000Z')
    const id = sessionId('mysql-table-types')
    await stores.sessions.create(
      sessionInput({
        aal: 2,
        absoluteExpiresAt: new Date(Date.now() + 600_000),
        actingAs: { expiresAt, realIdentityId: ID, reason: 'support', startedAt },
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 60_000),
        factors: [{ completedAt, method: 'password' }],
        fresh: true,
        id,
        identityId: ID,
        kind: 'user',
        rotatedAt: new Date(),
      }),
    )

    const [row] = await db.select().from(authSessions).where(eq(authSessions.id, id))
    expect(row?.factors[0]?.completedAt).toBeInstanceOf(Date)
    expect(row?.factors[0]?.completedAt?.getTime()).toBe(completedAt.getTime())
    expect(row?.actingAs?.startedAt).toBeInstanceOf(Date)
    expect(row?.actingAs?.expiresAt.getTime()).toBe(expiresAt.getTime())
  })
})
