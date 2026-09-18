/** Store-contract compliance for the Drizzle Postgres adapter, against REAL Postgres. */
import { createHash } from 'node:crypto'
import { eq } from 'drizzle-orm'
import { drizzle } from 'drizzle-orm/node-postgres'
import { Pool } from 'pg'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { authUuidV7 } from '~/core/crypto'
import { applyPgSchema, databaseUrl, isolatedDatabaseUrl } from '~/test/e2e-env'
import {
  runAdapterRebindCompliance,
  runCredentialStoreCompliance,
  runIdentityStoreCompliance,
  runSessionStoreCompliance,
} from '~/test/store-compliance'
import { credentialInput, identityInput, sessionInput } from '~/test/store-inputs'
import { authIdentities, authIdentityProviders, authSessions, DrizzlePgAdapter } from '../index'

const URL = databaseUrl()
const suite = URL ? describe : describe.skip

type Profile = { username: string; email: string }

/** `chk_auth_sessions_id_length` demands exactly 64 chars, as every real sid is. */
const sessionId = (label: string) => createHash('sha256').update(label).digest('hex')

/** `auth_identities.id` is `uuid`, and sessions/credentials carry an FK to it. */
const OWNER = authUuidV7()
const OTHER = authUuidV7()

suite('DrizzlePg compliance matrix (real Postgres)', () => {
  let pool: Pool
  let stores: DrizzlePgAdapter
  // A real handle for the rebind check: `withClient` refuses anything that is not one.
  let handle: unknown

  beforeAll(async () => {
    // Owned database: this suite truncates between cases, and the other pg suites
    // run in parallel workers against the shared one.
    const own = (await isolatedDatabaseUrl('pg_compliance')) as string
    pool = new Pool({ connectionString: own })
    await applyPgSchema(pool)
    handle = drizzle(pool)
    stores = new DrizzlePgAdapter(own)
  }, 60_000)

  afterAll(async () => {
    await pool?.end()
  })

  /**
   * The matrix asks for a fresh store per case and plants fixed ids. Against one
   * shared database that means wiping between cases, and re-planting the two
   * identity rows the session + credential foreign keys point at.
   */
  beforeEach(async () => {
    await pool.query('TRUNCATE auth_sessions, auth_credentials, auth_identities CASCADE')
    for (const [id, name] of [
      [OWNER, 'owner'],
      [OTHER, 'other'],
    ]) {
      await pool.query(
        `INSERT INTO auth_identities (id, profile, version, email_verified, created_at, updated_at)
         VALUES ($1, $2::jsonb, 1, true, now(), now())`,
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

  describe('optimistic locking under a real transaction', () => {
    it('refuses the second of two updates that started from the same version', async () => {
      // Two request handlers read the same row and both write. One must lose, or a
      // profile edit silently overwrites another. sqlite can pass this while pg
      // behaves differently under its own concurrency control, which is the point.
      const created = await stores.identities.create(
        identityInput<Profile>({ profile: { email: 'lock@x.com', username: 'lock' } }),
      )

      const first = await stores.identities.update(created.id, { emailVerified: true }, created.version)
      expect(first.version).toBe(created.version + 1)

      await expect(
        stores.identities.update(created.id, { emailVerified: false }, created.version),
      ).rejects.toMatchObject({ code: 'AUTH_STALE_WRITE' })
    })

    it('admits exactly one of many concurrent updates from the same version', async () => {
      const created = await stores.identities.create(
        identityInput<Profile>({ profile: { email: 'race@x.com', username: 'race' } }),
      )

      const settled = await Promise.allSettled(
        Array.from({ length: 10 }, (_, i) =>
          stores.identities.update(
            created.id,
            { profile: { email: `race@x.com`, username: `race-${i}` } },
            created.version,
          ),
        ),
      )

      expect(settled.filter((r) => r.status === 'fulfilled')).toHaveLength(1)
      for (const r of settled.filter((x) => x.status === 'rejected')) {
        expect((r as PromiseRejectedResult).reason).toMatchObject({ code: 'AUTH_STALE_WRITE' })
      }
      const final = await stores.identities.find({ id: created.id })
      expect(final?.version).toBe(created.version + 1)
    })

    it('a sequential chain of updates advances the version once each time', async () => {
      let current = await stores.identities.create(
        identityInput<Profile>({ profile: { email: 'chain@x.com', username: 'chain' } }),
      )
      for (let i = 0; i < 5; i++) {
        current = await stores.identities.update(
          current.id,
          { profile: { email: 'chain@x.com', username: `chain-${i}` } },
          current.version,
        )
      }
      expect(current.version).toBe(6)
      expect(current.profile.username).toBe('chain-4')
    })
  })

  describe('unique indexes on the profile jsonb', () => {
    it('refuses a second live identity with the same email', async () => {
      await stores.identities.create(identityInput<Profile>({ profile: { email: 'dup@x.com', username: 'dup-a' } }))
      await expect(
        stores.identities.create(identityInput<Profile>({ profile: { email: 'dup@x.com', username: 'dup-b' } })),
      ).rejects.toMatchObject({ code: 'AUTH_EMAIL_TAKEN' })
    })

    it('treats email case-insensitively, because the index is on lower()', async () => {
      await stores.identities.create(identityInput<Profile>({ profile: { email: 'Case@X.com', username: 'case-a' } }))
      await expect(
        stores.identities.create(identityInput<Profile>({ profile: { email: 'case@x.com', username: 'case-b' } })),
      ).rejects.toMatchObject({ code: 'AUTH_EMAIL_TAKEN' })
    })

    it('refuses a duplicate username case-insensitively too', async () => {
      await stores.identities.create(identityInput<Profile>({ profile: { email: 'u1@x.com', username: 'Taken' } }))
      await expect(
        stores.identities.create(identityInput<Profile>({ profile: { email: 'u2@x.com', username: 'taken' } })),
      ).rejects.toMatchObject({ code: 'AUTH_USERNAME_TAKEN' })
    })

    it('keeps the address while the holder is hidden, and frees it on erase', async () => {
      // The index carries no `WHERE deleted_at IS NULL`: handing the address out during the grace window
      // would leave the row no way back, which is the one thing the window promises.
      const first = await stores.identities.create(
        identityInput<Profile>({ profile: { email: 'reuse@x.com', username: 'reuse-a' } }),
      )
      await stores.identities.softDelete(first.id, 60_000)
      await expect(
        stores.identities.create(identityInput<Profile>({ profile: { email: 'reuse@x.com', username: 'reuse-b' } })),
      ).rejects.toMatchObject({ code: 'AUTH_EMAIL_TAKEN' })

      await stores.identities.erase(first.id)
      const second = await stores.identities.create(
        identityInput<Profile>({ profile: { email: 'reuse@x.com', username: 'reuse-b' } }),
      )
      expect(second.id).not.toBe(first.id)
    })

    it('findByEmail ignores a soft-deleted holder', async () => {
      const first = await stores.identities.create(
        identityInput<Profile>({ profile: { email: 'hidden@x.com', username: 'hidden' } }),
      )
      await stores.identities.softDelete(first.id, 60_000)
      await expect(stores.identities.find({ email: 'hidden@x.com' })).rejects.toMatchObject({
        code: 'AUTH_IDENTITY_NOT_FOUND',
      })
    })
  })

  describe('jsonb column round trips', () => {
    it('preserves a deeply nested profile through the driver', async () => {
      const profile = {
        email: 'json@x.com',
        username: 'json',
        // biome-ignore lint/suspicious/noExplicitAny: deliberately wider than Profile
        nested: { list: [1, 2, { deep: true }], unicode: 'naïve 🦆', when: '2026-01-01T00:00:00.000Z' },
      } as unknown as Profile
      const created = await stores.identities.create(identityInput<Profile>({ profile }))
      const read = await stores.identities.find({ id: created.id })
      expect(read?.profile).toEqual(profile)
    })

    it('preserves factors and actingAs on a session row', async () => {
      const now = new Date()
      const id = sessionId('acting')
      await stores.sessions.create(
        sessionInput({
          absoluteExpiresAt: new Date(now.getTime() + 600_000),
          actingAs: {
            expiresAt: new Date(now.getTime() + 60_000),
            realIdentityId: OTHER,
            reason: 'support',
            startedAt: now,
          },
          aal: 2,
          createdAt: now,
          expiresAt: new Date(now.getTime() + 60_000),
          factors: [
            { completedAt: now, method: 'password' },
            { completedAt: now, method: 'totp' },
          ],
          fresh: true,
          id,
          identityId: OWNER,
          kind: 'user',
          rotatedAt: now,
        }),
      )
      const read = await stores.sessions.getByHash(id)
      expect(read?.factors.map((f) => f.method)).toEqual(['password', 'totp'])
      expect(read?.factors[0]?.completedAt).toBeInstanceOf(Date)
      expect(read?.actingAs?.realIdentityId).toBe(OTHER)
      expect(read?.actingAs?.expiresAt).toBeInstanceOf(Date)
    })

    it('keeps credential metadata typed through jsonb', async () => {
      const c = await stores.credentials.create(
        credentialInput({ identityId: OWNER, kind: 'totp', metadata: { confirmed: false, counter: 0 }, secret: 's' }),
        {},
      )
      const patched = await stores.credentials.patchMetadata(c.id, { confirmed: true }, {})
      expect(patched.metadata).toEqual({ confirmed: true, counter: 0 })
    })
  })

  describe('timestamptz precision', () => {
    it('returns Date objects, not strings, on every temporal column', async () => {
      const created = await stores.identities.create(
        identityInput<Profile>({ profile: { email: 'time@x.com', username: 'time' } }),
      )
      const read = await stores.identities.find({ id: created.id })
      expect(read?.createdAt).toBeInstanceOf(Date)
      expect(read?.updatedAt).toBeInstanceOf(Date)
      expect(Number.isFinite(read?.createdAt.getTime())).toBe(true)
    })

    it('survives a millisecond-precision round trip', async () => {
      const now = new Date()
      const id = sessionId('precision')
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
      const read = await stores.sessions.getByHash(id)
      expect(read?.createdAt.getTime()).toBe(now.getTime())
    })
  })

  describe('foreign keys and check constraints', () => {
    it('cascades session rows when the identity is erased', async () => {
      const id = sessionId('cascade')
      const now = new Date()
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
      await stores.identities.erase(OWNER)
      await expect(stores.sessions.getByHash(id)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    })

    it('refuses a session pointing at an identity that does not exist', async () => {
      const now = new Date()
      await expect(
        stores.sessions.create(
          sessionInput({
            aal: 1,
            absoluteExpiresAt: new Date(now.getTime() + 600_000),
            createdAt: now,
            expiresAt: new Date(now.getTime() + 60_000),
            factors: [],
            fresh: true,
            id: sessionId('orphan'),
            identityId: authUuidV7(),
            kind: 'user',
            rotatedAt: now,
          }),
        ),
      ).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
    })

    it('refuses an out-of-range aal', async () => {
      const now = new Date()
      await expect(
        stores.sessions.create(
          sessionInput({
            absoluteExpiresAt: new Date(now.getTime() + 600_000),
            // biome-ignore lint/suspicious/noExplicitAny: violating the typed shape on purpose
            aal: 9 as any,
            createdAt: now,
            expiresAt: new Date(now.getTime() + 60_000),
            factors: [],
            fresh: true,
            id: sessionId('bad-aal'),
            identityId: OWNER,
            kind: 'user',
            rotatedAt: now,
          }),
        ),
      ).rejects.toMatchObject({ code: 'AUTH_INVALID_PARAMETERS' })
    })

    it('refuses an expiry that precedes creation', async () => {
      // `chk_auth_sessions_expires_after_created`. A backdated expiry would make a
      // session that is dead the moment it is written.
      const now = new Date()
      await expect(
        stores.sessions.create(
          sessionInput({
            aal: 1,
            absoluteExpiresAt: new Date(now.getTime() + 600_000),
            createdAt: now,
            expiresAt: new Date(now.getTime() - 60_000),
            factors: [],
            fresh: true,
            id: sessionId('backdated'),
            identityId: OWNER,
            kind: 'user',
            rotatedAt: now,
          }),
        ),
      ).rejects.toMatchObject({ code: 'AUTH_INVALID_PARAMETERS' })
    })

    it('refuses a session id that is not 64 chars', async () => {
      const now = new Date()
      await expect(
        stores.sessions.create(
          sessionInput({
            aal: 1,
            absoluteExpiresAt: new Date(now.getTime() + 600_000),
            createdAt: now,
            expiresAt: new Date(now.getTime() + 60_000),
            factors: [],
            fresh: true,
            id: 'too-short',
            identityId: OWNER,
            kind: 'user',
            rotatedAt: now,
          }),
        ),
      ).rejects.toMatchObject({ code: 'AUTH_INVALID_PARAMETERS' })
    })

    it('refuses an unrecognised session kind', async () => {
      const now = new Date()
      await expect(
        stores.sessions.create(
          sessionInput({
            aal: 1,
            absoluteExpiresAt: new Date(now.getTime() + 600_000),
            createdAt: now,
            expiresAt: new Date(now.getTime() + 60_000),
            factors: [],
            fresh: true,
            id: sessionId('bad-kind'),
            identityId: OWNER,
            // biome-ignore lint/suspicious/noExplicitAny: violating the typed shape on purpose
            kind: 'web' as any,
            rotatedAt: now,
          }),
        ),
      ).rejects.toMatchObject({ code: 'AUTH_INVALID_PARAMETERS' })
    })

    it('refuses a profile missing the required keys', async () => {
      // `chk_auth_identities_profile_shape` requires username + email to exist.
      await expect(
        // biome-ignore lint/suspicious/noExplicitAny: violating the typed shape on purpose
        stores.identities.create(identityInput<Profile>({ profile: { nickname: 'nope' } as any })),
      ).rejects.toMatchObject({ code: 'AUTH_INVALID_PARAMETERS' })
    })
  })

  describe('bulk behaviour at size', () => {
    it('listByIdentity returns every row for a busy identity', async () => {
      const now = new Date()
      const ids = Array.from({ length: 50 }, (_, i) => sessionId(`bulk-${i}`))
      await Promise.all(
        ids.map((id) =>
          stores.sessions.create(
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
          ),
        ),
      )
      expect(await stores.sessions.listByIdentity(OWNER)).toHaveLength(50)
      await stores.sessions.deleteAllForIdentity(OWNER)
      expect(await stores.sessions.listByIdentity(OWNER)).toHaveLength(0)
    })

    it('gc removes only the expired rows out of a mixed set', async () => {
      const now = Date.now()
      const live = Array.from({ length: 10 }, (_, i) => sessionId(`gc-live-${i}`))
      const dead = Array.from({ length: 10 }, (_, i) => sessionId(`gc-dead-${i}`))
      const base = { factors: [], identityId: OWNER, kind: 'user' as const }
      await Promise.all([
        ...live.map((id) =>
          stores.sessions.create(
            sessionInput({
              ...base,
              aal: 1,
              absoluteExpiresAt: new Date(now + 600_000),
              createdAt: new Date(now),
              expiresAt: new Date(now + 60_000),
              fresh: true,
              id,
              rotatedAt: new Date(now),
            }),
          ),
        ),
        ...dead.map((id) =>
          stores.sessions.create(
            sessionInput({
              ...base,
              aal: 1,
              absoluteExpiresAt: new Date(now - 1),
              createdAt: new Date(now - 100_000),
              expiresAt: new Date(now - 1),
              fresh: false,
              id,
              rotatedAt: new Date(now - 100_000),
            }),
          ),
        ),
      ])

      const { deleted } = await stores.sessions.gc(now)
      expect(deleted).toBe(10)
      expect(await stores.sessions.listByIdentity(OWNER)).toHaveLength(10)
    })
  })
})

/**
 * The tables are a public export, so a `db.select().from(authIdentities)` is a
 * supported way to read - and it does not go through the adapter. Until
 * the columns carried their own codec, `$type<ProviderLink[]>()` promised
 * `addedAt: Date` over a value Postgres handed back as an ISO string:
 * `addedAt.getTime()` threw, `addedAt < new Date()` was always `false`, and
 * `tsc` had been told the opposite. Everything here reads the table directly on
 * purpose; routing through the store would test the layer that was never broken.
 */
suite('the exported tables hand back the types they declare (real Postgres)', () => {
  let pool: Pool
  let db: ReturnType<typeof drizzle>
  let stores: DrizzlePgAdapter
  const ID = authUuidV7()

  beforeAll(async () => {
    const own = (await isolatedDatabaseUrl('pg_table_types')) as string
    pool = new Pool({ connectionString: own })
    await applyPgSchema(pool)
    db = drizzle(pool)
    stores = new DrizzlePgAdapter(own)
  }, 60_000)

  afterAll(async () => {
    await pool?.end()
  })

  beforeEach(async () => {
    await pool.query('TRUNCATE auth_sessions, auth_credentials, auth_identities CASCADE')
    await pool.query(
      `INSERT INTO auth_identities (id, profile, version, email_verified, created_at, updated_at)
       VALUES ($1, $2::jsonb, 1, true, now(), now())`,
      [ID, JSON.stringify({ email: 'tbl@fk.local', username: 'tbl' })],
    )
  })

  it('gives auth_identity_providers.added_at as a Date on a direct select', async () => {
    const addedAt = new Date('2026-01-02T03:04:05.000Z')
    await stores.identities.link(ID, { addedAt, providerId: 'google', providerSub: 'sub-1' })

    // A real `timestamptz` now, not a date inside jsonb: what is under test is the driver handing back a
    // Date rather than the string it read off the wire.
    const [row] = await db.select().from(authIdentityProviders).where(eq(authIdentityProviders.identityId, ID))
    expect(row?.addedAt).toBeInstanceOf(Date)
    expect(row?.addedAt?.getTime()).toBe(addedAt.getTime())
  })

  it('gives factors[].completedAt and both actingAs dates as Dates on a direct select', async () => {
    const completedAt = new Date('2026-01-02T03:04:05.000Z')
    const startedAt = new Date('2026-01-02T03:00:00.000Z')
    const expiresAt = new Date('2026-01-02T04:00:00.000Z')
    const id = sessionId('table-types')
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
    expect(row?.actingAs?.startedAt.getTime()).toBe(startedAt.getTime())
    expect(row?.actingAs?.expiresAt.getTime()).toBe(expiresAt.getTime())
  })

  /** The column is `NOT NULL jsonb` and nothing more, so a hand-run `UPDATE` can leave an unreadable date in it.
   *  Handled the opposite way to a provider link, which is kept at the epoch because dropping it would remove a
   *  way into the account: an impersonation window whose end cannot be read is not one anyone should be inside.
   *  Which is why answering `null` was wrong - `null` is "never an impersonation", so it left the session inside
   *  no window at all, read as the person being impersonated. The whole row is refused instead, as redis does. */
  it('refuses a session whose actingAs dates are unreadable rather than reading it as no impersonation', async () => {
    const id = sessionId('acting-corrupt')
    await stores.sessions.create(
      sessionInput({
        aal: 1,
        absoluteExpiresAt: new Date(Date.now() + 600_000),
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 60_000),
        factors: [],
        fresh: true,
        id,
        identityId: ID,
        kind: 'user',
        rotatedAt: new Date(),
      }),
    )
    await pool.query(`UPDATE auth_sessions SET acting_as = $1::jsonb WHERE id = $2`, [
      JSON.stringify({ expiresAt: 'nope', realIdentityId: ID, reason: 'support', startedAt: 'nope' }),
      id,
    ])

    await expect(db.select().from(authSessions).where(eq(authSessions.id, id))).rejects.toMatchObject({
      code: 'AUTH_SESSION_REVOKED',
    })
  })
})
