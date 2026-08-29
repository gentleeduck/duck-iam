/**
 * Store-contract compliance for the Drizzle Postgres adapter, against REAL Postgres.
 *
 * This adapter shipped with no cross-adapter coverage at all. The matrix ran on
 * memory and sqlite only, and the sqlite run deliberately drops every CHECK
 * constraint "so the suite exercises store behaviour, not dialect-level column
 * checks" - which leaves the shipped Postgres schema, the one production writes
 * to, unproven. That exemption is the same one that let four defects survive in
 * the Redis session store.
 *
 * Everything below the matrix is dialect-specific: behaviour that exists only
 * because the column is `jsonb`, or `timestamptz`, or carries a CHECK, a partial
 * unique index, or a CASCADE. None of it can be observed on sqlite or in memory.
 *
 * Skips when DUCKAUTH_E2E_DATABASE_URL is unset; `globalSetup` provisions a
 * container when docker is available.
 */
import { createHash, randomUUID } from 'node:crypto'
import { Pool } from 'pg'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { applyPgSchema, databaseUrl, isolatedDatabaseUrl } from '~/test/e2e-env'
import {
  runCredentialStoreCompliance,
  runIdentityStoreCompliance,
  runSessionStoreCompliance,
} from '~/test/store-compliance'
import { credentialInput, identityInput, sessionInput } from '~/test/store-inputs'
import { drizzlePgStorage } from '../index'

const URL = databaseUrl()
const suite = URL ? describe : describe.skip

type Profile = { username: string; email: string }

/** `chk_auth_sessions_id_length` demands exactly 64 chars, as every real sid is. */
const sessionId = (label: string) => createHash('sha256').update(label).digest('hex')

/** `auth_identities.id` is `uuid`, and sessions/credentials carry an FK to it. */
const OWNER = randomUUID()
const OTHER = randomUUID()

suite('DrizzlePg compliance matrix (real Postgres)', () => {
  let pool: Pool
  let stores: ReturnType<typeof drizzlePgStorage<Profile>>

  beforeAll(async () => {
    // Owned database: this suite truncates between cases, and the other pg suites
    // run in parallel workers against the shared one.
    const own = (await isolatedDatabaseUrl('pg_compliance')) as string
    pool = new Pool({ connectionString: own })
    await applyPgSchema(pool)
    stores = drizzlePgStorage<Profile>(own)
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
    await pool.query('TRUNCATE auth_events, auth_sessions, auth_credentials, auth_identities CASCADE')
    for (const [id, name] of [
      [OWNER, 'owner'],
      [OTHER, 'other'],
    ]) {
      await pool.query(
        `INSERT INTO auth_identities (id, profile, providers, version, email_verified, created_at, updated_at)
         VALUES ($1, $2::jsonb, '[]'::jsonb, 1, true, now(), now())`,
        [id, JSON.stringify({ email: `${name}@fk.local`, username: name })],
      )
    }
  })

  runIdentityStoreCompliance<Profile>(() => stores.identities)
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
      const final = await stores.identities.findById(created.id)
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

  describe('partial unique indexes on the profile jsonb', () => {
    it('refuses a second live identity with the same email', async () => {
      await stores.identities.create(identityInput<Profile>({ profile: { email: 'dup@x.com', username: 'dup-a' } }))
      await expect(
        stores.identities.create(identityInput<Profile>({ profile: { email: 'dup@x.com', username: 'dup-b' } })),
      ).rejects.toThrow()
    })

    it('treats email case-insensitively, because the index is on lower()', async () => {
      await stores.identities.create(identityInput<Profile>({ profile: { email: 'Case@X.com', username: 'case-a' } }))
      await expect(
        stores.identities.create(identityInput<Profile>({ profile: { email: 'case@x.com', username: 'case-b' } })),
      ).rejects.toThrow()
    })

    it('refuses a duplicate username case-insensitively too', async () => {
      await stores.identities.create(identityInput<Profile>({ profile: { email: 'u1@x.com', username: 'Taken' } }))
      await expect(
        stores.identities.create(identityInput<Profile>({ profile: { email: 'u2@x.com', username: 'taken' } })),
      ).rejects.toThrow()
    })

    it('frees the address once the holder is soft-deleted, because the index is partial', async () => {
      // `WHERE deleted_at IS NULL`: a soft-deleted row must stop reserving its
      // address, or an account deletion locks the email out forever.
      const first = await stores.identities.create(
        identityInput<Profile>({ profile: { email: 'reuse@x.com', username: 'reuse-a' } }),
      )
      await stores.identities.softDelete(first.id, 60_000)
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
      expect(await stores.identities.findByEmail('hidden@x.com')).toBeNull()
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
      const read = await stores.identities.findById(created.id)
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
      const c = await stores.credentials.upsert(
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
      const read = await stores.identities.findById(created.id)
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
      expect(await stores.sessions.getByHash(id)).toBeNull()
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
            identityId: randomUUID(),
            kind: 'user',
            rotatedAt: now,
          }),
        ),
      ).rejects.toThrow()
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
      ).rejects.toThrow()
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
      ).rejects.toThrow()
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
      ).rejects.toThrow()
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
      ).rejects.toThrow()
    })

    it('refuses a profile missing the required keys', async () => {
      // `chk_auth_identities_profile_shape` requires username + email to exist.
      await expect(
        // biome-ignore lint/suspicious/noExplicitAny: violating the typed shape on purpose
        stores.identities.create(identityInput<Profile>({ profile: { nickname: 'nope' } as any })),
      ).rejects.toThrow()
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
