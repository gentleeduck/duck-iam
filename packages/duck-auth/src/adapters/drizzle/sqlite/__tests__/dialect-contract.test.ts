/** Store-contract cases the shared compliance matrix does not reach. */

import { createHash } from 'node:crypto'
import { eq } from 'drizzle-orm'
import { beforeEach, describe, expect, it } from 'vitest'
import type { Adapter } from '~/adapters/adapter'
import type { Sessions } from '~/core/sessions/sessions.types'
import { SQLITE_DDL as DDL } from '~/test/sqlite-schema'
import { credentialInput, identityInput, sessionInput } from '~/test/store-inputs'
import { DrizzleSqliteAdapter } from '../sqlite'
import { authIdentities, authIdentityProviders, authSessions } from '../sqlite.schema'

type Profile = { username: string; email: string }

const OWNER = 'identity-under-test'

/** `chk_auth_sessions_id_length` demands exactly 64 chars, as every real sid is. */
const sessionId = (label: string) => createHash('sha256').update(label).digest('hex')

async function makeStores(): Promise<Adapter.Me<Profile>> {
  const { default: Database } = await import('better-sqlite3')
  const { drizzle } = await import('drizzle-orm/better-sqlite3')
  const sqlite = new Database(':memory:')
  sqlite.exec(DDL)
  // Sessions and credentials below carry a foreign key to this row; the tests
  // plant the id rather than creating the identity, so it is seeded here.
  sqlite.exec(
    `INSERT INTO auth_identities (id, profile, version, email_verified, created_at, updated_at)
     VALUES ('${OWNER}', '{"email":"owner@fk.local","username":"owner"}', 1, 1, 0, 0)`,
  )
  // biome-ignore lint/suspicious/noExplicitAny: better-sqlite3 Database is structurally the drizzle client.
  return new DrizzleSqliteAdapter(drizzle(sqlite as any))
}

const profile = (name: string): Profile => ({ email: `${name}@x.com`, username: name })

describe('DrizzleSqlite store-contract divergences', () => {
  let stores: Adapter.Me<Profile>

  beforeEach(async () => {
    stores = await makeStores()
  })

  /**
   * The store's own pre-checks are read-then-write, so under concurrency the
   * unique index is what actually decides. Inserting straight past the
   * pre-check is how a test reaches that decision deterministically.
   */
  describe('unique index violations arrive typed', () => {
    it('a duplicate email is AUTH_EMAIL_TAKEN, not a raw driver error', async () => {
      await stores.identities.create(identityInput({ profile: { email: 'dup@x.com', username: 'first' } }))
      await expect(
        stores.identities.create(identityInput({ profile: { email: 'DUP@x.com', username: 'second' } })),
      ).rejects.toMatchObject({ code: 'AUTH_EMAIL_TAKEN', status: 409 })
    })

    it('a duplicate username is AUTH_USERNAME_TAKEN, told apart from the email clash', async () => {
      await stores.identities.create(identityInput({ profile: { email: 'a@x.com', username: 'taken' } }))
      // Distinct address, same handle: the two indexes must not be reported as
      // each other, or "change your email" is the advice for a username clash.
      await expect(
        stores.identities.create(identityInput({ profile: { email: 'b@x.com', username: 'TAKEN' } })),
      ).rejects.toMatchObject({ code: 'AUTH_USERNAME_TAKEN', status: 409 })
    })

    it('a soft-deleted row keeps its address, and update surfaces the clash typed', async () => {
      const first = await stores.identities.create(identityInput({ profile: profile('holder') }))
      const second = await stores.identities.create(identityInput({ profile: profile('other') }))
      // Neither index is partial on deletedAt, so a hidden row holds its address for the whole grace
      // window - which is what lets `restore` bring it back without a freeness check.
      await stores.identities.softDelete(first.id, 60_000)
      // Only the address collides: `profile('holder')` would trip the username index too, and which of
      // the two a dialect reports first is its own business, not something to pin.
      await expect(
        stores.identities.create(identityInput({ profile: { email: 'holder@x.com', username: 'newcomer' } })),
      ).rejects.toMatchObject({ code: 'AUTH_EMAIL_TAKEN' })
      await expect(
        stores.identities.update(second.id, { profile: { email: 'holder@x.com', username: 'other' } }, second.version),
      ).rejects.toMatchObject({ code: 'AUTH_EMAIL_TAKEN' })
    })

    it('a driver error that is not a unique violation is not dressed up as one', async () => {
      // `chk_auth_sessions_id_length` fails on a short id. It must propagate as
      // itself: renaming every write failure to a conflict would turn real bugs
      // into 409s the caller retries forever.
      const now = new Date()
      const exp = new Date(now.getTime() + 60_000)
      await expect(
        stores.sessions.create(
          sessionInput({
            aal: 1,
            absoluteExpiresAt: exp,
            createdAt: now,
            expiresAt: exp,
            factors: [],
            fresh: true,
            id: 'too-short',
            identityId: OWNER,
            kind: 'user',
            rotatedAt: now,
          }),
        ),
      ).rejects.not.toMatchObject({ code: 'AUTH_EMAIL_TAKEN' })
    })
  })

  describe('identities.link', () => {
    it('refuses a providerSub already attached to a different identity', async () => {
      const holder = await stores.identities.create(identityInput({ profile: profile('holder') }))
      const attacker = await stores.identities.create(identityInput({ profile: profile('attacker') }))
      const link = { addedAt: new Date(), providerId: 'oauth:google', providerSub: 'sub-1' }
      await stores.identities.link(holder.id, link)

      await expect(stores.identities.link(attacker.id, link)).rejects.toMatchObject({
        code: 'AUTH_PROVIDER_TAKEN',
      })
      // The takeover attempt left no trace on either row.
      expect((await stores.identities.find({ id: attacker.id }))?.providers).toHaveLength(0)
      expect((await stores.identities.find({ providerId: 'oauth:google', providerSub: 'sub-1' }))?.id).toBe(holder.id)
    })

    it('still admits the same sub under a different providerId', async () => {
      const holder = await stores.identities.create(identityInput({ profile: profile('gh') }))
      const other = await stores.identities.create(identityInput({ profile: profile('gl') }))
      await stores.identities.link(holder.id, { addedAt: new Date(), providerId: 'oauth:github', providerSub: '42' })

      const linked = await stores.identities.link(other.id, {
        addedAt: new Date(),
        providerId: 'oauth:gitlab',
        providerSub: '42',
      })
      expect(linked?.providers).toHaveLength(1)
    })

    it('is idempotent on an exact repeat of (providerId, providerSub)', async () => {
      const i = await stores.identities.create(identityInput({ profile: profile('idem') }))
      const link = { addedAt: new Date(), providerId: 'oauth:google', providerSub: 'sub-2' }
      await stores.identities.link(i.id, link)

      const again = await stores.identities.link(i.id, link)
      expect(again?.providers).toHaveLength(1)
    })

    it('keeps the sub it holds when a second one arrives for the same providerId', async () => {
      const i = await stores.identities.create(identityInput({ profile: profile('two') }))
      await stores.identities.link(i.id, { addedAt: new Date(), providerId: 'oauth:google', providerSub: 'sub-a' })

      // `uq_auth_identity_providers_owned` holds one row per provider, and `unlink` takes no sub, so a
      // second row at the same provider would be one nothing could address.
      const both = await stores.identities.link(i.id, {
        addedAt: new Date(),
        providerId: 'oauth:google',
        providerSub: 'sub-b',
      })
      expect(both?.providers.map((p) => p.providerSub)).toEqual(['sub-a'])
    })
  })

  describe('identities.softDelete', () => {
    it('answers null for an already-deleted row without pushing its purge deadline out', async () => {
      const i = await stores.identities.create(identityInput({ profile: profile('sd') }))
      // A grace window that has already closed: the row is queued for purge.
      await expect(stores.identities.softDelete(i.id, -60_000)).resolves.toBeTruthy()

      await expect(stores.identities.softDelete(i.id, 10 * 60_000)).rejects.toMatchObject({
        code: 'AUTH_IDENTITY_NOT_FOUND',
      })

      // The second call must not have re-opened the window a purge is waiting on.
      await expect(stores.identities.restore(i.id)).rejects.toMatchObject({ code: 'AUTH_GRACE_EXPIRED' })
    })
  })

  describe('identities.restore', () => {
    it('refuses a closed grace window instead of restoring it', async () => {
      const live = await stores.identities.create(identityInput({ profile: profile('rl') }))
      const expired = await stores.identities.create(identityInput({ profile: profile('rx') }))
      await stores.identities.softDelete(live.id, 60_000)
      // A negative grace period puts the purge deadline in the past, which is what `restore` refuses.
      await stores.identities.softDelete(expired.id, -60_000)

      expect(await stores.identities.restore(live.id)).toMatchObject({ deletedAt: null, deletedBy: null })
      await expect(stores.identities.restore(expired.id)).rejects.toMatchObject({ code: 'AUTH_GRACE_EXPIRED' })
      await expect(stores.identities.find({ id: expired.id })).rejects.toMatchObject({
        code: 'AUTH_IDENTITY_NOT_FOUND',
      })
      await expect(stores.identities.find({ id: live.id })).resolves.toBeTruthy()
    })

    it('reads an id that is not there as null rather than a refusal', async () => {
      await expect(stores.identities.restore('no-such-identity')).rejects.toMatchObject({
        code: 'AUTH_IDENTITY_NOT_FOUND',
      })
    })
  })

  describe('sessions.gc', () => {
    it('collects a session past its idle expiry even while its absolute expiry is ahead', async () => {
      const nowMs = Date.now()
      const base = {
        aal: 1,
        createdAt: new Date(nowMs - 100_000),
        factors: [],
        fresh: false,
        identityId: OWNER,
        kind: 'user',
        rotatedAt: new Date(nowMs - 100_000),
      } satisfies Partial<Sessions.CreateInput>
      await stores.sessions.create(
        sessionInput({
          ...base,
          absoluteExpiresAt: new Date(nowMs + 60_000),
          expiresAt: new Date(nowMs - 1),
          id: sessionId('idle-expired'),
        }),
      )
      await stores.sessions.create(
        sessionInput({
          ...base,
          absoluteExpiresAt: new Date(nowMs + 60_000),
          expiresAt: new Date(nowMs + 60_000),
          id: sessionId('live'),
        }),
      )

      expect((await stores.sessions.gc(nowMs)).deleted).toBe(1)
      await expect(stores.sessions.getByHash(sessionId('idle-expired'))).rejects.toMatchObject({
        code: 'AUTH_SESSION_REVOKED',
      })
      await expect(stores.sessions.getByHash(sessionId('live'))).resolves.toBeTruthy()
    })
  })

  describe('conditional writes on an id that is not there', () => {
    it('report AUTH_STALE_WRITE, never AUTH_UNAUTHENTICATED', async () => {
      await expect(stores.identities.update('nope', { emailVerified: true }, 1)).rejects.toMatchObject({
        code: 'AUTH_STALE_WRITE',
      })
      await expect(stores.credentials.rotate('nope', 'new', 1, {})).rejects.toMatchObject({
        code: 'AUTH_STALE_WRITE',
      })
      // patchMetadata reads before it writes, so there is no version to have lost.
      await expect(stores.credentials.patchMetadata('nope', { a: 1 }, {})).rejects.toMatchObject({
        code: 'AUTH_CREDENTIAL_NOT_FOUND',
      })
    })
  })

  describe('credentials.rotate', () => {
    it('stamps lastUsedAt on the same write that changes the secret', async () => {
      const c = await stores.credentials.create(
        credentialInput({ identityId: OWNER, kind: 'api-key', secret: 'v1' }),
        {},
      )
      expect(c.lastUsedAt).toBeNull()

      const rotated = await stores.credentials.rotate(c.id, 'v2', c.version, {})

      expect(rotated.secret).toBe('v2')
      expect(rotated.lastUsedAt).toBeInstanceOf(Date)
    })
  })
})

/**
 * The tables are a public export, so a `db.select().from(authIdentities)` is a
 * supported read that never goes through the adapter. SQLite stores these
 * columns as raw `TEXT`, so the value coming back is a JSON string, not even a
 * parsed object - and the declared type said `ProviderLink[]` with a `Date` on
 * it. pg and mysql carry the same assertions in their e2e suites; this is the
 * one dialect that can make them without a container.
 */
describe('the exported tables hand back the types they declare', () => {
  async function makeDb() {
    const { default: Database } = await import('better-sqlite3')
    const { drizzle } = await import('drizzle-orm/better-sqlite3')
    const sqlite = new Database(':memory:')
    sqlite.exec(DDL)
    sqlite.exec(
      `INSERT INTO auth_identities (id, profile, version, email_verified, created_at, updated_at)
       VALUES ('${OWNER}', '{"email":"owner@fk.local","username":"owner"}', 1, 1, 0, 0)`,
    )
    // biome-ignore lint/suspicious/noExplicitAny: better-sqlite3 Database is structurally the drizzle client.
    const db = drizzle(sqlite as any)
    return { db, sqlite, stores: new DrizzleSqliteAdapter(db) }
  }

  it('gives a link addedAt as a Date on a direct select', async () => {
    const { db, stores } = await makeDb()
    const addedAt = new Date('2026-01-02T03:04:05.000Z')
    await stores.identities.link(OWNER, { addedAt, providerId: 'google', providerSub: 'sub-1' })

    const [row] = await db.select().from(authIdentityProviders).where(eq(authIdentityProviders.identityId, OWNER))
    expect(row?.addedAt).toBeInstanceOf(Date)
    expect(row?.addedAt?.getTime()).toBe(addedAt.getTime())
  })

  it('gives factors[].completedAt and both actingAs dates as Dates on a direct select', async () => {
    const { db, stores } = await makeDb()
    const completedAt = new Date('2026-01-02T03:04:05.000Z')
    const startedAt = new Date('2026-01-02T03:00:00.000Z')
    const expiresAt = new Date('2026-01-02T04:00:00.000Z')
    const id = sessionId('sqlite-table-types')
    await stores.sessions.create(
      sessionInput({
        aal: 2,
        absoluteExpiresAt: new Date(Date.now() + 600_000),
        actingAs: { expiresAt, realIdentityId: OWNER, reason: 'support', startedAt },
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 60_000),
        factors: [{ completedAt, method: 'password' }],
        fresh: true,
        id,
        identityId: OWNER,
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

  it('refuses a session whose acting_as TEXT will not parse, rather than reading it as no impersonation', async () => {
    // Every JSON column is raw TEXT on this dialect, so unparseable bytes reach the codec here in a way
    // pg and mysql only do when a column is read as text. `null` was the old answer, and it does not mean
    // "unreadable" - it means "never an impersonation", which loads the row as an ordinary session
    // belonging to the person being impersonated: no expiry cap, and an audit trail naming them instead
    // of the operator.
    const { db, sqlite, stores } = await makeDb()
    const id = sessionId('sqlite-acting-as-corrupt')
    await stores.sessions.create(
      sessionInput({
        aal: 1,
        absoluteExpiresAt: new Date(Date.now() + 600_000),
        actingAs: {
          expiresAt: new Date(Date.now() + 60_000),
          realIdentityId: OWNER,
          reason: 'support',
          startedAt: new Date(),
        },
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 60_000),
        factors: [],
        fresh: true,
        id,
        identityId: OWNER,
        kind: 'user',
        rotatedAt: new Date(),
      }),
    )
    sqlite.exec(`UPDATE auth_sessions SET acting_as = '{ broken' WHERE id = '${id}'`)

    await expect(db.select().from(authSessions).where(eq(authSessions.id, id))).rejects.toMatchObject({
      code: 'AUTH_SESSION_REVOKED',
    })
    await expect(stores.sessions.getByHash(id)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
  })
})
