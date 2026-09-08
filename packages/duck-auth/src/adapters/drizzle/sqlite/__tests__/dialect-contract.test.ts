/**
 * Store-contract cases the shared compliance matrix does not reach.
 *
 * `compliance.test.ts` next door proves the dialect answers the same shapes as
 * every other adapter. What it cannot prove is the handful of semantics where a
 * dialect had drifted from the memory adapter without any shared assertion
 * noticing - a link that appends where another replaces, a soft delete that
 * re-stamps its own grace window, a `gc` that reads one of the two expiry
 * columns. Those live here, written against SQLite because it is the only
 * dialect that runs without a container; pg and mysql carry the same fixes and
 * are covered by their own e2e suites.
 */

import { createHash } from 'node:crypto'
import { eq } from 'drizzle-orm'
import { beforeEach, describe, expect, it } from 'vitest'
import { createSqlStores } from '~/adapters/sql/sql'
import type { Sessions } from '~/core/sessions/sessions.types'
import { SQLITE_DDL as DDL } from '~/test/sqlite-schema'
import { credentialInput, identityInput, sessionInput } from '~/test/store-inputs'
import { createDrizzleSqliteBridge } from '../sqlite'
import { authIdentities, authSessions } from '../sqlite.schema'

type Profile = { username: string; email: string }

const OWNER = 'identity-under-test'

/** `chk_auth_sessions_id_length` demands exactly 64 chars, as every real sid is. */
const sessionId = (label: string) => createHash('sha256').update(label).digest('hex')

async function makeStores(): Promise<ReturnType<typeof createSqlStores<Profile>>> {
  const { default: Database } = await import('better-sqlite3')
  const { drizzle } = await import('drizzle-orm/better-sqlite3')
  const sqlite = new Database(':memory:')
  sqlite.exec(DDL)
  // Sessions and credentials below carry a foreign key to this row; the tests
  // plant the id rather than creating the identity, so it is seeded here.
  sqlite.exec(
    `INSERT INTO auth_identities (id, profile, providers, version, email_verified, created_at, updated_at)
     VALUES ('${OWNER}', '{"email":"owner@fk.local","username":"owner"}', '[]', 1, 1, 0, 0)`,
  )
  // biome-ignore lint/suspicious/noExplicitAny: better-sqlite3 Database is structurally the drizzle client.
  return createSqlStores<Profile>(createDrizzleSqliteBridge(drizzle(sqlite as any)))
}

const profile = (name: string): Profile => ({ email: `${name}@x.com`, username: name })

describe('DrizzleSqlite store-contract divergences', () => {
  let stores: ReturnType<typeof createSqlStores<Profile>>

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

    it('a soft-deleted row frees its address, and update surfaces the clash typed', async () => {
      const first = await stores.identities.create(identityInput({ profile: profile('holder') }))
      const second = await stores.identities.create(identityInput({ profile: profile('other') }))
      // Control: the indexes are partial on deletedAt, so hiding one must let
      // the address be reused - otherwise the refusals above prove nothing more
      // than that the column is unique unconditionally.
      await stores.identities.softDelete(first.id, 60_000)
      await expect(stores.identities.create(identityInput({ profile: profile('holder') }))).resolves.toBeDefined()
      // Only the address collides - `profile('holder')` would trip the username
      // index too, and which of the two a dialect reports first is its own
      // business, not something to pin.
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
        code: 'AUTH_PROVIDER_FAILED',
      })
      // The takeover attempt left no trace on either row.
      expect((await stores.identities.findById(attacker.id))?.providers).toHaveLength(0)
      expect((await stores.identities.findByProviderSub('oauth:google', 'sub-1'))?.id).toBe(holder.id)
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

    it('leaves a null-sub link (password) linkable by more than one identity', async () => {
      const a = await stores.identities.create(identityInput({ profile: profile('pa') }))
      const b = await stores.identities.create(identityInput({ profile: profile('pb') }))
      const link = { addedAt: new Date(), providerId: 'password', providerSub: null }
      await stores.identities.link(a.id, link)

      expect((await stores.identities.link(b.id, link))?.providers).toHaveLength(1)
    })

    it('is idempotent on an exact repeat of (providerId, providerSub)', async () => {
      const i = await stores.identities.create(identityInput({ profile: profile('idem') }))
      const link = { addedAt: new Date(), providerId: 'oauth:google', providerSub: 'sub-2' }
      await stores.identities.link(i.id, link)

      const again = await stores.identities.link(i.id, link)
      expect(again?.providers).toHaveLength(1)
    })

    it('appends a second link for the same providerId with a different sub', async () => {
      const i = await stores.identities.create(identityInput({ profile: profile('two') }))
      await stores.identities.link(i.id, { addedAt: new Date(), providerId: 'oauth:google', providerSub: 'sub-a' })

      const both = await stores.identities.link(i.id, {
        addedAt: new Date(),
        providerId: 'oauth:google',
        providerSub: 'sub-b',
      })
      expect(both?.providers.map((p) => p.providerSub).sort()).toEqual(['sub-a', 'sub-b'])
    })
  })

  describe('identities.softDelete', () => {
    it('answers null for an already-deleted row without pushing its purge deadline out', async () => {
      const i = await stores.identities.create(identityInput({ profile: profile('sd') }))
      // A grace window that has already closed: the row is queued for purge.
      expect(await stores.identities.softDelete(i.id, -60_000)).not.toBeNull()

      expect(await stores.identities.softDelete(i.id, 10 * 60_000)).toBeNull()

      // The second call must not have re-opened the window a purge is waiting on.
      await expect(stores.identities.restore(i.id)).rejects.toMatchObject({ code: 'AUTH_GRACE_EXPIRED' })
    })
  })

  describe('identities.merge', () => {
    it('merging a row into itself is a no-op that keeps the row', async () => {
      const i = await stores.identities.create(identityInput({ profile: profile('self') }))
      await stores.identities.link(i.id, { addedAt: new Date(), providerId: 'oauth:google', providerSub: 'sub-s' })

      const merged = await stores.identities.merge(i.id, i.id)

      expect(merged?.id).toBe(i.id)
      expect(merged?.providers).toHaveLength(1)
      expect(await stores.identities.findById(i.id)).not.toBeNull()
    })
  })

  describe('identities.restoreMany', () => {
    it('reports a closed grace window as a per-row failure instead of restoring it', async () => {
      const live = await stores.identities.create(identityInput({ profile: profile('rl') }))
      const expired = await stores.identities.create(identityInput({ profile: profile('rx') }))
      await stores.identities.softDelete(live.id, 60_000)
      // A negative grace period puts the purge deadline in the past, which is
      // what `restore` refuses with AUTH_GRACE_EXPIRED.
      await stores.identities.softDelete(expired.id, -60_000)

      const result = await stores.identities.restoreMany?.([live.id, expired.id])

      expect(result?.applied).toBe(1)
      expect(result?.outcomes[1]).toMatchObject({ id: expired.id, ok: false })
      expect(await stores.identities.findById(expired.id)).toBeNull()
      expect(await stores.identities.findById(live.id)).not.toBeNull()
    })

    it('refuses a row whose address a live identity has taken since', async () => {
      const hidden = await stores.identities.create(identityInput({ profile: profile('claimed') }))
      await stores.identities.softDelete(hidden.id, 60_000)
      await stores.identities.create(identityInput({ profile: { email: 'claimed@x.com', username: 'squatter' } }))

      const result = await stores.identities.restoreMany?.([hidden.id])

      expect(result?.applied).toBe(0)
      expect(await stores.identities.findById(hidden.id)).toBeNull()
    })

    it('admits only one of two batched rows that share an address', async () => {
      const a = await stores.identities.create(identityInput({ profile: profile('twin') }))
      const b = await stores.identities.create(identityInput({ profile: profile('other') }))
      await stores.identities.softDelete(a.id, 60_000)
      await stores.identities.softDelete(b.id, 60_000)
      // Both hidden rows now answer to the same address, which only one of them
      // can hold once they are live again.
      await stores.identities.update(b.id, { profile: { email: 'twin@x.com', username: 'other' } }, b.version)

      const result = await stores.identities.restoreMany?.([a.id, b.id])

      expect(result?.applied).toBe(1)
      expect(result?.failed).toBe(1)
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
      expect(await stores.sessions.getByHash(sessionId('idle-expired'))).toBeNull()
      expect(await stores.sessions.getByHash(sessionId('live'))).not.toBeNull()
    })
  })

  describe('credentials.findByProviderSub', () => {
    it('ignores a non-oauth credential carrying the same provider/sub metadata', async () => {
      await stores.credentials.upsert(
        credentialInput({
          identityId: OWNER,
          kind: 'api-key',
          metadata: { provider: 'google', sub: 'sub-1' },
          secret: 'k',
        }),
        {},
      )

      expect(await stores.credentials.findByProviderSub('google', 'sub-1', {})).toBeNull()
    })

    it('is scoped to the calling tenant', async () => {
      await stores.credentials.upsert(
        credentialInput({
          identityId: OWNER,
          kind: 'oauth',
          metadata: { provider: 'google', sub: 'sub-2' },
          secret: 'o',
          tenantId: 'tenant-a',
        }),
        {},
      )

      expect(await stores.credentials.findByProviderSub('google', 'sub-2', { tenantId: 'tenant-b' })).toBeNull()
      expect(await stores.credentials.findByProviderSub('google', 'sub-2', { tenantId: 'tenant-a' })).not.toBeNull()
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
      await expect(stores.credentials.patchMetadata('nope', { a: 1 }, {})).rejects.toMatchObject({
        code: 'AUTH_STALE_WRITE',
      })
    })
  })

  describe('credentials.rotate', () => {
    it('stamps lastUsedAt on the same write that changes the secret', async () => {
      const c = await stores.credentials.upsert(
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
 * supported read that never touches `createSqlStores`. SQLite stores these
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
      `INSERT INTO auth_identities (id, profile, providers, version, email_verified, created_at, updated_at)
       VALUES ('${OWNER}', '{"email":"owner@fk.local","username":"owner"}', '[]', 1, 1, 0, 0)`,
    )
    // biome-ignore lint/suspicious/noExplicitAny: better-sqlite3 Database is structurally the drizzle client.
    const db = drizzle(sqlite as any)
    return { db, sqlite, stores: createSqlStores<Profile>(createDrizzleSqliteBridge(db)) }
  }

  it('gives providers[].addedAt as a Date on a direct select', async () => {
    const { db, stores } = await makeDb()
    const addedAt = new Date('2026-01-02T03:04:05.000Z')
    await stores.identities.link(OWNER, { addedAt, providerId: 'google', providerSub: 'sub-1' })

    const [row] = await db.select().from(authIdentities).where(eq(authIdentities.id, OWNER))
    expect(row?.providers[0]?.addedAt).toBeInstanceOf(Date)
    expect(row?.providers[0]?.addedAt?.getTime()).toBe(addedAt.getTime())
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

  it('reads an unparseable addedAt as null at the table and as createdAt through the store', async () => {
    const { db, sqlite, stores } = await makeDb()
    sqlite.exec(
      `UPDATE auth_identities SET providers = '${JSON.stringify([
        { addedAt: 'not-a-date', providerId: 'google', providerSub: 'sub-1' },
      ])}' WHERE id = '${OWNER}'`,
    )

    const [row] = await db.select().from(authIdentities).where(eq(authIdentities.id, OWNER))
    expect(row?.providers[0]?.addedAt).toBeNull()

    const viaStore = await stores.identities.findById(OWNER)
    expect(viaStore?.providers[0]?.addedAt).toBeInstanceOf(Date)
    expect(viaStore?.providers[0]?.addedAt.getTime()).toBe(row?.createdAt.getTime())
  })

  /** A column holding text that is not JSON at all reads as empty, not as a throw. */
  it('answers [] for a providers column that is not JSON', async () => {
    const { db, sqlite } = await makeDb()
    sqlite.exec(`UPDATE auth_identities SET providers = 'not json' WHERE id = '${OWNER}'`)
    const [row] = await db.select().from(authIdentities).where(eq(authIdentities.id, OWNER))
    expect(row?.providers).toEqual([])
  })
})
