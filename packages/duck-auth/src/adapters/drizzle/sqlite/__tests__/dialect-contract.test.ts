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

import { beforeEach, describe, expect, it } from 'vitest'
import { createSqlStores } from '~/adapters/sql/sql'
import type { Sessions } from '~/core/sessions/sessions.types'
import { credentialInput, identityInput, sessionInput } from '~/test/store-inputs'
import { createDrizzleSqliteBridge } from '../sqlite'

const DDL = `
CREATE TABLE auth_identities (
  id TEXT PRIMARY KEY, tenant_id TEXT, profile TEXT NOT NULL,
  providers TEXT NOT NULL DEFAULT '[]', version INTEGER NOT NULL DEFAULT 1,
  email_verified INTEGER NOT NULL DEFAULT 0, created_by TEXT, updated_by TEXT,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, deleted_at INTEGER);
CREATE TABLE auth_credentials (
  id TEXT PRIMARY KEY, identity_id TEXT NOT NULL, tenant_id TEXT, kind TEXT NOT NULL,
  secret TEXT NOT NULL, metadata TEXT, version INTEGER NOT NULL DEFAULT 1, created_by TEXT,
  updated_by TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
  last_used_at INTEGER, expires_at INTEGER, revoked_at INTEGER);
CREATE TABLE auth_sessions (
  id TEXT PRIMARY KEY, identity_id TEXT, tenant_id TEXT, kind TEXT NOT NULL, aal INTEGER NOT NULL,
  factors TEXT NOT NULL DEFAULT '[]', csrf_hash TEXT, ip TEXT, user_agent TEXT, fingerprint TEXT,
  created_by TEXT, updated_by TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
  rotated_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  absolute_expires_at INTEGER NOT NULL, fresh INTEGER NOT NULL, acting_as TEXT);
`

type Profile = { username: string; email: string }

const OWNER = 'identity-under-test'

async function makeStores(): Promise<ReturnType<typeof createSqlStores<Profile>>> {
  const { default: Database } = await import('better-sqlite3')
  const { drizzle } = await import('drizzle-orm/better-sqlite3')
  const sqlite = new Database(':memory:')
  sqlite.exec(DDL)
  // biome-ignore lint/suspicious/noExplicitAny: better-sqlite3 Database is structurally the drizzle client.
  return createSqlStores<Profile>(createDrizzleSqliteBridge(drizzle(sqlite as any)))
}

const profile = (name: string): Profile => ({ email: `${name}@x.com`, username: name })

describe('DrizzleSqlite store-contract divergences', () => {
  let stores: ReturnType<typeof createSqlStores<Profile>>

  beforeEach(async () => {
    stores = await makeStores()
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
          id: 'idle-expired',
        }),
      )
      await stores.sessions.create(
        sessionInput({
          ...base,
          absoluteExpiresAt: new Date(nowMs + 60_000),
          expiresAt: new Date(nowMs + 60_000),
          id: 'live',
        }),
      )

      expect((await stores.sessions.gc(nowMs)).deleted).toBe(1)
      expect(await stores.sessions.getByHash('idle-expired')).toBeNull()
      expect(await stores.sessions.getByHash('live')).not.toBeNull()
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
