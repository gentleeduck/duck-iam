import { describe, expect, it } from 'vitest'
import type { AuthCredential } from '../../core/types/credential'
import type { AuthIdentity } from '../../core/types/identity'
import type { AuthSession } from '../../core/types/session'

/**
 * AuthCompliance test matrix for AuthIdentity stores. Every shipped adapter (memory,
 * redis, drizzle, prisma) imports this and runs it against a fresh instance;
 * the same assertions guarantee behaviour parity across adapters.
 *
 * @param factory - factory returning a fresh `AuthIdentity.IStore` per test
 */
export function authRunIdentityStoreCompliance<P = { email: string }>(factory: () => AuthIdentity.IStore<P>): void {
  describe('AuthIdentity.IStore compliance', () => {
    it('create stamps id, version=1, createdAt, updatedAt; respects providers + tenantId', async () => {
      const store = factory()
      const i = await store.create(
        {
          profile: { email: 'a@x.com' } as unknown as P,
          providers: [{ providerId: 'password', addedAt: Date.now() }],
        },
        { tenantId: 'T' },
      )
      expect(i.id).toBeTruthy()
      expect(i.version).toBe(1)
      expect(i.tenantId).toBe('T')
      expect(i.providers).toHaveLength(1)
      expect(i.createdAt).toBeGreaterThan(0)
    })

    it('findByEmail honours tenant scoping', async () => {
      const store = factory()
      await store.create({ profile: { email: 'shared@x' } as unknown as P, providers: [] }, { tenantId: 'A' })
      expect(await store.findByEmail('shared@x', { tenantId: 'B' })).toBeNull()
      expect(await store.findByEmail('shared@x', { tenantId: 'A' })).not.toBeNull()
    })

    it('update with expectedVersion mismatch surfaces AUTH/STALE_WRITE', async () => {
      const store = factory()
      const i = await store.create({ profile: { email: 'a@x' } as unknown as P, providers: [] }, {})
      await store.update(i.id, { profile: { email: 'b@x' } as unknown as P }, i.version, {})
      await expect(store.update(i.id, { profile: { email: 'c@x' } as unknown as P }, 1, {})).rejects.toMatchObject({
        code: 'AUTH/STALE_WRITE',
      })
    })

    it('softDelete hides; restore brings back within grace; erase is permanent', async () => {
      const store = factory()
      const i = await store.create({ profile: { email: 'a@x' } as unknown as P, providers: [] }, {})
      await store.softDelete(i.id, 60_000, {})
      expect(await store.findById(i.id, {})).toBeNull()
      const restored = await store.restore(i.id, {})
      expect(restored.id).toBe(i.id)
      await store.erase(i.id, {})
      expect(await store.findById(i.id, {})).toBeNull()
    })

    it('link / unlink mutate providers; findByProviderSub locates linked identities', async () => {
      const store = factory()
      const i = await store.create({ profile: { email: 'a@x' } as unknown as P, providers: [] }, {})
      await store.link(i.id, { providerId: 'oauth:authGoogle', providerSub: 'sub-1', addedAt: Date.now() }, {})
      const found = await store.findByProviderSub('oauth:authGoogle', 'sub-1', {})
      expect(found?.id).toBe(i.id)
      await store.unlink(i.id, 'oauth:authGoogle', {})
      expect(await store.findByProviderSub('oauth:authGoogle', 'sub-1', {})).toBeNull()
    })

    it('merge moves providers from dup into survivor + deletes dup', async () => {
      const store = factory()
      const survivor = await store.create(
        {
          profile: { email: 's@x' } as unknown as P,
          providers: [{ providerId: 'password', addedAt: Date.now() }],
        },
        {},
      )
      const dup = await store.create(
        {
          profile: { email: 'd@x' } as unknown as P,
          providers: [{ providerId: 'oauth:authGoogle', providerSub: 'g', addedAt: Date.now() }],
        },
        {},
      )
      await store.merge(survivor.id, dup.id, {})
      const fresh = await store.findById(survivor.id, {})
      expect(fresh?.providers.some((p) => p.providerId === 'oauth:authGoogle')).toBe(true)
      expect(await store.findById(dup.id, {})).toBeNull()
    })
  })
}

/**
 * AuthCompliance matrix for AuthSession stores. Verifies hashed-key storage,
 * listing, GC purge of expired rows, and per-identity bulk delete.
 */
export function authRunSessionStoreCompliance(factory: () => AuthSession.IStore): void {
  describe('AuthSession.IStore compliance', () => {
    it('create + getByHash roundtrip uses the row id directly', async () => {
      const store = factory()
      const session: AuthSession.ISession = {
        id: 'hash-1',
        identityId: 'u',
        kind: 'user',
        aal: 1,
        factors: [],
        createdAt: Date.now(),
        rotatedAt: Date.now(),
        expiresAt: Date.now() + 60_000,
        absoluteExpiresAt: Date.now() + 60_000,
        fresh: true,
      }
      await store.create(session)
      expect(await store.getByHash('hash-1')).toEqual(session)
    })

    it('listByIdentity returns only sessions of the requested identity', async () => {
      const store = factory()
      const now = Date.now()
      const base = {
        kind: 'user' as const,
        aal: 1 as const,
        factors: [],
        createdAt: now,
        rotatedAt: now,
        expiresAt: now + 60_000,
        absoluteExpiresAt: now + 60_000,
        fresh: true,
      }
      await store.create({ id: 'u-1', identityId: 'u', ...base })
      await store.create({ id: 'u-2', identityId: 'u', ...base })
      await store.create({ id: 'v-1', identityId: 'v', ...base })
      const us = await store.listByIdentity('u')
      expect(us).toHaveLength(2)
    })

    it('deleteAllForIdentity wipes every session for the identity', async () => {
      const store = factory()
      const now = Date.now()
      const base = {
        kind: 'user' as const,
        aal: 1 as const,
        factors: [],
        createdAt: now,
        rotatedAt: now,
        expiresAt: now + 60_000,
        absoluteExpiresAt: now + 60_000,
        fresh: true,
      }
      await store.create({ id: 'a', identityId: 'u', ...base })
      await store.create({ id: 'b', identityId: 'u', ...base })
      await store.deleteAllForIdentity('u')
      expect(await store.listByIdentity('u')).toHaveLength(0)
    })

    it('gc purges sessions with expiresAt or absoluteExpiresAt past now', async () => {
      const store = factory()
      const now = Date.now()
      await store.create({
        id: 'expired',
        identityId: 'u',
        kind: 'user',
        aal: 1,
        factors: [],
        createdAt: now - 100_000,
        rotatedAt: now - 100_000,
        expiresAt: now - 1,
        absoluteExpiresAt: now - 1,
        fresh: false,
      })
      await store.create({
        id: 'live',
        identityId: 'u',
        kind: 'user',
        aal: 1,
        factors: [],
        createdAt: now,
        rotatedAt: now,
        expiresAt: now + 60_000,
        absoluteExpiresAt: now + 60_000,
        fresh: true,
      })
      const r = await store.gc(now)
      expect(r.deleted).toBe(1)
      expect(await store.getByHash('expired')).toBeNull()
      expect(await store.getByHash('live')).not.toBeNull()
    })
  })
}

/**
 * AuthCompliance matrix for AuthCredential stores. Covers upsert + findById +
 * findByHashedSecret semantics (revoked rows distinguished from missing),
 * rotate optimistic-lock, deleteByKind cleanup.
 */
export function authRunCredentialStoreCompliance(factory: () => AuthCredential.IStore): void {
  describe('AuthCredential.IStore compliance', () => {
    it('upsert stamps id + version=1; findById retrieves it', async () => {
      const store = factory()
      const c = await store.upsert({ identityId: 'u', kind: 'password', secret: 'hashed-pw', metadata: {} }, {})
      expect(c.id).toBeTruthy()
      expect(c.version).toBe(1)
      const got = await store.findById(c.id, {})
      expect(got?.secret).toBe('hashed-pw')
    })

    it('findByHashedSecret returns the freshest live row before falling back to revoked', async () => {
      const store = factory()
      const c1 = await store.upsert(
        { identityId: 'u', kind: 'magic-link', secret: 'hash', metadata: {}, expiresAt: Date.now() + 60_000 },
        {},
      )
      await store.revoke(c1.id, {})
      // Same secret hash, but fresh row.
      const c2 = await store.upsert(
        { identityId: 'u', kind: 'magic-link', secret: 'hash', metadata: {}, expiresAt: Date.now() + 60_000 },
        {},
      )
      const got = await store.findByHashedSecret('hash', 'magic-link', {})
      expect(got?.id).toBe(c2.id)
    })

    it('findByHashedSecret falls back to the revoked row when no live rows exist', async () => {
      const store = factory()
      const c = await store.upsert({ identityId: 'u', kind: 'api-key', secret: 'hash-x', metadata: {} }, {})
      await store.revoke(c.id, {})
      const got = await store.findByHashedSecret('hash-x', 'api-key', {})
      expect(got?.revokedAt).toBeTruthy()
    })

    it('rotate with mismatched version surfaces AUTH/STALE_WRITE', async () => {
      const store = factory()
      const c = await store.upsert({ identityId: 'u', kind: 'password', secret: 'h1', metadata: {} }, {})
      await store.rotate(c.id, 'h2', c.version, {})
      await expect(store.rotate(c.id, 'h3', 1, {})).rejects.toMatchObject({ code: 'AUTH/STALE_WRITE' })
    })

    it('deleteByKind removes only credentials of that kind for an identity', async () => {
      const store = factory()
      await store.upsert({ identityId: 'u', kind: 'password', secret: 'p', metadata: {} }, {})
      await store.upsert({ identityId: 'u', kind: 'totp', secret: 't', metadata: {} }, {})
      await store.deleteByKind('u', 'password', {})
      const rest = await store.listByIdentity('u', undefined, {})
      expect(rest.every((c) => c.kind !== 'password')).toBe(true)
    })

    it('patchMetadata shallow-merges + bumps version atomically', async () => {
      const store = factory()
      const c = await store.upsert(
        { identityId: 'u', kind: 'totp', secret: 's', metadata: { confirmed: false, counter: 0 } },
        {},
      )
      const next = await store.patchMetadata(c.id, { confirmed: true }, {})
      expect((next.metadata as { confirmed: boolean; counter: number }).confirmed).toBe(true)
      expect((next.metadata as { confirmed: boolean; counter: number }).counter).toBe(0)
      expect(next.version).toBe(c.version + 1)
    })

    it('patchMetadata throws AUTH/UNAUTHENTICATED for an unknown id', async () => {
      const store = factory()
      await expect(store.patchMetadata('does-not-exist', { x: 1 }, {})).rejects.toMatchObject({
        code: 'AUTH/UNAUTHENTICATED',
      })
    })
  })
}
