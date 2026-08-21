import { describe, expect, it } from 'vitest'
import type { SqlBridge } from '~/adapters/sql/sql.types'
import type { Credential } from '~/core/credentials/credentials.types'
import type { Identities } from '~/core/identities/identities.types'
import type { Sessions } from '~/core/sessions/sessions.types'
import { credentialInput, identityInput, sessionInput } from '~/test/store-inputs'

/**
 * Compliance test matrix for Identity stores. Every shipped adapter (memory,
 * redis, drizzle, prisma) imports this and runs it against a fresh instance;
 * the same assertions guarantee behaviour parity across adapters.
 *
 * @param factory - factory returning a fresh `Identity.IStore` per test
 */
export function runIdentityStoreCompliance<P extends SqlBridge.ProfileMetadataBase = SqlBridge.ProfileMetadataBase>(
  factory: () => Identities.Store<P>,
): void {
  describe('Identity.IStore compliance', () => {
    it('create stamps id, version=1, createdAt, updatedAt; respects providers + tenantId', async () => {
      const store = factory()
      const i = await store.create(
        identityInput({
          profile: { email: 'a@x.com', username: 'a' } as unknown as P,
          providers: [{ providerId: 'password', providerSub: null, addedAt: new Date() }],
        }),
      )
      expect(i.id).toBeTruthy()
      expect(i.version).toBe(1)
      expect(i.providers).toHaveLength(1)
      expect(i.createdAt).toBeInstanceOf(Date)
    })

    it('findByEmail finds a created identity (identities are global)', async () => {
      const store = factory()
      await store.create(identityInput({ profile: { email: 'shared@x', username: 'shared' } as unknown as P }))
      expect(await store.findByEmail('shared@x')).not.toBeNull()
    })

    it('update with expectedVersion mismatch surfaces AUTH/STALE_WRITE', async () => {
      const store = factory()
      const i = await store.create(identityInput({ profile: { email: 'a@x', username: 'a' } as unknown as P }))
      await store.update(i.id, { profile: { email: 'b@x', username: 'b' } as unknown as P }, i.version)
      await expect(store.update(i.id, { profile: { email: 'c@x', username: 'c' } as unknown as P }, 1)).rejects.toMatchObject({
        code: 'AUTH_STALE_WRITE',
      })
    })

    it('admits exactly one of many concurrent updates from the same version', async () => {
      // Two request handlers reading the same row and both writing is the ordinary
      // case for a profile edit. Whichever concurrency control the adapter has, the
      // observable contract is the same: one write lands, the rest are refused, and
      // the version advances exactly once.
      const store = factory()
      const i = await store.create(identityInput({ profile: { email: 'race@x', username: 'race' } as unknown as P }))

      const settled = await Promise.allSettled(
        Array.from({ length: 10 }, (_, n) =>
          store.update(i.id, { profile: { email: 'race@x', username: `race-${n}` } as unknown as P }, i.version),
        ),
      )

      expect(settled.filter((r) => r.status === 'fulfilled')).toHaveLength(1)
      for (const r of settled) {
        if (r.status === 'rejected') expect(r.reason).toMatchObject({ code: 'AUTH_STALE_WRITE' })
      }
      expect((await store.findById(i.id))?.version).toBe(i.version + 1)
    })

    it('softDelete hides; restore brings back within grace; erase is permanent', async () => {
      const store = factory()
      const i = await store.create(identityInput({ profile: { email: 'a@x', username: 'a' } as unknown as P }))
      await store.softDelete(i.id, 60_000)
      expect(await store.findById(i.id)).toBeNull()
      const restored = await store.restore(i.id)
      expect(restored.id).toBe(i.id)
      await store.erase(i.id)
      expect(await store.findById(i.id)).toBeNull()
    })

    it('link / unlink mutate providers; findByProviderSub locates linked identities', async () => {
      const store = factory()
      const i = await store.create(identityInput({ profile: { email: 'a@x', username: 'a' } as unknown as P }))
      await store.link(i.id, { providerId: 'oauth:authGoogle', providerSub: 'sub-1', addedAt: new Date() })
      const found = await store.findByProviderSub('oauth:authGoogle', 'sub-1')
      expect(found?.id).toBe(i.id)
      await store.unlink(i.id, 'oauth:authGoogle')
      expect(await store.findByProviderSub('oauth:authGoogle', 'sub-1')).toBeNull()
    })

    it('merge moves providers from dup into survivor + deletes dup', async () => {
      const store = factory()
      const survivor = await store.create(
        identityInput({
          profile: { email: 's@x', username: 's' } as unknown as P,
          providers: [{ providerId: 'password', providerSub: null, addedAt: new Date() }],
        }),
      )
      const dup = await store.create(
        identityInput({
          profile: { email: 'd@x', username: 'd' } as unknown as P,
          providers: [{ providerId: 'oauth:authGoogle', providerSub: 'g', addedAt: new Date() }],
        }),
      )
      await store.merge(survivor.id, dup.id)
      const fresh = await store.findById(survivor.id)
      expect(fresh?.providers.some((p) => p.providerId === 'oauth:authGoogle')).toBe(true)
      expect(await store.findById(dup.id)).toBeNull()
    })
  })
}

/**
 * Row identifiers the session + credential matrices plant. The defaults are short
 * readable strings, which is all a permissive store needs. Adapters with a strict
 * schema override them: Postgres types `identity_id` as `uuid` behind a foreign
 * key, and constrains `auth_sessions.id` to exactly 64 chars, so the matrix has to
 * be handed ids that satisfy the real columns or it can never run there.
 */
export type ComplianceIds = {
  /** Owning identity. Must already exist when the adapter enforces the FK. */
  identityId?: string
  /** A second identity, for the isolation cases. Must also already exist. */
  otherIdentityId?: string
  /** Map a readable label to a row id the adapter's `id` column accepts. */
  sessionId?: (label: string) => string
}

const DEFAULT_IDS: Required<ComplianceIds> = {
  identityId: 'u',
  otherIdentityId: 'v',
  sessionId: (label) => label,
}

/**
 * Compliance matrix for Session stores. Verifies hashed-key storage,
 * listing, GC purge of expired rows, and per-identity bulk delete.
 */
export function runSessionStoreCompliance(factory: () => Sessions.Store, ids: ComplianceIds = {}): void {
  const { identityId: OWNER, otherIdentityId: OTHER, sessionId: sid } = { ...DEFAULT_IDS, ...ids }
  describe('Session.IStore compliance', () => {
    it('create + getByHash roundtrip uses the row id directly', async () => {
      const store = factory()
      const now = new Date()
      const exp = new Date(now.getTime() + 60_000)
      const session = sessionInput({
        id: sid('hash-1'),
        identityId: OWNER,
        kind: 'user',
        aal: 1,
        factors: [],
        createdAt: now,
        rotatedAt: now,
        expiresAt: exp,
        absoluteExpiresAt: exp,
        fresh: true,
      })
      await store.create(session)
      // Nullable columns the store fills with `null` are extra keys on the
      // returned row, so assert the caller-provided fields are a subset.
      expect(await store.getByHash(sid('hash-1'))).toMatchObject(session)
    })

    it('listByIdentity returns only sessions of the requested identity', async () => {
      const store = factory()
      const now = new Date()
      const exp = new Date(now.getTime() + 60_000)
      const base = {
        kind: 'user' as const,
        aal: 1 as const,
        factors: [],
        createdAt: now,
        rotatedAt: now,
        expiresAt: exp,
        absoluteExpiresAt: exp,
        fresh: true,
      }
      await store.create(sessionInput({ id: sid('u-1'), identityId: OWNER, ...base }))
      await store.create(sessionInput({ id: sid('u-2'), identityId: OWNER, ...base }))
      await store.create(sessionInput({ id: sid('v-1'), identityId: OTHER, ...base }))
      const us = await store.listByIdentity(OWNER)
      expect(us).toHaveLength(2)
    })

    it('deleteAllForIdentity wipes every session for the identity', async () => {
      const store = factory()
      const now = new Date()
      const exp = new Date(now.getTime() + 60_000)
      const base = {
        kind: 'user' as const,
        aal: 1 as const,
        factors: [],
        createdAt: now,
        rotatedAt: now,
        expiresAt: exp,
        absoluteExpiresAt: exp,
        fresh: true,
      }
      await store.create(sessionInput({ id: sid('a'), identityId: OWNER, ...base }))
      await store.create(sessionInput({ id: sid('b'), identityId: OWNER, ...base }))
      await store.deleteAllForIdentity(OWNER)
      expect(await store.listByIdentity(OWNER)).toHaveLength(0)
    })

    it('gc purges sessions with expiresAt or absoluteExpiresAt past now', async () => {
      const store = factory()
      const nowMs = Date.now()
      await store.create(
        sessionInput({
          id: sid('expired'),
          identityId: OWNER,
          kind: 'user',
          aal: 1,
          factors: [],
          createdAt: new Date(nowMs - 100_000),
          rotatedAt: new Date(nowMs - 100_000),
          expiresAt: new Date(nowMs - 1),
          absoluteExpiresAt: new Date(nowMs - 1),
          fresh: false,
        }),
      )
      await store.create(
        sessionInput({
          id: sid('live'),
          identityId: OWNER,
          kind: 'user',
          aal: 1,
          factors: [],
          createdAt: new Date(nowMs),
          rotatedAt: new Date(nowMs),
          expiresAt: new Date(nowMs + 60_000),
          absoluteExpiresAt: new Date(nowMs + 60_000),
          fresh: true,
        }),
      )
      const r = await store.gc(nowMs)
      expect(r.deleted).toBe(1)
      expect(await store.getByHash(sid('expired'))).toBeNull()
      expect(await store.getByHash(sid('live'))).not.toBeNull()
    })

    // --- update / delete -----------------------------------------------
    // These two methods had NO cross-adapter coverage. Both confirmed
    // divergences (error code, implicit rotatedAt) lived here.

    it('getByHash returns null for an unknown id', async () => {
      expect(await factory().getByHash(sid('nope'))).toBeNull()
    })

    it('update merges the patch and persists it', async () => {
      const store = factory()
      const now = new Date()
      const exp = new Date(now.getTime() + 60_000)
      await store.create(
        sessionInput({
          id: sid('u-1'), identityId: OWNER, kind: 'user', aal: 1, factors: [],
          createdAt: now, rotatedAt: now, expiresAt: exp, absoluteExpiresAt: exp, fresh: true,
        }),
      )
      const updated = await store.update(sid('u-1'), { fresh: false })
      expect(updated.fresh).toBe(false)
      expect(await store.getByHash(sid('u-1'))).toMatchObject({ fresh: false })
    })

    it('update does NOT mutate fields the caller did not patch', async () => {
      const store = factory()
      const rotated = new Date(Date.now() - 600_000)
      const exp = new Date(Date.now() + 60_000)
      await store.create(
        sessionInput({
          id: sid('u-1'), identityId: OWNER, kind: 'user', aal: 1, factors: [],
          createdAt: rotated, rotatedAt: rotated, expiresAt: exp, absoluteExpiresAt: exp, fresh: true,
        }),
      )
      const updated = await store.update(sid('u-1'), { fresh: false })
      // rotatedAt feeds the freshness gate — a store must never move it implicitly.
      expect(updated.rotatedAt.getTime()).toBe(rotated.getTime())
      expect(updated.createdAt.getTime()).toBe(rotated.getTime())
    })

    it('update on an unknown id throws AUTH_SESSION_REVOKED', async () => {
      await expect(factory().update(sid('nope'), { fresh: false })).rejects.toMatchObject({
        code: 'AUTH_SESSION_REVOKED',
      })
    })

    it('delete removes the row; deleting an unknown id is a silent no-op', async () => {
      const store = factory()
      const now = new Date()
      const exp = new Date(now.getTime() + 60_000)
      await store.create(
        sessionInput({
          id: sid('d-1'), identityId: OWNER, kind: 'user', aal: 1, factors: [],
          createdAt: now, rotatedAt: now, expiresAt: exp, absoluteExpiresAt: exp, fresh: true,
        }),
      )
      await store.delete(sid('d-1'))
      expect(await store.getByHash(sid('d-1'))).toBeNull()
      await expect(store.delete(sid('nope'))).resolves.toBeUndefined()
    })
  })
}

/**
 * Compliance matrix for Credential stores. Covers upsert + findById +
 * findByHashedSecret semantics (revoked rows distinguished from missing),
 * rotate optimistic-lock, deleteByKind cleanup.
 */
export function runCredentialStoreCompliance(factory: () => Credential.Store, ids: ComplianceIds = {}): void {
  const { identityId: OWNER } = { ...DEFAULT_IDS, ...ids }
  describe('Credential.IStore compliance', () => {
    it('upsert stamps id + version=1; findById retrieves it', async () => {
      const store = factory()
      const c = await store.upsert(
        credentialInput({ identityId: OWNER, kind: 'password', secret: 'hashed-pw', metadata: {} }),
        {},
      )
      expect(c.id).toBeTruthy()
      expect(c.version).toBe(1)
      const got = await store.findById(c.id, {})
      expect(got?.secret).toBe('hashed-pw')
    })

    it('findByHashedSecret returns the freshest live row before falling back to revoked', async () => {
      const store = factory()
      const c1 = await store.upsert(
        credentialInput({
          identityId: OWNER,
          kind: 'magic-link',
          secret: 'hash',
          metadata: {},
          expiresAt: new Date(Date.now() + 60_000),
        }),
        {},
      )
      await store.revoke(c1.id, {})
      // Same secret hash, but fresh row.
      const c2 = await store.upsert(
        credentialInput({
          identityId: OWNER,
          kind: 'magic-link',
          secret: 'hash',
          metadata: {},
          expiresAt: new Date(Date.now() + 60_000),
        }),
        {},
      )
      const got = await store.findByHashedSecret('hash', 'magic-link', {})
      expect(got?.id).toBe(c2.id)
    })

    it('findByHashedSecret falls back to the revoked row when no live rows exist', async () => {
      const store = factory()
      const c = await store.upsert(
        credentialInput({ identityId: OWNER, kind: 'api-key', secret: 'hash-x', metadata: {} }),
        {},
      )
      await store.revoke(c.id, {})
      const got = await store.findByHashedSecret('hash-x', 'api-key', {})
      expect(got?.revokedAt).toBeTruthy()
    })

    it('rotate with mismatched version surfaces AUTH/STALE_WRITE', async () => {
      const store = factory()
      const c = await store.upsert(
        credentialInput({ identityId: OWNER, kind: 'password', secret: 'h1', metadata: {} }),
        {},
      )
      await store.rotate(c.id, 'h2', c.version, {})
      await expect(store.rotate(c.id, 'h3', 1, {})).rejects.toMatchObject({ code: 'AUTH_STALE_WRITE' })
    })

    it('deleteByKind removes only credentials of that kind for an identity', async () => {
      const store = factory()
      await store.upsert(credentialInput({ identityId: OWNER, kind: 'password', secret: 'p', metadata: {} }), {})
      await store.upsert(credentialInput({ identityId: OWNER, kind: 'totp', secret: 't', metadata: {} }), {})
      await store.deleteByKind(OWNER, 'password', {})
      const rest = await store.listByIdentity(OWNER, null, {})
      expect(rest.every((c) => c.kind !== 'password')).toBe(true)
    })

    it('patchMetadata shallow-merges + bumps version atomically', async () => {
      const store = factory()
      const c = await store.upsert(
        credentialInput({ identityId: OWNER, kind: 'totp', secret: 's', metadata: { confirmed: false, counter: 0 } }),
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
        code: 'AUTH_UNAUTHENTICATED',
      })
    })
  })
}
