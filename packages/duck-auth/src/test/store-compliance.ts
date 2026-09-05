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
/**
 * An identity id that is guaranteed absent AND guaranteed acceptable to the
 * adapter's `id` column. A literal like `'no-such-id'` is neither: Postgres
 * stores identity ids as `uuid` and rejects it as malformed input long before
 * it can miss. Creating a row and erasing it borrows the store's own id shape.
 */
async function absentIdentityId<P extends SqlBridge.ProfileMetadataBase>(
  store: Identities.Store<P>,
): Promise<string> {
  const doomed = await store.create(
    identityInput({ profile: { email: `absent-${Date.now()}@x`, username: 'absent' } as unknown as P }),
  )
  await store.erase(doomed.id)
  return doomed.id
}

/** Same idea for session compliance, whose identity ids come from the caller. */
const ABSENT = '00000000-0000-4000-8000-000000000000'

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

    it('withClient, when present, returns a distinct store and leaves the original intact', async () => {
      const store = factory()
      // Adapters with no transactional driver omit withClient by design.
      if (!store.withClient) return
      const i = await store.create(identityInput({ profile: { email: 'wc@x', username: 'wc' } as unknown as P }))

      // Re-binding to the SAME client must still produce a new object, never
      // `this` - a bound facade that shared identity with the engine's store
      // could mutate it, which is the whole failure mode withClient prevents.
      const rebound = store.withClient({})
      expect(rebound).not.toBe(store)
      expect(rebound.findById).toBeTypeOf('function')
      expect(await store.findById(i.id)).not.toBeNull()
    })

    it('softDeleteMany, when present, reports one outcome per id in input order', async () => {
      const store = factory()
      // A store with no set-based form is complete without one; the facet loops.
      if (!store.softDeleteMany) return
      const a = await store.create(identityInput({ profile: { email: 'ba@x', username: 'ba' } as unknown as P }))
      const b = await store.create(identityInput({ profile: { email: 'bb@x', username: 'bb' } as unknown as P }))
      const gone = await absentIdentityId(store)

      const result = await store.softDeleteMany([a.id, gone, b.id], 1000)

      expect(result.outcomes.map((o) => o.id)).toEqual([a.id, gone, b.id])
      expect(result.applied).toBe(2)
      expect(result.failed).toBe(1)
      expect(await store.findById(a.id)).toBeNull()
      expect(await store.findById(b.id)).toBeNull()
    })

    it('updateProfileMany, when present, reports stale rows without throwing', async () => {
      const store = factory()
      if (!store.updateProfileMany) return
      const a = await store.create(identityInput({ profile: { email: 'ua@x', username: 'ua' } as unknown as P }))
      const b = await store.create(identityInput({ profile: { email: 'ub@x', username: 'ub' } as unknown as P }))

      const result = await store.updateProfileMany([
        { expectedVersion: 999, id: a.id, profile: { email: 'ua2@x', username: 'ua2' } as unknown as P },
        { expectedVersion: b.version, id: b.id, profile: { email: 'ub2@x', username: 'ub2' } as unknown as P },
      ])

      expect(result.outcomes[0]).toMatchObject({ ok: false, reason: 'stale-write' })
      expect(result.outcomes[1]?.ok).toBe(true)
      // The winner really landed and its version really moved on.
      const after = await store.findById(b.id)
      expect(after?.profile.username).toBe('ub2')
      expect(after?.version).toBe(b.version + 1)
      // The loser is untouched.
      expect((await store.findById(a.id))?.profile.username).toBe('ua')
    })

    it('eraseMany and restoreMany, when present, round-trip', async () => {
      const store = factory()
      if (!store.restoreMany || !store.eraseMany) return
      const a = await store.create(identityInput({ profile: { email: 'er@x', username: 'er' } as unknown as P }))
      await store.softDelete(a.id, 1000)

      expect((await store.restoreMany([a.id, await absentIdentityId(store)])).applied).toBe(1)
      expect(await store.findById(a.id)).not.toBeNull()

      expect((await store.eraseMany([a.id])).applied).toBe(1)
      expect(await store.findById(a.id)).toBeNull()
    })

    it('a batch over an empty list is a no-op', async () => {
      const store = factory()
      if (!store.softDeleteMany) return
      expect((await store.softDeleteMany([], 1000)).outcomes).toEqual([])
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

    it('softDelete clears emailVerified, so a restore does not hand back a verified claim', async () => {
      const store = factory()
      const i = await store.create(
        identityInput({ emailVerified: true, profile: { email: 'a@x', username: 'a' } as unknown as P }),
      )
      expect(i.emailVerified).toBe(true)

      await store.softDelete(i.id, 60_000)

      // The address is free while the row is hidden - the unique index and
      // `findByEmail` are both partial on `deletedAt` - so anyone may claim and
      // verify it during the grace window. Restoring must not assert ownership
      // the identity can no longer prove.
      const restored = await store.restore(i.id)
      expect(restored.emailVerified).toBe(false)
      expect((await store.findById(i.id))?.emailVerified).toBe(false)
    })

    it('softDeleteMany clears emailVerified too, when the store implements it', async () => {
      const store = factory()
      if (!store.softDeleteMany) return
      const a = await store.create(
        identityInput({ emailVerified: true, profile: { email: 'a@x', username: 'a' } as unknown as P }),
      )
      const b = await store.create(
        identityInput({ emailVerified: true, profile: { email: 'b@x', username: 'b' } as unknown as P }),
      )

      expect((await store.softDeleteMany([a.id, b.id], 60_000)).applied).toBe(2)

      expect((await store.restore(a.id)).emailVerified).toBe(false)
      expect((await store.restore(b.id)).emailVerified).toBe(false)
    })

    it('restore refuses once the grace window has closed', async () => {
      const store = factory()
      const i = await store.create(identityInput({ profile: { email: 'a@x', username: 'a' } as unknown as P }))

      // `deletedAt` holds the moment the window shuts, so a negative grace is a
      // window that shut before it opened - the same state a row reaches by
      // simply sitting there, without the test having to wait for it.
      await store.softDelete(i.id, -1000)

      await expect(store.restore(i.id)).rejects.toMatchObject({ code: 'AUTH_GRACE_EXPIRED' })
      // Still gone: a refused restore must not half-apply.
      expect(await store.findById(i.id)).toBeNull()
    })

    it('restore refuses when the address was taken while the row was hidden', async () => {
      const store = factory()
      const i = await store.create(identityInput({ profile: { email: 'a@x', username: 'a' } as unknown as P }))
      await store.softDelete(i.id, 60_000)

      // Free to claim precisely because the unique index and `findByEmail` are
      // both partial on `deletedAt`. A different username, so this pins the
      // email check rather than the username one.
      const claimant = await store.create(identityInput({ profile: { email: 'a@x', username: 'a2' } as unknown as P }))

      await expect(store.restore(i.id)).rejects.toMatchObject({ code: 'AUTH_EMAIL_TAKEN' })
      expect(await store.findById(i.id)).toBeNull()
      // The live claimant is untouched: the refusal costs the innocent row nothing.
      expect((await store.findById(claimant.id))?.id).toBe(claimant.id)
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
      const merged = await store.merge(survivor.id, dup.id)
      // The survivor comes back from the write itself, already carrying the
      // union - a caller that needs it should not have to re-read.
      expect(merged?.id).toBe(survivor.id)
      expect(merged?.providers.some((p) => p.providerId === 'oauth:authGoogle')).toBe(true)
      const fresh = await store.findById(survivor.id)
      expect(fresh?.providers.some((p) => p.providerId === 'oauth:authGoogle')).toBe(true)
      expect(await store.findById(dup.id)).toBeNull()
    })

    it('merge writes nothing when either side is missing', async () => {
      const store = factory()
      const dup = await store.create(identityInput({ profile: { email: 'md@x', username: 'md' } as unknown as P }))
      const survivor = await store.create(identityInput({ profile: { email: 'ms@x', username: 'ms' } as unknown as P }))
      const gone = (await store.create(identityInput({ profile: { email: 'mg@x', username: 'mg' } as unknown as P })))
        .id
      await store.erase(gone)

      // A merge re-points the dup's credentials and sessions and then deletes
      // it. With one side missing that is not a merge, it is data loss - so
      // nothing is written and the caller is told plainly.
      expect(await store.merge(gone, dup.id)).toBeNull()
      expect(await store.findById(dup.id)).not.toBeNull()

      expect(await store.merge(survivor.id, gone)).toBeNull()
      expect(await store.findById(survivor.id)).not.toBeNull()
    })

    it('every mutating write answers with the row it touched', async () => {
      const store = factory()
      const i = await store.create(identityInput({ profile: { email: 'ret@x', username: 'ret' } as unknown as P }))

      const linked = await store.link(i.id, {
        addedAt: new Date(),
        providerId: 'oauth:authGoogle',
        providerSub: 'ret-1',
      })
      expect(linked?.id).toBe(i.id)
      expect(linked?.providers.some((p) => p.providerId === 'oauth:authGoogle')).toBe(true)

      const unlinked = await store.unlink(i.id, 'oauth:authGoogle')
      expect(unlinked?.id).toBe(i.id)
      expect(unlinked?.providers.some((p) => p.providerId === 'oauth:authGoogle')).toBe(false)

      // `deletedAt` is the moment the grace window CLOSES, so the deadline a
      // caller reports comes off the row the store wrote rather than a second
      // reading of the clock.
      const before = Date.now()
      const hidden = await store.softDelete(i.id, 60_000)
      expect(hidden?.id).toBe(i.id)
      expect(hidden?.deletedAt?.getTime()).toBeGreaterThanOrEqual(before + 60_000)
      expect(hidden?.emailVerified).toBe(false)

      const back = await store.restore(i.id)
      expect(back.deletedAt).toBeNull()

      // The row as it was: once the delete lands there is nothing left to read.
      const erased = await store.erase(i.id)
      expect(erased?.id).toBe(i.id)
      expect(await store.findById(i.id)).toBeNull()
    })

    it('a write that matches no row answers null rather than reporting a change', async () => {
      const store = factory()
      // A real id whose row is gone - valid for every dialect's id column,
      // which a made-up string would not be.
      const gone = (await store.create(identityInput({ profile: { email: 'g@x', username: 'g' } as unknown as P }))).id
      await store.erase(gone)

      expect(await store.softDelete(gone, 60_000)).toBeNull()
      expect(await store.erase(gone)).toBeNull()
      expect(await store.link(gone, { addedAt: new Date(), providerId: 'password', providerSub: null })).toBeNull()
      expect(await store.unlink(gone, 'password')).toBeNull()
      expect(await store.merge(gone, gone)).toBeNull()
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

    it('deleteAllForIdentities, when present, sweeps every named identity', async () => {
      const store = factory()
      // A store with no set-based form is complete without one; the facet loops.
      if (!store.deleteAllForIdentities) return
      const now = new Date()
      const exp = new Date(now.getTime() + 60_000)
      const mk = (id: string, identityId: string) =>
        sessionInput({
          id: sid(id),
          identityId,
          kind: 'user',
          aal: 1,
          factors: [],
          createdAt: now,
          rotatedAt: now,
          expiresAt: exp,
          absoluteExpiresAt: exp,
          fresh: true,
        })
      await store.create(mk('bulk-1', OWNER))
      await store.create(mk('bulk-2', OWNER))
      await store.create(mk('bulk-3', OTHER))

      const result = await store.deleteAllForIdentities([OWNER, OTHER, ABSENT])

      expect(result.outcomes.map((o) => o.id)).toEqual([OWNER, OTHER, ABSENT])
      expect(result.applied).toBe(2)
      expect(result.outcomes[2]).toMatchObject({ ok: false, reason: 'not-found' })
      expect(await store.listByIdentity(OWNER)).toEqual([])
      expect(await store.listByIdentity(OTHER)).toEqual([])
    })

    it('listByIdentities, when present, returns the union of the named identities', async () => {
      const store = factory()
      if (!store.listByIdentities) return
      const now = new Date()
      const exp = new Date(now.getTime() + 60_000)
      await store.create(
        sessionInput({
          id: sid('union-1'),
          identityId: OWNER,
          kind: 'user',
          aal: 1,
          factors: [],
          createdAt: now,
          rotatedAt: now,
          expiresAt: exp,
          absoluteExpiresAt: exp,
          fresh: true,
        }),
      )

      const rows = await store.listByIdentities([OWNER, ABSENT])

      expect(rows.map((r) => r.identityId)).toEqual([OWNER])
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

    it('deleteByIdentities, when present, reports one outcome per identity in input order', async () => {
      const store = factory()
      // Stores with no set-based form are complete without one; the facet loops.
      if (!store.deleteByIdentities) return
      await store.upsert(credentialInput({ identityId: OWNER, kind: 'password', secret: 'bp', metadata: {} }), {})
      await store.upsert(credentialInput({ identityId: OWNER, kind: 'totp', secret: 'bt', metadata: {} }), {})

      const result = await store.deleteByIdentities([OWNER, ABSENT], {})

      expect(result.outcomes.map((o) => o.id)).toEqual([OWNER, ABSENT])
      expect(result.applied).toBe(1)
      expect(result.outcomes[1]).toMatchObject({ ok: false, reason: 'not-found' })
      // Every kind went, not just the one the last statement happened to match.
      expect(await store.listByIdentity(OWNER, null, {})).toEqual([])
    })

    it('deleteByKind removes only credentials of that kind for an identity', async () => {
      const store = factory()
      await store.upsert(credentialInput({ identityId: OWNER, kind: 'password', secret: 'p', metadata: {} }), {})
      await store.upsert(credentialInput({ identityId: OWNER, kind: 'totp', secret: 't', metadata: {} }), {})
      const removed = await store.deleteByKind(OWNER, 'password', {})
      // The rows that went, so a caller can say how many factors it dropped
      // without a count query the delete already answered.
      expect(removed.map((c) => c.kind)).toEqual(['password'])
      const rest = await store.listByIdentity(OWNER, null, {})
      expect(rest.every((c) => c.kind !== 'password')).toBe(true)
    })

    it('every credential removal answers with what it removed', async () => {
      const store = factory()
      const a = await store.upsert(credentialInput({ identityId: OWNER, kind: 'api-key', secret: 'k1' }), {})
      const b = await store.upsert(credentialInput({ identityId: OWNER, kind: 'password', secret: 'p1' }), {})

      const revoked = await store.revoke(a.id, {})
      expect(revoked?.id).toBe(a.id)
      expect(revoked?.revokedAt).toBeInstanceOf(Date)

      // The row as it was: once the delete lands there is nothing left to read.
      const deleted = await store.delete(b.id, {})
      expect(deleted?.id).toBe(b.id)
      expect(await store.findById(b.id, {})).toBeNull()
    })

    it('a credential removal that matches no row answers null or an empty list', async () => {
      const store = factory()
      const gone = (await store.upsert(credentialInput({ identityId: OWNER, kind: 'api-key', secret: 'k2' }), {})).id
      await store.delete(gone, {})

      expect(await store.revoke(gone, {})).toBeNull()
      expect(await store.delete(gone, {})).toBeNull()
      expect(await store.deleteByKind(OWNER, 'recovery', {})).toEqual([])
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
