import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { actorId, withActor } from '~/core/actor'
import { sha256 } from '~/core/crypto'
import { InMemoryEvents } from '~/core/events'
import type { Identities } from '~/core/identities/identities.types'
import { credentialInput, sessionInput } from '~/test/store-inputs'
import { IdentitiesImpl } from '../identities'
import { DEFAULT_IDENTITIES_CONFIG } from '../identities.constants'

interface MyProfile extends Identities.ProfileMetadataBase {
  name?: string
  roles?: string[]
}

describe('IdentitiesFacet', () => {
  let adapter: MemoryAdapter<MyProfile>
  let events: InMemoryEvents
  let facet: IdentitiesImpl<MyProfile>

  beforeEach(() => {
    adapter = new MemoryAdapter<MyProfile>()
    events = new InMemoryEvents()
    facet = new IdentitiesImpl<MyProfile>(adapter.identities, events, DEFAULT_IDENTITIES_CONFIG)
  })

  describe('create', () => {
    it('creates an identity and emits signup.completed', async () => {
      const handler = vi.fn()
      events.on('signup.completed', handler)
      const i = await facet.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
      expect(i.profile?.email).toBe('a@x.com')
      expect(i.version).toBe(1)
      expect(handler).toHaveBeenCalledOnce()
    })

    it('identities are global: getByEmail finds the account regardless of origin tenant', async () => {
      await facet.create({ profile: { username: 'shared@x.com', email: 'shared@x.com' } })
      const found = await facet.getByEmail('shared@x.com')
      expect(found?.profile.email).toBe('shared@x.com')
    })

    it('rejects an oversize profile (storage / read amplification defense)', async () => {
      // Default cap is 16 KiB; force-stuff a ~32 KiB string into a custom
      // field. The cap check sees serialized JSON UTF-8 bytes.
      const huge = 'x'.repeat(32 * 1024)
      await expect(
        facet.create({ profile: { username: 'a@x.com', email: 'a@x.com', big: huge } }),
      ).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
    })

    it('rejects a circular profile (JSON.stringify throws - fail-closed)', async () => {
      const circular: Record<string, unknown> = { email: 'a@x.com' }
      circular.self = circular
      await expect(
        // @ts-expect-error: deliberately wrong shape to test the JSON-serializable guard.
        facet.create({ profile: circular }),
      ).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
    })

    it('honors an operator-supplied profileMaxBytes cap', async () => {
      const tight = new IdentitiesImpl<MyProfile>(adapter.identities, events, {
        softDeleteGracePeriodMs: DEFAULT_IDENTITIES_CONFIG.softDeleteGracePeriodMs,
        profileMaxBytes: 32,
      })
      await expect(
        tight.create({
          profile: { username: 'long-name-over-32-bytes@example.com', email: 'long-name-over-32-bytes@example.com' },
        }),
      ).rejects.toMatchObject({
        code: 'AUTH_MISCONFIGURED',
      })
    })

    it('an at-cap profile passes through', async () => {
      const tight = new IdentitiesImpl<MyProfile>(adapter.identities, events, {
        softDeleteGracePeriodMs: DEFAULT_IDENTITIES_CONFIG.softDeleteGracePeriodMs,
        profileMaxBytes: 48,
      })
      // `{"username":"a@x.com","email":"a@x.com"}` is 40 bytes - within 48.
      const i = await tight.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
      expect(i.profile?.email).toBe('a@x.com')
    })

    it('opt-out (profileMaxBytes: 0) accepts a large profile', async () => {
      const unbounded = new IdentitiesImpl<MyProfile>(adapter.identities, events, {
        softDeleteGracePeriodMs: DEFAULT_IDENTITIES_CONFIG.softDeleteGracePeriodMs,
        profileMaxBytes: 0,
      })
      const huge = 'x'.repeat(64 * 1024)
      const i = await unbounded.create({ profile: { username: 'a@x.com', email: 'a@x.com', big: huge } })
      expect(i.profile?.email).toBe('a@x.com')
    })
  })

  describe('updateProfile w/ optimistic locking', () => {
    it('updateProfile rejects when merged profile exceeds cap', async () => {
      const i = await facet.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
      const huge = 'x'.repeat(32 * 1024)
      await expect(facet.updateProfile(i.id, { name: huge }, i.version)).rejects.toMatchObject({
        code: 'AUTH_MISCONFIGURED',
      })
    })

    it('happy path: returns new version', async () => {
      const i = await facet.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
      const updated = await facet.updateProfile(i.id, { name: 'Alice' }, i.version)
      expect(updated.profile?.name).toBe('Alice')
      expect(updated.version).toBe(2)
    })

    it('stale write surfaces AUTH_STALE_WRITE', async () => {
      const i = await facet.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
      // First update bumps version 1 -> 2.
      await facet.updateProfile(i.id, { name: 'Alice' }, 1)
      // Second update with expectedVersion=1 collides.
      await expect(facet.updateProfile(i.id, { name: 'Eve' }, 1)).rejects.toMatchObject({
        code: 'AUTH_STALE_WRITE',
        meta: { expected: 1, actual: 2 },
      })
    })
  })

  describe('link / unlink', () => {
    it('link emits identity.linked + persists the provider entry', async () => {
      const i = await facet.create({
        profile: { username: 'a@x.com', email: 'a@x.com' },
        providers: [{ providerId: 'password', providerSub: 'local-1', addedAt: new Date() }],
      })
      const handler = vi.fn()
      events.on('identity.linked', handler)
      await facet.link(i.id, { providerId: 'oauth:authGoogle', providerSub: 'g-123' })
      expect(handler).toHaveBeenCalledOnce()
      const fresh = await facet.getById(i.id)
      expect(fresh?.providers.some((p) => p.providerId === 'oauth:authGoogle')).toBe(true)
    })

    it('link rejects duplicate providerId for same identity', async () => {
      const i = await facet.create({
        profile: { username: 'a@x.com', email: 'a@x.com' },
        providers: [{ providerId: 'oauth:authGoogle', providerSub: 'local-2', addedAt: new Date() }],
      })
      await expect(facet.link(i.id, { providerId: 'oauth:authGoogle', providerSub: 'local-3' })).rejects.toMatchObject({
        code: 'AUTH_PROVIDER_FAILED',
      })
    })

    it('unlink refuses the last provider (leaves account inaccessible)', async () => {
      const i = await facet.create({
        profile: { username: 'a@x.com', email: 'a@x.com' },
        providers: [{ providerId: 'password', providerSub: 'local-4', addedAt: new Date() }],
      })
      await expect(facet.unlink(i.id, 'password')).rejects.toMatchObject({
        code: 'AUTH_PROVIDER_FAILED',
      })
    })

    it('unlink succeeds when 2+ providers remain', async () => {
      const i = await facet.create({
        profile: { username: 'a@x.com', email: 'a@x.com' },
        providers: [
          { providerId: 'password', providerSub: 'local-5', addedAt: new Date() },
          { providerId: 'oauth:authGoogle', providerSub: 'local-6', addedAt: new Date() },
        ],
      })
      const unlinked = await facet.unlink(i.id, 'oauth:authGoogle')
      expect(unlinked.providers).toHaveLength(1)
      const fresh = await facet.getById(i.id)
      expect(fresh?.providers).toHaveLength(1)
    })

    it('link answers with the identity carrying the new provider', async () => {
      const i = await facet.create({
        profile: { username: 'a@x.com', email: 'a@x.com' },
        providers: [{ providerId: 'password', providerSub: 'local-7', addedAt: new Date() }],
      })

      const linked = await facet.link(i.id, { providerId: 'oauth:authGoogle', providerSub: 'g-1' })

      expect(linked.id).toBe(i.id)
      expect(linked.providers.map((p) => p.providerId)).toContain('oauth:authGoogle')
      // The addedAt the store stamped travels back with the row, so a caller
      // that wants to show "linked just now" does not have to guess it.
      expect(linked.providers.find((p) => p.providerId === 'oauth:authGoogle')?.addedAt).toBeInstanceOf(Date)
    })
  })

  describe('soft delete / restore / erase', () => {
    it('softDelete hides the identity from findById; restore brings it back', async () => {
      const i = await facet.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
      await facet.softDelete(i.id)
      await expect(facet.getById(i.id)).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
      const back = await facet.restore(i.id)
      expect(back.id).toBe(i.id)
      await expect(facet.getById(i.id)).resolves.toMatchObject({ id: i.id })
    })

    it('softDelete answers with the hidden row, carrying the grace deadline', async () => {
      const i = await facet.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })

      const before = Date.now()
      const hidden = await facet.softDelete(i.id)

      // `deletedAt` is when the window CLOSES, so a caller can tell the user
      // how long they have to change their mind straight off this row - and
      // off the same clock reading the store used, not a later one.
      expect(hidden.id).toBe(i.id)
      expect(hidden.deletedAt?.getTime()).toBeGreaterThanOrEqual(
        before + DEFAULT_IDENTITIES_CONFIG.softDeleteGracePeriodMs,
      )
    })

    it('softDelete and erase reject an identity that is not there, which orNull reads back as null', async () => {
      const ghost = '00000000-0000-4000-8000-000000000000'
      await expect(facet.softDelete(ghost)).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
      await expect(facet.erase(ghost, { reason: 'test' })).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
      await expect(facet.softDelete(ghost).orNull()).resolves.toBeNull()
      await expect(facet.erase(ghost, { reason: 'test' }).orNull()).resolves.toBeNull()
    })

    it('restore after grace expired surfaces AUTH_GRACE_EXPIRED', async () => {
      const tightFacet = new IdentitiesImpl<MyProfile>(adapter.identities, events, {
        softDeleteGracePeriodMs: 1, // 1ms grace = always expired by the time we check
      })
      const i = await tightFacet.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
      await tightFacet.softDelete(i.id)
      await new Promise((r) => setTimeout(r, 5))
      await expect(tightFacet.restore(i.id)).rejects.toMatchObject({ code: 'AUTH_GRACE_EXPIRED' })
    })

    it('erase answers with the row as it was, since a later read finds nothing', async () => {
      const i = await facet.create({ profile: { username: 'gone@x.com', email: 'gone@x.com' } })

      const erased = await facet.erase(i.id, { reason: 'gdpr' })

      expect(erased.id).toBe(i.id)
      expect(erased.profile.email).toBe('gone@x.com')
      await expect(facet.getById(i.id)).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
    })

    it('erase hard-removes the identity', async () => {
      const i = await facet.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
      await facet.erase(i.id, { reason: 'gdpr-2026-05-25' })
      await expect(facet.getById(i.id)).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
      // An erased id matched nothing, which is the same outcome `softDelete` and `erase` report - and the
      // same code, not one of three the three happen to raise between them.
      await expect(facet.restore(i.id)).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
    })
  })

  describe('bulkCreate', () => {
    it('skipExisting (default) leaves duplicates alone', async () => {
      await facet.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
      const r = await facet.bulkCreate([
        { profile: { username: 'a@x.com', email: 'a@x.com' } },
        { profile: { username: 'b@x.com', email: 'b@x.com' } },
      ])
      expect(r).toEqual({ created: 1, skipped: 1, failed: 0 })
    })

    it('merge appends new providers to existing identity', async () => {
      const i = await facet.create({
        profile: { username: 'a@x.com', email: 'a@x.com' },
        providers: [{ providerId: 'password', providerSub: 'local-10', addedAt: new Date() }],
      })
      await facet.bulkCreate(
        [
          {
            profile: { username: 'a@x.com', email: 'a@x.com' },
            providers: [{ providerId: 'oauth:authGoogle', providerSub: 'g', addedAt: new Date(), addedBy: null }],
          },
        ],
        { mode: 'merge' },
      )
      const fresh = await facet.getById(i.id)
      expect(fresh?.providers.some((p) => p.providerId === 'oauth:authGoogle')).toBe(true)
    })

    it('replace erases pre-existing identities by email then creates fresh', async () => {
      const before = await facet.create({ profile: { username: 'a@x.com', email: 'a@x.com', name: 'Old' } })
      await facet.bulkCreate([{ profile: { username: 'a@x.com', email: 'a@x.com', name: 'New' } }], { mode: 'replace' })
      const survivor = await facet.getByEmail('a@x.com')
      expect(survivor?.id).not.toBe(before.id)
      expect(survivor?.profile?.name).toBe('New')
    })
  })

  describe('exportAll', () => {
    it('strips credential secrets and includes identity + redacted credentials list', async () => {
      const i = await facet.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
      await adapter.credentials.create(
        credentialInput({ identityId: i.id, kind: 'password', secret: 'argon2id$...', metadata: {} }),
        {},
      )
      const blob = await facet.exportAll(i.id, adapter.credentials)
      expect(blob.identity.id).toBe(i.id)
      expect(blob.credentials).toHaveLength(1)
      // Type assertion: `secret` must not appear in the exported credential.
      expect(blob.credentials[0]).not.toHaveProperty('secret')
    })

    it('carries no oauth bearer token, which metadata used to hold in plaintext', async () => {
      const i = await facet.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
      await adapter.credentials.create(
        credentialInput({
          identityId: i.id,
          kind: 'oauth',
          secret: 'sha256-of-refresh-token',
          // A row written before the token stopped being stored.
          metadata: { provider: 'oauth:google', sub: 's', familyId: 'f', generation: 1, accessToken: 'ya29-LIVE' },
        }),
        {},
      )
      const json = IdentitiesImpl.exportToJson(await facet.exportAll(i.id, adapter.credentials))
      expect(json).not.toContain('ya29-LIVE')
      expect(json).not.toContain('sha256-of-refresh-token')
    })

    it('throws AUTH_UNAUTHENTICATED for unknown identity', async () => {
      await expect(facet.exportAll('nope', adapter.credentials)).rejects.toMatchObject({
        code: 'AUTH_UNAUTHENTICATED',
      })
    })

    it('emits schemaVersion=1 + empty sessions array when sessions store omitted', async () => {
      const i = await facet.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
      const blob = await facet.exportAll(i.id, adapter.credentials)
      expect(blob.schemaVersion).toBe('1')
      expect(blob.sessions).toEqual([])
    })

    it('includes sessions when sessions store supplied; strips csrfHash', async () => {
      const i = await facet.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
      const now = Date.now()
      await adapter.sessions.create(
        sessionInput({
          id: sha256('sid-hash-1'),
          identityId: i.id,
          kind: 'user',
          aal: 2,
          factors: [{ method: 'password', completedAt: new Date(now) }],
          csrfHash: 'redact-me',
          createdAt: new Date(now),
          rotatedAt: new Date(now),
          expiresAt: new Date(now + 60_000),
          absoluteExpiresAt: new Date(now + 60_000),
          fresh: true,
        }),
      )
      const blob = await facet.exportAll(i.id, adapter.credentials, {}, { sessions: adapter.sessions })
      expect(blob.sessions).toHaveLength(1)
      expect(blob.sessions[0]).not.toHaveProperty('csrfHash')
      expect(blob.sessions[0]!.identityId).toBe(i.id)
    })

    it('exportToJson produces deterministic JSON across runs (sorted keys)', async () => {
      const i = await facet.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
      const blob1 = await facet.exportAll(i.id, adapter.credentials)
      const blob2 = await facet.exportAll(i.id, adapter.credentials)
      // exportedAt differs each run; assert the rest of the structure
      // round-trips through canonical JSON the same way.
      const j1 = IdentitiesImpl.exportToJson({ ...blob1, exportedAt: 0 })
      const j2 = IdentitiesImpl.exportToJson({ ...blob2, exportedAt: 0 })
      expect(j1).toBe(j2)
      expect(j1.split('\n')[0]).toBe('{')
    })
  })

  /**
   * `erase` has always taken `{ reason, operatorId }` and its body did
   * `void opts` - the operator was accepted at the signature and discarded.
   * Provenance columns have the same shape of defect, which is why these two
   * sit together: declaring a place for who-did-it and never filling it.
   */
  describe('actor provenance', () => {
    it('erase binds its operatorId as the ambient actor for the store call', async () => {
      const i = await facet.create({ profile: { email: 'e@x.com', username: 'e@x.com' } })
      const inner = adapter.identities.erase.bind(adapter.identities)
      let seen: string | null = 'nothing-ran'
      adapter.identities.erase = (id: string) => {
        seen = actorId()
        return inner(id)
      }

      await facet.erase(i.id, { operatorId: 'op-7', reason: 'gdpr-request' })

      expect(seen).toBe('op-7')
    })

    it('eraseMany attributes the operator, as erase does — erasure is irreversible either way', async () => {
      const a = await facet.create({ profile: { email: 'm1@x.com', username: 'm1@x.com' } })
      const b = await facet.create({ profile: { email: 'm2@x.com', username: 'm2@x.com' } })
      const inner = adapter.identities.eraseMany.bind(adapter.identities)
      let seen: string | null = 'nothing-ran'
      adapter.identities.eraseMany = (ids: string[]) => {
        seen = actorId()
        return inner(ids)
      }

      await facet.eraseMany([a.id, b.id], { operatorId: 'op-8', reason: 'gdpr-bulk' })

      expect(seen).toBe('op-8')
    })

    it('eraseMany with no operatorId leaves the ambient actor alone, as erase does', async () => {
      const a = await facet.create({ profile: { email: 'm3@x.com', username: 'm3@x.com' } })
      const inner = adapter.identities.eraseMany.bind(adapter.identities)
      let seen: string | null = 'nothing-ran'
      adapter.identities.eraseMany = (ids: string[]) => {
        seen = actorId()
        return inner(ids)
      }

      await withActor('outer', () => facet.eraseMany([a.id], { reason: 'gdpr-bulk' }))

      expect(seen).toBe('outer')
    })

    it('erase with no operatorId leaves the ambient actor alone rather than clearing it', async () => {
      const i = await facet.create({ profile: { email: 'e2@x.com', username: 'e2@x.com' } })
      const inner = adapter.identities.erase.bind(adapter.identities)
      let seen: string | null = 'nothing-ran'
      adapter.identities.erase = (id: string) => {
        seen = actorId()
        return inner(id)
      }

      // An omitted `operatorId` is "I did not say", not "nobody" - an outer
      // request-scoped actor still has to survive the call.
      await withActor('outer', () => facet.erase(i.id, { reason: 'gdpr-request' }))

      expect(seen).toBe('outer')
    })

    it('a create through the facet carries the ambient actor onto the row', async () => {
      const i = await withActor('op-9', () => facet.create({ profile: { email: 'p@x.com', username: 'p@x.com' } }))

      // The facet does not stamp anything itself; this pins that it does not
      // lose the context on the way down to the store either.
      expect(i.createdBy).toBe('op-9')
      expect(i.updatedBy).toBe('op-9')
    })
  })

  describe('unlinkMany — the batch path of a guard that exists on the single one', () => {
    /** One provider, no credentials, so the link under test is the only way into the account. */
    async function soleLink() {
      return facet.create({
        profile: { username: 'a@x.com', email: 'a@x.com' },
        providers: [{ providerId: 'oauth:authGoogle', providerSub: 'g-1', addedAt: new Date() }],
      })
    }

    it('unlink refuses to drop the last way in', async () => {
      const i = await soleLink()
      await expect(facet.unlink(i.id, 'oauth:authGoogle')).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
    })

    it('unlinkMany refuses it too, rather than stranding the account', async () => {
      const i = await soleLink()
      const out = await facet.unlinkMany([{ identityId: i.id, providerId: 'oauth:authGoogle' }])
      expect(out).toEqual([])
      const fresh = await facet.getById(i.id)
      expect(fresh?.providers.map((p) => p.providerId)).toEqual(['oauth:authGoogle'])
    })

    it('unlinkMany still drops a link when another way in remains', async () => {
      const i = await facet.create({
        profile: { username: 'b@x.com', email: 'b@x.com' },
        providers: [
          { providerId: 'oauth:authGoogle', providerSub: 'g-2', addedAt: new Date() },
          { providerId: 'password', providerSub: 'local-1', addedAt: new Date() },
        ],
      })
      const out = await facet.unlinkMany([{ identityId: i.id, providerId: 'oauth:authGoogle' }])
      expect(out).toHaveLength(1)
      const fresh = await facet.getById(i.id)
      expect(fresh?.providers.map((p) => p.providerId)).toEqual(['password'])
    })

    it('one stranding row does not stop the rest of the batch', async () => {
      const sole = await soleLink()
      const spare = await facet.create({
        profile: { username: 'c@x.com', email: 'c@x.com' },
        providers: [
          { providerId: 'oauth:authGoogle', providerSub: 'g-3', addedAt: new Date() },
          { providerId: 'password', providerSub: 'local-2', addedAt: new Date() },
        ],
      })
      const out = await facet.unlinkMany([
        { identityId: sole.id, providerId: 'oauth:authGoogle' },
        { identityId: spare.id, providerId: 'oauth:authGoogle' },
      ])
      expect(out.map((r) => r.id)).toEqual([spare.id])
    })
  })

  describe('bulkCreate — a driver failure is not a failed row', () => {
    it('rethrows a hard driver error instead of counting it as a failed row', async () => {
      // `refusable` exists in this file because Postgres leaves a transaction aborted once a statement
      // has failed, so swallowing one would turn COMMIT into a silent ROLLBACK. A bare catch here made
      // bulkCreate the one path that did swallow it.
      adapter.identities.create = () => Promise.reject(new Error('ECONNRESET'))
      await expect(facet.bulkCreate([{ profile: { username: 'z@x.com', email: 'z@x.com' } }])).rejects.toThrow(
        /ECONNRESET/,
      )
    })

    it('still counts a refusal this layer decided as a failed row', async () => {
      const facetCapped = new IdentitiesImpl<MyProfile>(adapter.identities, events, {
        ...DEFAULT_IDENTITIES_CONFIG,
        profileMaxBytes: 8,
      })
      const out = await facetCapped.bulkCreate([
        { profile: { username: 'big@x.com', email: 'big@x.com', name: 'x'.repeat(500) } },
      ])
      expect(out).toMatchObject({ created: 0, failed: 1 })
    })

    it('merge mode emits identity.linked for the links it folds in', async () => {
      await facet.create({
        profile: { username: 'mrg@x.com', email: 'mrg@x.com' },
        providers: [{ providerId: 'password', providerSub: 'local-9', addedAt: new Date() }],
      })
      const handler = vi.fn()
      events.on('identity.linked', handler)
      const out = await facet.bulkCreate(
        [
          {
            profile: { username: 'mrg@x.com', email: 'mrg@x.com' },
            providers: [{ providerId: 'oauth:authGoogle', providerSub: 'g-9', addedAt: new Date(), addedBy: null }],
          },
        ],
        { mode: 'merge' },
      )
      expect(out).toMatchObject({ skipped: 1 })
      expect(handler).toHaveBeenCalledOnce()
    })
  })

  describe('linkMany — the batch path of the duplicate guard', () => {
    it('skips a providerId the identity already has, as link refuses it', async () => {
      const i = await facet.create({
        profile: { username: 'g@x.com', email: 'g@x.com' },
        providers: [{ providerId: 'oauth:authGoogle', providerSub: 'g-7', addedAt: new Date() }],
      })
      const out = await facet.linkMany([
        { identityId: i.id, link: { providerId: 'oauth:authGoogle', providerSub: 'g-8' } },
      ])
      expect(out).toEqual([])
      const fresh = await facet.getById(i.id)
      expect(fresh?.providers.filter((p) => p.providerId === 'oauth:authGoogle')).toHaveLength(1)
      expect(fresh?.providers[0]?.providerSub).toBe('g-7')
    })
  })

  describe('identity.unlinked — the event whose own docs call it the half a takeover performs', () => {
    it('unlink emits it, mirroring identity.linked', async () => {
      const i = await facet.create({
        profile: { username: 'd@x.com', email: 'd@x.com' },
        providers: [
          { providerId: 'oauth:authGoogle', providerSub: 'g-4', addedAt: new Date() },
          { providerId: 'password', providerSub: 'local-3', addedAt: new Date() },
        ],
      })
      const handler = vi.fn()
      events.on('identity.unlinked', handler)
      await facet.unlink(i.id, 'oauth:authGoogle')
      expect(handler).toHaveBeenCalledOnce()
      expect(handler.mock.calls[0]?.[0]).toMatchObject({
        allowedLockout: false,
        identityId: i.id,
        providerId: 'oauth:authGoogle',
      })
    })

    it('unlinkMany emits one per link it actually drops', async () => {
      const sole = await facet.create({
        profile: { username: 'e@x.com', email: 'e@x.com' },
        providers: [{ providerId: 'oauth:authGoogle', providerSub: 'g-5', addedAt: new Date() }],
      })
      const spare = await facet.create({
        profile: { username: 'f@x.com', email: 'f@x.com' },
        providers: [
          { providerId: 'oauth:authGoogle', providerSub: 'g-6', addedAt: new Date() },
          { providerId: 'password', providerSub: 'local-5', addedAt: new Date() },
        ],
      })
      const handler = vi.fn()
      events.on('identity.unlinked', handler)
      await facet.unlinkMany([
        { identityId: sole.id, providerId: 'oauth:authGoogle' },
        { identityId: spare.id, providerId: 'oauth:authGoogle' },
      ])
      expect(handler).toHaveBeenCalledOnce()
      expect(handler.mock.calls[0]?.[0]).toMatchObject({ identityId: spare.id })
    })
  })
})
