import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { InMemoryEvents } from '~/core/events'
import type { Identity } from '~/core/types/identity'
import { credentialInput, sessionInput } from '~/test/store-inputs'
import { IdentitiesFacet } from '../identities.facet'
import { DEFAULT_IDENTITIES_CONFIG } from '../identities.constants'

interface MyProfile extends Identity.ProfileMetadataBase {
  name?: string
  roles?: string[]
}

describe('IdentitiesFacet', () => {
  let adapter: MemoryAdapter<MyProfile>
  let events: InMemoryEvents
  let facet: IdentitiesFacet<MyProfile>

  beforeEach(() => {
    adapter = new MemoryAdapter<MyProfile>()
    events = new InMemoryEvents()
    facet = new IdentitiesFacet<MyProfile>(adapter.identities, events, DEFAULT_IDENTITIES_CONFIG)
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

    it('respects tenantId scoping (findByEmail in tenant A misses tenant B)', async () => {
      await facet.create(
        { profile: { username: 'shared@x.com', email: 'shared@x.com' }, tenantId: 'A' },
        { tenantId: 'A' },
      )
      const inB = await facet.getByEmail('shared@x.com', { tenantId: 'B' })
      expect(inB).toBeNull()
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
      const tight = new IdentitiesFacet<MyProfile>(adapter.identities, events, {
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
      const tight = new IdentitiesFacet<MyProfile>(adapter.identities, events, {
        softDeleteGracePeriodMs: DEFAULT_IDENTITIES_CONFIG.softDeleteGracePeriodMs,
        profileMaxBytes: 48,
      })
      // `{"username":"a@x.com","email":"a@x.com"}` is 40 bytes - within 48.
      const i = await tight.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
      expect(i.profile?.email).toBe('a@x.com')
    })

    it('opt-out (profileMaxBytes: 0) accepts a large profile', async () => {
      const unbounded = new IdentitiesFacet<MyProfile>(adapter.identities, events, {
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

    it('stale write surfaces AUTH/STALE_WRITE', async () => {
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
        providers: [{ providerId: 'password', providerSub: null, addedAt: new Date() }],
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
        providers: [{ providerId: 'oauth:authGoogle', providerSub: null, addedAt: new Date() }],
      })
      await expect(facet.link(i.id, { providerId: 'oauth:authGoogle', providerSub: null })).rejects.toMatchObject({
        code: 'AUTH_PROVIDER_FAILED',
      })
    })

    it('unlink refuses the last provider (leaves account inaccessible)', async () => {
      const i = await facet.create({
        profile: { username: 'a@x.com', email: 'a@x.com' },
        providers: [{ providerId: 'password', providerSub: null, addedAt: new Date() }],
      })
      await expect(facet.unlink(i.id, 'password')).rejects.toMatchObject({
        code: 'AUTH_PROVIDER_FAILED',
      })
    })

    it('unlink succeeds when 2+ providers remain', async () => {
      const i = await facet.create({
        profile: { username: 'a@x.com', email: 'a@x.com' },
        providers: [
          { providerId: 'password', providerSub: null, addedAt: new Date() },
          { providerId: 'oauth:authGoogle', providerSub: null, addedAt: new Date() },
        ],
      })
      await facet.unlink(i.id, 'oauth:authGoogle')
      const fresh = await facet.getById(i.id)
      expect(fresh?.providers).toHaveLength(1)
    })
  })

  describe('merge', () => {
    it('refuses to merge identity into itself', async () => {
      const i = await facet.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
      await expect(facet.merge(i.id, i.id)).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
    })

    it('merges dup into survivor and emits identity.merged', async () => {
      const survivor = await facet.create({
        profile: { username: 's@x.com', email: 's@x.com' },
        providers: [{ providerId: 'password', providerSub: null, addedAt: new Date() }],
      })
      const dup = await facet.create({
        profile: { username: 'd@x.com', email: 'd@x.com' },
        providers: [{ providerId: 'oauth:authGoogle', providerSub: 'g-1', addedAt: new Date() }],
      })
      const handler = vi.fn()
      events.on('identity.merged', handler)
      await facet.merge(survivor.id, dup.id)
      expect(handler).toHaveBeenCalledOnce()
      const fresh = await facet.getById(survivor.id)
      expect(fresh?.providers.some((p) => p.providerId === 'oauth:authGoogle')).toBe(true)
      expect(await facet.getById(dup.id)).toBeNull()
    })
  })

  describe('soft delete / restore / erase', () => {
    it('softDelete hides the identity from findById; restore brings it back', async () => {
      const i = await facet.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
      await facet.softDelete(i.id)
      expect(await facet.getById(i.id)).toBeNull()
      const back = await facet.restore(i.id)
      expect(back.id).toBe(i.id)
      expect(await facet.getById(i.id)).not.toBeNull()
    })

    it('restore after grace expired surfaces AUTH_GRACE_EXPIRED', async () => {
      const tightFacet = new IdentitiesFacet<MyProfile>(adapter.identities, events, {
        softDeleteGracePeriodMs: 1, // 1ms grace = always expired by the time we check
      })
      const i = await tightFacet.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
      await tightFacet.softDelete(i.id)
      await new Promise((r) => setTimeout(r, 5))
      await expect(tightFacet.restore(i.id)).rejects.toMatchObject({ code: 'AUTH_GRACE_EXPIRED' })
    })

    it('erase hard-removes the identity', async () => {
      const i = await facet.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
      await facet.erase(i.id, { reason: 'gdpr-2026-05-25' })
      expect(await facet.getById(i.id)).toBeNull()
      await expect(facet.restore(i.id)).rejects.toMatchObject({ code: 'AUTH_UNAUTHENTICATED' })
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
        providers: [{ providerId: 'password', providerSub: null, addedAt: new Date() }],
      })
      await facet.bulkCreate(
        [
          {
            profile: { username: 'a@x.com', email: 'a@x.com' },
            providers: [{ providerId: 'oauth:authGoogle', providerSub: 'g', addedAt: new Date() }],
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
      await adapter.credentials.upsert(
        credentialInput({ identityId: i.id, kind: 'password', secret: 'argon2id$...', metadata: {} }),
        {},
      )
      const blob = await facet.exportAll(i.id, adapter.credentials)
      expect(blob.identity.id).toBe(i.id)
      expect(blob.credentials).toHaveLength(1)
      // Type assertion: `secret` must not appear in the exported credential.
      expect(blob.credentials[0]).not.toHaveProperty('secret')
    })

    it('throws AUTH/UNAUTHENTICATED for unknown identity', async () => {
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
          id: 'sid-hash-1',
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
      const j1 = IdentitiesFacet.exportToJson({ ...blob1, exportedAt: 0 })
      const j2 = IdentitiesFacet.exportToJson({ ...blob2, exportedAt: 0 })
      expect(j1).toBe(j2)
      expect(j1.split('\n')[0]).toBe('{')
    })
  })
})
