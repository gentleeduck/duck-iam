import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAuthAdapter } from '../../../adapters/memory'
import { InMemoryEvents } from '../../events'
import { DEFAULT_IDENTITIES_CONFIG, IdentitiesFacet } from '../identities'

interface MyProfile {
  email: string
  name?: string
  roles?: string[]
}

describe('IdentitiesFacet', () => {
  let adapter: MemoryAuthAdapter<MyProfile>
  let events: InMemoryEvents
  let facet: IdentitiesFacet<MyProfile>

  beforeEach(() => {
    adapter = new MemoryAuthAdapter<MyProfile>()
    events = new InMemoryEvents()
    facet = new IdentitiesFacet<MyProfile>(adapter.identities, events, DEFAULT_IDENTITIES_CONFIG)
  })

  describe('create', () => {
    it('creates an identity and emits signup.completed', async () => {
      const handler = vi.fn()
      events.on('signup.completed', handler)
      const i = await facet.create({ profile: { email: 'a@x.com' } })
      expect(i.profile?.email).toBe('a@x.com')
      expect(i.version).toBe(1)
      expect(handler).toHaveBeenCalledOnce()
    })

    it('respects tenantId scoping (findByEmail in tenant A misses tenant B)', async () => {
      await facet.create({ profile: { email: 'shared@x.com' }, tenantId: 'A' }, { tenantId: 'A' })
      const inB = await facet.getByEmail('shared@x.com', { tenantId: 'B' })
      expect(inB).toBeNull()
    })
  })

  describe('updateProfile w/ optimistic locking', () => {
    it('happy path: returns new version', async () => {
      const i = await facet.create({ profile: { email: 'a@x.com' } })
      const updated = await facet.updateProfile(i.id, { name: 'Alice' }, i.version)
      expect(updated.profile?.name).toBe('Alice')
      expect(updated.version).toBe(2)
    })

    it('stale write surfaces AUTH/STALE_WRITE', async () => {
      const i = await facet.create({ profile: { email: 'a@x.com' } })
      // First update bumps version 1 -> 2.
      await facet.updateProfile(i.id, { name: 'Alice' }, 1)
      // Second update with expectedVersion=1 collides.
      await expect(facet.updateProfile(i.id, { name: 'Eve' }, 1)).rejects.toMatchObject({
        code: 'AUTH/STALE_WRITE',
        meta: { expected: 1, actual: 2 },
      })
    })
  })

  describe('link / unlink', () => {
    it('link emits identity.linked + persists the provider entry', async () => {
      const i = await facet.create({
        profile: { email: 'a@x.com' },
        providers: [{ providerId: 'password', addedAt: Date.now() }],
      })
      const handler = vi.fn()
      events.on('identity.linked', handler)
      await facet.link(i.id, { providerId: 'oauth:google', providerSub: 'g-123' })
      expect(handler).toHaveBeenCalledOnce()
      const fresh = await facet.getById(i.id)
      expect(fresh?.providers.some((p) => p.providerId === 'oauth:google')).toBe(true)
    })

    it('link rejects duplicate providerId for same identity', async () => {
      const i = await facet.create({
        profile: { email: 'a@x.com' },
        providers: [{ providerId: 'oauth:google', addedAt: Date.now() }],
      })
      await expect(facet.link(i.id, { providerId: 'oauth:google' })).rejects.toMatchObject({
        code: 'AUTH/PROVIDER_FAILED',
      })
    })

    it('unlink refuses the last provider (leaves account inaccessible)', async () => {
      const i = await facet.create({
        profile: { email: 'a@x.com' },
        providers: [{ providerId: 'password', addedAt: Date.now() }],
      })
      await expect(facet.unlink(i.id, 'password')).rejects.toMatchObject({
        code: 'AUTH/PROVIDER_FAILED',
      })
    })

    it('unlink succeeds when 2+ providers remain', async () => {
      const i = await facet.create({
        profile: { email: 'a@x.com' },
        providers: [
          { providerId: 'password', addedAt: Date.now() },
          { providerId: 'oauth:google', addedAt: Date.now() },
        ],
      })
      await facet.unlink(i.id, 'oauth:google')
      const fresh = await facet.getById(i.id)
      expect(fresh?.providers).toHaveLength(1)
    })
  })

  describe('merge', () => {
    it('refuses to merge identity into itself', async () => {
      const i = await facet.create({ profile: { email: 'a@x.com' } })
      await expect(facet.merge(i.id, i.id)).rejects.toMatchObject({ code: 'AUTH/PROVIDER_FAILED' })
    })

    it('merges dup into survivor and emits identity.merged', async () => {
      const survivor = await facet.create({
        profile: { email: 's@x.com' },
        providers: [{ providerId: 'password', addedAt: Date.now() }],
      })
      const dup = await facet.create({
        profile: { email: 'd@x.com' },
        providers: [{ providerId: 'oauth:google', providerSub: 'g-1', addedAt: Date.now() }],
      })
      const handler = vi.fn()
      events.on('identity.merged', handler)
      await facet.merge(survivor.id, dup.id)
      expect(handler).toHaveBeenCalledOnce()
      const fresh = await facet.getById(survivor.id)
      expect(fresh?.providers.some((p) => p.providerId === 'oauth:google')).toBe(true)
      expect(await facet.getById(dup.id)).toBeNull()
    })
  })

  describe('soft delete / restore / erase', () => {
    it('softDelete hides the identity from findById; restore brings it back', async () => {
      const i = await facet.create({ profile: { email: 'a@x.com' } })
      await facet.softDelete(i.id)
      expect(await facet.getById(i.id)).toBeNull()
      const back = await facet.restore(i.id)
      expect(back.id).toBe(i.id)
      expect(await facet.getById(i.id)).not.toBeNull()
    })

    it('restore after grace expired surfaces AUTH/GRACE_EXPIRED', async () => {
      const tightFacet = new IdentitiesFacet<MyProfile>(adapter.identities, events, {
        softDeleteGracePeriodMs: 1, // 1ms grace = always expired by the time we check
      })
      const i = await tightFacet.create({ profile: { email: 'a@x.com' } })
      await tightFacet.softDelete(i.id)
      await new Promise((r) => setTimeout(r, 5))
      await expect(tightFacet.restore(i.id)).rejects.toMatchObject({ code: 'AUTH/GRACE_EXPIRED' })
    })

    it('erase hard-removes the identity', async () => {
      const i = await facet.create({ profile: { email: 'a@x.com' } })
      await facet.erase(i.id, { reason: 'gdpr-2026-05-25' })
      expect(await facet.getById(i.id)).toBeNull()
      await expect(facet.restore(i.id)).rejects.toMatchObject({ code: 'AUTH/UNAUTHENTICATED' })
    })
  })

  describe('bulkCreate', () => {
    it('skipExisting (default) leaves duplicates alone', async () => {
      await facet.create({ profile: { email: 'a@x.com' } })
      const r = await facet.bulkCreate([{ profile: { email: 'a@x.com' } }, { profile: { email: 'b@x.com' } }])
      expect(r).toEqual({ created: 1, skipped: 1, failed: 0 })
    })

    it('merge appends new providers to existing identity', async () => {
      const i = await facet.create({
        profile: { email: 'a@x.com' },
        providers: [{ providerId: 'password', addedAt: Date.now() }],
      })
      await facet.bulkCreate(
        [
          {
            profile: { email: 'a@x.com' },
            providers: [{ providerId: 'oauth:google', providerSub: 'g', addedAt: Date.now() }],
          },
        ],
        { mode: 'merge' },
      )
      const fresh = await facet.getById(i.id)
      expect(fresh?.providers.some((p) => p.providerId === 'oauth:google')).toBe(true)
    })

    it('replace erases pre-existing identities by email then creates fresh', async () => {
      const before = await facet.create({ profile: { email: 'a@x.com', name: 'Old' } })
      await facet.bulkCreate([{ profile: { email: 'a@x.com', name: 'New' } }], { mode: 'replace' })
      const survivor = await facet.getByEmail('a@x.com')
      expect(survivor?.id).not.toBe(before.id)
      expect(survivor?.profile?.name).toBe('New')
    })
  })

  describe('exportAll', () => {
    it('strips credential secrets and includes identity + redacted credentials list', async () => {
      const i = await facet.create({ profile: { email: 'a@x.com' } })
      await adapter.credentials.upsert({ identityId: i.id, kind: 'password', secret: 'argon2id$...', metadata: {} }, {})
      const blob = await facet.exportAll(i.id, adapter.credentials)
      expect(blob.identity.id).toBe(i.id)
      expect(blob.credentials).toHaveLength(1)
      // Type assertion: `secret` must not appear in the exported credential.
      expect(blob.credentials[0]).not.toHaveProperty('secret')
    })

    it('throws AUTH/UNAUTHENTICATED for unknown identity', async () => {
      await expect(facet.exportAll('nope', adapter.credentials)).rejects.toMatchObject({
        code: 'AUTH/UNAUTHENTICATED',
      })
    })
  })
})
