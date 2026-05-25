import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAuthAdapter } from '../../../adapters/memory'
import { randomToken, sha256 } from '../../crypto'
import { InMemoryEvents } from '../../events'
import { ApiKeysFacet, DEFAULT_APIKEYS_CONFIG } from '../apikeys'

describe('ApiKeysFacet', () => {
  let adapter: MemoryAuthAdapter
  let events: InMemoryEvents
  let facet: ApiKeysFacet

  beforeEach(() => {
    adapter = new MemoryAuthAdapter()
    events = new InMemoryEvents()
    facet = new ApiKeysFacet(adapter.credentials, events, { randomToken, sha256 }, DEFAULT_APIKEYS_CONFIG)
  })

  describe('create', () => {
    it('returns plaintext once + persists hash; metadata carries name + scopes', async () => {
      const { key, plaintext } = await facet.create('user-1', {
        name: 'CI deploy',
        scopes: ['deploy.write'],
      })
      expect(plaintext.startsWith('ak_live_')).toBe(true)
      expect(plaintext.length).toBeGreaterThan('ak_live_'.length + 30)
      const rows = await adapter.credentials.listByIdentity('user-1', 'api-key', {})
      expect(rows).toHaveLength(1)
      expect(rows[0]?.secret).toBe(sha256(plaintext))
      expect((rows[0]?.metadata as { scopes: string[] }).scopes).toEqual(['deploy.write'])
      expect(key.name).toBe('CI deploy')
    })

    it('respects expiresAt + tenantId', async () => {
      const expiresAt = Date.now() + 1000
      const { key } = await facet.create('u', { name: 'k', scopes: [], expiresAt, tenantId: 'T' })
      expect(key.expiresAt).toBe(expiresAt)
    })
  })

  describe('verify', () => {
    it('happy path returns identity + scopes', async () => {
      const { plaintext } = await facet.create('user-1', { name: 'k', scopes: ['read'] })
      const v = await facet.verify(plaintext)
      expect(v.identityId).toBe('user-1')
      expect(v.scopes).toEqual(['read'])
    })

    it('wrong prefix surfaces AUTH/APIKEY_INVALID without lookup', async () => {
      await expect(facet.verify('not-our-prefix-token')).rejects.toMatchObject({ code: 'AUTH/APIKEY_INVALID' })
    })

    it('unknown token surfaces AUTH/APIKEY_INVALID', async () => {
      await expect(facet.verify('ak_live_aaaaaaaa')).rejects.toMatchObject({ code: 'AUTH/APIKEY_INVALID' })
    })

    it('revoked token surfaces AUTH/APIKEY_REVOKED', async () => {
      const { key, plaintext } = await facet.create('user-1', { name: 'k', scopes: [] })
      await facet.revoke(key.id)
      await expect(facet.verify(plaintext)).rejects.toMatchObject({ code: 'AUTH/APIKEY_REVOKED' })
    })

    it('expired token surfaces AUTH/APIKEY_REVOKED', async () => {
      const { plaintext } = await facet.create('user-1', { name: 'k', scopes: [], expiresAt: Date.now() - 1 })
      await expect(facet.verify(plaintext)).rejects.toMatchObject({ code: 'AUTH/APIKEY_REVOKED' })
    })
  })

  describe('rotate', () => {
    it('issues a new plaintext + revokes the old row', async () => {
      const { key, plaintext: oldPlain } = await facet.create('user-1', {
        name: 'k',
        scopes: ['read'],
      })
      const { plaintext: newPlain } = await facet.rotate(key.id)
      expect(newPlain).not.toBe(oldPlain)
      await expect(facet.verify(oldPlain)).rejects.toMatchObject({ code: 'AUTH/APIKEY_REVOKED' })
      const v = await facet.verify(newPlain)
      expect(v.scopes).toEqual(['read'])
    })

    it('rotate on missing key surfaces AUTH/APIKEY_INVALID', async () => {
      await expect(facet.rotate('does-not-exist')).rejects.toMatchObject({ code: 'AUTH/APIKEY_INVALID' })
    })
  })

  describe('list + requireScopes', () => {
    it('list returns metadata without plaintext', async () => {
      await facet.create('user-1', { name: 'A', scopes: ['x'] })
      await facet.create('user-1', { name: 'B', scopes: ['y'] })
      const ks = await facet.list('user-1')
      expect(ks).toHaveLength(2)
      expect(ks.map((k) => k.name).sort()).toEqual(['A', 'B'])
    })

    it('requireScopes throws AUTH/APIKEY_SCOPE_INSUFFICIENT when missing', () => {
      expect(() => facet.requireScopes(['read'], ['write'])).toThrow()
      expect(() => facet.requireScopes(['read', 'write'], ['write'])).not.toThrow()
    })
  })
})
