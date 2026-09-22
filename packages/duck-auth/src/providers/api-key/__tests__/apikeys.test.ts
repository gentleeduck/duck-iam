import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { randomToken, sha256 } from '~/core/crypto'
import { InMemoryEvents } from '~/core/events'
import { credentialInput } from '~/test/store-inputs'
import { ApiKeysFacet } from '../api-key'
import { DEFAULT_APIKEYS_CONFIG } from '../api-key.constants'

describe('ApiKeysFacet', () => {
  let adapter: MemoryAdapter
  let events: InMemoryEvents
  let facet: ApiKeysFacet

  beforeEach(() => {
    adapter = new MemoryAdapter()
    events = new InMemoryEvents()
    facet = new ApiKeysFacet(
      adapter.credentials,
      events,
      { randomToken: randomToken, sha256: sha256 },
      DEFAULT_APIKEYS_CONFIG,
    )
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
      expect(key.expiresAt).toEqual(new Date(expiresAt))
    })
  })

  describe('verify', () => {
    it('happy path returns identity + scopes', async () => {
      const { plaintext } = await facet.create('user-1', { name: 'k', scopes: ['read'] })
      const v = await facet.verify(plaintext)
      expect(v.identityId).toBe('user-1')
      expect(v.scopes).toEqual(['read'])
    })

    it('wrong prefix surfaces AUTH_APIKEY_INVALID without lookup', async () => {
      await expect(facet.verify('not-our-prefix-token')).rejects.toMatchObject({ code: 'AUTH_APIKEY_INVALID' })
    })

    it('unknown token surfaces AUTH_APIKEY_INVALID', async () => {
      await expect(facet.verify('ak_live_aaaaaaaa')).rejects.toMatchObject({ code: 'AUTH_APIKEY_INVALID' })
    })

    it('revoked token surfaces AUTH_APIKEY_REVOKED', async () => {
      const { key, plaintext } = await facet.create('user-1', { name: 'k', scopes: [] })
      const revoked = await facet.revoke(key.id)
      // The key that went, named and scoped, so a "key revoked" confirmation
      // needs no read - and `list` would no longer return it anyway.
      expect(revoked).toMatchObject({ id: key.id, identityId: 'user-1', name: 'k' })
      await expect(facet.verify(plaintext)).rejects.toMatchObject({ code: 'AUTH_APIKEY_REVOKED' })
    })

    it('revoking a key that is not there rejects, and orNull reads that as null', async () => {
      const missing = '01900000-0000-7000-8000-000000000000'
      await expect(facet.revoke(missing)).rejects.toMatchObject({ code: 'AUTH_CREDENTIAL_NOT_FOUND' })
      await expect(facet.revoke(missing).orNull()).resolves.toBeNull()
    })

    it('expired token surfaces AUTH_APIKEY_REVOKED', async () => {
      const { plaintext } = await facet.create('user-1', { name: 'k', scopes: [], expiresAt: Date.now() + 60_000 })
      const row = await adapter.credentials.findByHashedSecret(sha256(plaintext), 'api-key', {})
      if (!row) throw new Error('row missing')
      // A key reaches this state by time passing, never by being created already expired:
      // `chk_auth_credentials_expires_after_created` refuses that write on every dialect, and so does memory.
      adapter.raw.credentials.set(row.id, { ...row, expiresAt: new Date(Date.now() - 1) })
      await expect(facet.verify(plaintext)).rejects.toMatchObject({ code: 'AUTH_APIKEY_REVOKED' })
    })

    describe('defensive guards against malformed adapter rows', () => {
      async function createAndGrabRow(): Promise<{
        plaintext: string
        row: NonNullable<Awaited<ReturnType<typeof adapter.credentials.findByHashedSecret>>>
      }> {
        const { plaintext } = await facet.create('user-1', { name: 'k', scopes: ['read'] })
        const row = await adapter.credentials.findByHashedSecret(sha256(plaintext), 'api-key', {})
        if (!row) throw new Error('row missing')
        return { plaintext, row }
      }

      it('revokedAt === 0 (legitimate epoch number) surfaces as revoked (previously slipped past `if (row.revokedAt)`)', async () => {
        const { plaintext, row } = await createAndGrabRow()
        adapter.raw.credentials.set(row.id, { ...row, revokedAt: new Date(0) })
        await expect(facet.verify(plaintext)).rejects.toMatchObject({ code: 'AUTH_APIKEY_REVOKED' })
      })

      it('revokedAt as a non-numeric value surfaces as revoked', async () => {
        const { plaintext, row } = await createAndGrabRow()
        // @ts-expect-error: SEC test intentionally violates the typed shape
        adapter.raw.credentials.set(row.id, { ...row, revokedAt: 'compromised-marker' })
        await expect(facet.verify(plaintext)).rejects.toMatchObject({ code: 'AUTH_APIKEY_REVOKED' })
      })

      it('non-numeric expiresAt is treated as expired (NaN-bypass defense - would have accepted expired key)', async () => {
        const { plaintext, row } = await createAndGrabRow()
        // @ts-expect-error: SEC test intentionally violates the typed shape
        adapter.raw.credentials.set(row.id, { ...row, expiresAt: 'not-a-number' })
        await expect(facet.verify(plaintext)).rejects.toMatchObject({ code: 'AUTH_APIKEY_REVOKED' })
      })

      it('list() filters out keys with revokedAt === 0 (previously visible via `!r.revokedAt`)', async () => {
        const { plaintext, row } = await createAndGrabRow()
        adapter.raw.credentials.set(row.id, { ...row, revokedAt: new Date(0) })
        const visible = await facet.list('user-1')
        expect(visible.find((k) => k.id === row.id)).toBeUndefined()
        // Sanity: verify is also fail-closed.
        await expect(facet.verify(plaintext)).rejects.toMatchObject({ code: 'AUTH_APIKEY_REVOKED' })
      })
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
      await expect(facet.verify(oldPlain)).rejects.toMatchObject({ code: 'AUTH_APIKEY_REVOKED' })
      const v = await facet.verify(newPlain)
      expect(v.scopes).toEqual(['read'])
    })

    it('rotate on missing key surfaces AUTH_APIKEY_INVALID', async () => {
      await expect(facet.rotate('does-not-exist')).rejects.toMatchObject({ code: 'AUTH_APIKEY_INVALID' })
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

    it('requireScopes throws AUTH_APIKEY_SCOPE_INSUFFICIENT when missing', () => {
      expect(() => facet.requireScopes(['read'], ['write'])).toThrow()
      expect(() => facet.requireScopes(['read', 'write'], ['write'])).not.toThrow()
    })
  })
  describe('revoke', () => {
    it('rejects an unknown key rather than answering null', async () => {
      await expect(facet.revoke('no-such-row')).rejects.toMatchObject({ code: 'AUTH_CREDENTIAL_NOT_FOUND' })
      await expect(facet.revoke('no-such-row').orNull()).resolves.toBeNull()
    })

    it('rejects a row that is not an api key, and leaves it alone', async () => {
      // SECURITY: the row must come back unrevoked. Revoking first and rejecting on `kind` afterwards
      // would make this facet a way to revoke someone's recovery codes or passkey through the
      // api-keys route, and report that it did nothing.
      const cred = await adapter.credentials.create(
        credentialInput({ identityId: 'user-1', kind: 'recovery', secret: sha256('x') }),
        {},
      )

      await expect(facet.revoke(cred.id)).rejects.toMatchObject({ code: 'AUTH_CREDENTIAL_NOT_FOUND' })
      await expect(adapter.credentials.findById(cred.id, {})).resolves.toMatchObject({ revokedAt: null })
    })

    it('answers the key it revoked, so a caller can name it', async () => {
      const { key } = await facet.create('user-1', { name: 'CI deploy', scopes: ['deploy.write'] })
      await expect(facet.revoke(key.id)).resolves.toMatchObject({ name: 'CI deploy' })
    })
  })
})
