import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { randomToken, sha256 } from '~/core/crypto'
import { InMemoryEvents } from '~/core/events'
import { ApiKeysFacet } from '../api-key'
import { DEFAULT_APIKEYS_CONFIG } from '../api-key.constants'

/**
 * `ApiKeys.ApiKey` declares four `Date` fields. Every one of them has to be a
 * real `Date` on the way out, and `revokedAt` has to be there at all - the
 * projection used to drop it, so `revoke()`'s documented answer ("the key as it
 * stands revoked") carried nothing that said so.
 */
describe('ApiKeysFacet date fidelity', () => {
  let adapter: MemoryAdapter
  let facet: ApiKeysFacet

  beforeEach(() => {
    adapter = new MemoryAdapter()
    facet = new ApiKeysFacet(adapter.credentials, new InMemoryEvents(), { randomToken, sha256 }, DEFAULT_APIKEYS_CONFIG)
  })

  it('create returns a real Date for createdAt and expiresAt', async () => {
    const expiresAt = Date.now() + 60_000
    const { key } = await facet.create('u-1', { name: 'k', scopes: [], expiresAt })
    expect(key.createdAt).toBeInstanceOf(Date)
    expect(Number.isFinite(key.createdAt.getTime())).toBe(true)
    expect(key.expiresAt).toBeInstanceOf(Date)
    expect(key.expiresAt?.getTime()).toBe(expiresAt)
  })

  it('list returns real Dates and no revokedAt, because it only lists live keys', async () => {
    const expiresAt = Date.now() + 60_000
    await facet.create('u-1', { name: 'k', scopes: [], expiresAt })
    const [key] = await facet.list('u-1')
    expect(key?.createdAt).toBeInstanceOf(Date)
    expect(key?.expiresAt).toBeInstanceOf(Date)
    expect(key?.revokedAt).toBeUndefined()
  })

  it('revoke answers with revokedAt set, so a caller can see which key went', async () => {
    const { key } = await facet.create('u-1', { name: 'k', scopes: [] })
    const revoked = await facet.revoke(key.id)
    expect(revoked?.id).toBe(key.id)
    expect(revoked?.revokedAt).toBeInstanceOf(Date)
    expect(Number.isFinite(revoked?.revokedAt?.getTime() ?? Number.NaN)).toBe(true)
  })

  it('lastUsedAt comes back as a Date once verify has stamped it', async () => {
    const { key, plaintext } = await facet.create('u-1', { name: 'k', scopes: [] })
    await facet.verify(plaintext)
    // `verify` stamps the row in the background; read it back off the store.
    const row = await adapter.credentials.findById(key.id, {})
    expect(row?.lastUsedAt).toBeInstanceOf(Date)
    const [listed] = await facet.list('u-1')
    expect(listed?.lastUsedAt).toBeInstanceOf(Date)
  })
})
