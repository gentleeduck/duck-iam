/**
 * `randomBytes` is the whole secret. `randomToken(0)` answers `''` without complaint, so a zero makes
 * every key this facet ever mints the literal string `ak_live_` - a constant printed in the docs. One or
 * two bytes is the same problem wearing a number: the sign-in limiter buckets by the hash of the token
 * presented, so trying a different key each time costs an attacker nothing to spend.
 *
 * The facet's constructor ran none of this: `apiKeysFacet(..., { prefix: 'ak_', randomBytes: 0 })` minted
 * `ak_`, and `verify('ak_')` answered as the key's owner. Nor did anything bound the length, so a large
 * `randomBytes` or a long prefix minted keys that `verify` refuses for being over its cap.
 */
import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { randomToken, sha256 } from '~/core/crypto'
import { InMemoryEvents } from '~/core/events'
import { ApiKeysFacet, apiKeysFacet } from '../api-key'
import { APIKEY_MAX_LENGTH, toApiKeysCfg } from '../api-key.constants'

const CRYPTO = { randomToken, sha256 }

describe('the api-key secret must have enough bytes to be a secret', () => {
  for (const randomBytes of [0, 1, 8, 15]) {
    it(`refuses randomBytes: ${randomBytes}`, () => {
      expect(() => toApiKeysCfg({ randomBytes })).toThrowError(
        expect.objectContaining({
          code: 'AUTH_MISCONFIGURED',
          meta: expect.objectContaining({ detail: expect.stringMatching(/randomBytes/) }),
        }),
      )
    })
  }

  for (const randomBytes of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
    it(`refuses a randomBytes that is not a whole count: ${randomBytes}`, () => {
      expect(() => toApiKeysCfg({ randomBytes })).toThrowError(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
    })
  }

  it('accepts the documented minimum', () => {
    expect(toApiKeysCfg({ randomBytes: 16 }).randomBytes).toBe(16)
  })

  it('accepts the default when nothing is passed', () => {
    expect(toApiKeysCfg().randomBytes).toBe(32)
  })

  it('a compliance preset still ratchets a lower-but-legal value up', () => {
    expect(toApiKeysCfg({ compliance: 'hipaa', randomBytes: 16 }).randomBytes).toBeGreaterThanOrEqual(32)
  })
})

describe('a facet built by hand runs the same check', () => {
  const credentials = new MemoryAdapter().credentials
  const bus = new InMemoryEvents()

  it('refuses randomBytes: 0 through the constructor and the factory', () => {
    const misconfigured = expect.objectContaining({ code: 'AUTH_MISCONFIGURED' })
    expect(() => new ApiKeysFacet(credentials, bus, CRYPTO, { prefix: 'ak_', randomBytes: 0 })).toThrowError(
      misconfigured,
    )
    expect(() => apiKeysFacet(credentials, bus, CRYPTO, { prefix: 'ak_', randomBytes: 0 })).toThrowError(misconfigured)
  })

  it('builds on the defaults, where the bare prefix is not a key', async () => {
    const facet = apiKeysFacet(credentials, bus, CRYPTO)
    const { plaintext } = await facet.create('identity-1', { name: 'k', scopes: [] })
    await expect(facet.verify(plaintext)).resolves.toMatchObject({ identityId: 'identity-1' })
    await expect(facet.verify('ak_live_')).rejects.toMatchObject({ code: 'AUTH_APIKEY_INVALID' })
  })
})

describe('a key verify would refuse is never minted', () => {
  it('mints and verifies a key of exactly the length verify accepts', async () => {
    const facet = new ApiKeysFacet(new MemoryAdapter().credentials, new InMemoryEvents(), CRYPTO, { randomBytes: 378 })
    const { plaintext } = await facet.create('identity-1', { name: 'k', scopes: [] })
    expect(plaintext).toHaveLength(APIKEY_MAX_LENGTH)
    await expect(facet.verify(plaintext)).resolves.toMatchObject({ identityId: 'identity-1' })
  })

  it.each([{ randomBytes: 379 }, { prefix: 'p'.repeat(470) }])('refuses %j', (cfg) => {
    expect(() => toApiKeysCfg(cfg)).toThrowError(
      expect.objectContaining({
        code: 'AUTH_MISCONFIGURED',
        meta: expect.objectContaining({ detail: expect.stringMatching(/over the 512 verify accepts/) }),
      }),
    )
  })
})
