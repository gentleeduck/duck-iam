/**
 * `randomBytes` is the whole secret. `randomToken(0)` answers `''` without complaint, so a zero makes
 * every key this facet ever mints the literal string `ak_live_` - a constant printed in the docs. One or
 * two bytes is the same problem wearing a number: the sign-in limiter buckets by the hash of the token
 * presented, so trying a different key each time costs an attacker nothing to spend.
 */
import { describe, expect, it } from 'vitest'
import { toApiKeysCfg } from '../api-key.constants'

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
