import { describe, expect, it } from 'vitest'
import { iamExtractEnvironment } from '../index'

// SECURITY: `userAgent` is attacker-controlled and feeds `matches` conditions, which throw above
// MAX_REGEX_INPUT_LENGTH, so it is capped like the IP headers.
describe('iamExtractEnvironment user-agent cap', () => {
  it('drops an oversized user agent instead of passing it through', () => {
    const env = iamExtractEnvironment({ headers: { 'user-agent': 'x'.repeat(5000) } })
    expect(env.userAgent).toBeUndefined()
  })

  it('keeps a normal user agent verbatim', () => {
    expect(iamExtractEnvironment({ headers: { 'user-agent': 'curl/8.4.0' } }).userAgent).toBe('curl/8.4.0')
  })
})
