import { describe, expect, it } from 'vitest'
import { iamExtractEnvironment } from '../index'

/**
 * `userAgent` is attacker-controlled and flows into `matches` conditions, which
 * throw above MAX_REGEX_INPUT_LENGTH. The IP headers are already capped; the
 * user agent must be too, so an oversized header cannot perturb evaluation.
 */
describe('iamExtractEnvironment user-agent cap', () => {
  it('drops an oversized user agent instead of passing it through', () => {
    const env = iamExtractEnvironment({ headers: { 'user-agent': 'x'.repeat(5000) } })
    expect(env.userAgent).toBeUndefined()
  })

  it('keeps a normal user agent verbatim', () => {
    expect(iamExtractEnvironment({ headers: { 'user-agent': 'curl/8.4.0' } }).userAgent).toBe('curl/8.4.0')
  })
})
