import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { InMemoryEvents } from '~/core/events'
import { credentialInput } from '~/test/store-inputs'
import { matchTotpStep, TOTP_DEFAULTS, totpAt, verifyTotp } from '../internal/totp'
import { MfaImpl } from '../mfa'
import { DEFAULT_MFA_CONFIG } from '../mfa.constants'

/**
 * A base32 secret that decodes to nothing still makes a usable HMAC key - node pads it - so every code
 * it produces is derivable from the clock alone. A row blanked by a bad migration or a partial write
 * therefore verifies for anyone, while `hasTotp` goes on reporting the account as protected.
 */
describe('a TOTP secret that decodes to no bytes verifies nothing', () => {
  const step = Math.floor(Date.now() / 1000 / TOTP_DEFAULTS.periodSec)

  it('verifyTotp refuses the code derived from an empty secret', () => {
    expect(verifyTotp('', totpAt('', step))).toBe(false)
  })

  it('matchTotpStep refuses it too, so nothing can be spent against it', () => {
    expect(matchTotpStep('', totpAt('', step))).toBeNull()
  })

  it('refuses a secret of only padding and spaces, which decodes the same way', () => {
    expect(verifyTotp('==  ==', totpAt('', step))).toBe(false)
  })

  it('a real secret still verifies', () => {
    const secret = 'JBSWY3DPEHPK3PXP'
    expect(verifyTotp(secret, totpAt(secret, step))).toBe(true)
    expect(matchTotpStep(secret, totpAt(secret, step))).toBe(step)
  })

  it('MfaFacet.verifyTotp does not let a blanked row stand in for a second factor', async () => {
    const adapter = new MemoryAdapter()
    const facet = new MfaImpl(adapter.credentials, new InMemoryEvents(), DEFAULT_MFA_CONFIG)
    await adapter.credentials.create(
      // Padding only, not empty: the memory adapter refuses a secret that trims to nothing, and this
      // passes that guard while still decoding to zero bytes.
      credentialInput({ identityId: 'u', kind: 'totp', metadata: { confirmed: true }, secret: '======' }),
      {},
    )
    expect(await facet.hasTotp('u')).toBe(true)
    expect(await facet.verifyTotp('u', totpAt('', step))).toBe(false)
  })
})
