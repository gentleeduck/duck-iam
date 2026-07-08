import { beforeEach, describe, expect, it } from 'vitest'
import { credentialInput, identityInput } from '../../../test/store-inputs'
import { MemoryAdapter } from '../../../adapters/memory'
import { InMemoryEvents } from '../../events'
import { MfaFacet } from '../mfa'

describe('MfaFacet.verifyTotp / hasTotp - confirmed flag', () => {
  let adapter: MemoryAdapter
  let facet: MfaFacet
  const identityId = 'identity-1'

  beforeEach(() => {
    adapter = new MemoryAdapter()
    facet = new MfaFacet(adapter.credentials, new InMemoryEvents())
  })

  async function plant(metadata: unknown, secret = 'JBSWY3DPEHPK3PXP'): Promise<void> {
    await adapter.credentials.upsert(
      credentialInput({
        identityId,
        kind: 'totp',
        secret,
        metadata: metadata as Record<string, unknown>,
      }),
      {},
    )
  }

  it('hasTotp returns false for a row with confirmed: "yes" (string, not boolean)', async () => {
    await plant({ confirmed: 'yes' })
    expect(await facet.hasTotp(identityId)).toBe(false)
  })

  it('hasTotp returns false for a row with confirmed: 1 (number)', async () => {
    await plant({ confirmed: 1 })
    expect(await facet.hasTotp(identityId)).toBe(false)
  })

  it('hasTotp returns true for confirmed: true (strict boolean)', async () => {
    await plant({ confirmed: true })
    expect(await facet.hasTotp(identityId)).toBe(true)
  })

  it('hasTotp returns false when metadata is missing the field', async () => {
    await plant({})
    expect(await facet.hasTotp(identityId)).toBe(false)
  })

  it('hasTotp returns false when metadata is non-object', async () => {
    await plant('not-an-object')
    expect(await facet.hasTotp(identityId)).toBe(false)
  })

  it('authVerifyTotp returns false for non-string row.secret (corrupt adapter row)', async () => {
    // Plant a confirmed:true row but with a non-string secret (typo:
    // 12345 instead of 'JBSWY...'). The TOTP module would crash on
    // decodeBase32; the early-out keeps the request safe.
    await plant({ confirmed: true }, 12345 as unknown as string)
    expect(await facet.verifyTotp(identityId, '123456')).toBe(false)
  })
})
