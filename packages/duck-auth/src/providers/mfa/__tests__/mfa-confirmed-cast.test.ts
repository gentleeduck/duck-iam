import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { InMemoryEvents } from '~/core/events'
import { credentialInput } from '~/test/store-inputs'
import { MfaImpl } from '../mfa'

describe('MfaFacet.verifyTotp / hasTotp - confirmed flag', () => {
  let adapter: MemoryAdapter
  let facet: MfaImpl
  const identityId = 'identity-1'

  beforeEach(() => {
    adapter = new MemoryAdapter()
    facet = new MfaImpl(adapter.credentials, new InMemoryEvents())
  })

  async function plant(metadata: unknown, secret = 'JBSWY3DPEHPK3PXP'): Promise<void> {
    const row = await adapter.credentials.create(
      credentialInput({
        identityId,
        kind: 'totp',
        secret: 'JBSWY3DPEHPK3PXP',
        metadata: metadata as Record<string, unknown>,
      }),
      {},
    )
    // A non-string secret is a corrupt row, not a write: every dialect's column refuses it and so does
    // memory, so it is planted past the write path rather than through it.
    adapter.raw.credentials.set(row.id, { ...row, secret })
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

  it('verifyTotp returns false for non-string row.secret (corrupt adapter row)', async () => {
    // Plant a confirmed:true row but with a non-string secret (typo:
    // 12345 instead of 'JBSWY...'). The TOTP module would crash on
    // decodeBase32; the early-out keeps the request safe.
    await plant({ confirmed: true }, 12345 as unknown as string)
    expect(await facet.verifyTotp(identityId, '123456')).toBe(false)
  })
})
