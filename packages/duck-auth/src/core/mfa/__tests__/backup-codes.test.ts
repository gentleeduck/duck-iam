import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '../../../adapters/memory'
import { credentialInput, identityInput } from '../../../test/store-inputs'
import { randomToken, sha256 } from '../../crypto'
import { BackupCodesFacet } from '../backup-codes'

describe('AuthBackupCodesFacet', () => {
  let adapter: MemoryAdapter
  let facet: BackupCodesFacet
  let identityId: string

  beforeEach(async () => {
    adapter = new MemoryAdapter()
    facet = new BackupCodesFacet(adapter.credentials, { authRandomToken: randomToken, authSha256: sha256 })
    const ident = await adapter.identities.create(
      identityInput({ profile: { email: 'a@b.com', username: 'a' }, providers: [] }),
      {},
    )
    identityId = ident.id
  })

  it('generate emits the configured count of codes + persists hashes', async () => {
    const { codes } = await facet.generate(identityId)
    expect(codes).toHaveLength(10)
    for (const code of codes) {
      expect(code).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/)
    }
    const rows = await adapter.credentials.listByIdentity(identityId, 'recovery', {})
    expect(rows).toHaveLength(10)
    expect(rows[0]!.secret).not.toBe(codes[0])
  })

  it('verify consumes the code (single use)', async () => {
    const { codes } = await facet.generate(identityId)
    const code = codes[0]!
    expect(await facet.verify(identityId, code)).toBe(true)
    expect(await facet.verify(identityId, code)).toBe(false)
  })

  it('verify returns false for wrong code without throwing', async () => {
    await facet.generate(identityId)
    expect(await facet.verify(identityId, 'WRONG-CODE')).toBe(false)
  })

  it('verify throws AUTH/RECOVERY_TOKEN_INVALID on obviously bogus input', async () => {
    await facet.generate(identityId)
    await expect(facet.verify(identityId, '')).rejects.toMatchObject({
      code: 'AUTH_RECOVERY_TOKEN_INVALID',
    })
    await expect(facet.verify(identityId, 'AB')).rejects.toMatchObject({
      code: 'AUTH_RECOVERY_TOKEN_INVALID',
    })
  })

  it('verify is case + dash forgiving', async () => {
    const { codes } = await facet.generate(identityId)
    const code = codes[0]!
    const munged = code.toLowerCase().replace('-', '')
    expect(await facet.verify(identityId, munged)).toBe(true)
  })

  it('generate twice replaces the prior set', async () => {
    const first = await facet.generate(identityId)
    const second = await facet.generate(identityId)
    // First-set codes no longer verify after regenerate.
    expect(await facet.verify(identityId, first.codes[0]!)).toBe(false)
    expect(await facet.verify(identityId, second.codes[0]!)).toBe(true)
  })

  it('remaining returns count of unused codes', async () => {
    const { codes } = await facet.generate(identityId)
    expect(await facet.remaining(identityId)).toBe(10)
    await facet.verify(identityId, codes[0]!)
    expect(await facet.remaining(identityId)).toBe(9)
  })

  it('revokeAll wipes every backup code', async () => {
    await facet.generate(identityId)
    await facet.revokeAll(identityId)
    expect(await facet.remaining(identityId)).toBe(0)
  })

  it('respects custom count config', async () => {
    const small = new BackupCodesFacet(
      adapter.credentials,
      { authRandomToken: randomToken, authSha256: sha256 },
      { count: 3, byteLength: 5, groupFour: true },
    )
    const { codes } = await small.generate(identityId)
    expect(codes).toHaveLength(3)
  })
})
