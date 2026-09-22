import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { randomToken, sha256 } from '~/core/crypto'
import { identityInput } from '~/test/store-inputs'
import { BackupCodesFacet, DEFAULT_BACKUP_CODES_CONFIG } from '../internal/backup-codes'

const CRYPTO = { authRandomToken: randomToken, authSha256: sha256 }

describe('backup-code length follows byteLength', () => {
  let adapter: MemoryAdapter
  let identityId: string

  beforeEach(async () => {
    adapter = new MemoryAdapter()
    const ident = await adapter.identities.create(
      identityInput({ profile: { email: 'a@b.com', username: 'a' }, providers: [] }),
    )
    identityId = ident.id
  })

  it('the default config is unchanged: two groups of four', async () => {
    const facet = new BackupCodesFacet(adapter.credentials, CRYPTO)
    const { codes } = await facet.generate(identityId)
    for (const code of codes) expect(code).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/)
  })

  it('a larger byteLength mints a longer code instead of being ignored', async () => {
    const facet = new BackupCodesFacet(adapter.credentials, CRYPTO, {
      ...DEFAULT_BACKUP_CODES_CONFIG,
      byteLength: 10,
    })
    const { codes } = await facet.generate(identityId)
    // 10 bytes of entropy over a 32-character alphabet is 16 characters, grouped in fours.
    for (const code of codes) expect(code.replace(/-/g, '')).toHaveLength(16)
    expect(await facet.verify(identityId, codes[0] as string)).toBe(true)
  })

  it('groups every four characters, not only the first four', async () => {
    const facet = new BackupCodesFacet(adapter.credentials, CRYPTO, {
      ...DEFAULT_BACKUP_CODES_CONFIG,
      byteLength: 10,
    })
    const { codes } = await facet.generate(identityId)
    for (const code of codes) expect(code).toMatch(/^([A-Z0-9]{4}-){3}[A-Z0-9]{4}$/)
  })

  it('ungrouped output when groupFour is off, and it still verifies', async () => {
    const facet = new BackupCodesFacet(adapter.credentials, CRYPTO, {
      ...DEFAULT_BACKUP_CODES_CONFIG,
      byteLength: 10,
      groupFour: false,
    })
    const { codes } = await facet.generate(identityId)
    for (const code of codes) expect(code).toMatch(/^[A-Z0-9]{16}$/)
    expect(await facet.verify(identityId, codes[0] as string)).toBe(true)
  })
})

describe('a backup code is normalised the way its docstring says', () => {
  let adapter: MemoryAdapter
  let facet: BackupCodesFacet
  let identityId: string

  beforeEach(async () => {
    adapter = new MemoryAdapter()
    facet = new BackupCodesFacet(adapter.credentials, CRYPTO)
    const ident = await adapter.identities.create(
      identityInput({ profile: { email: 'a@b.com', username: 'a' }, providers: [] }),
    )
    identityId = ident.id
  })

  it('accepts the code with the hyphen in the wrong place', async () => {
    const { codes } = await facet.generate(identityId)
    const bare = (codes[0] as string).replace(/-/g, '')
    expect(await facet.verify(identityId, `${bare.slice(0, 2)}-${bare.slice(2)}`)).toBe(true)
  })

  it('refuses an oversize code rather than hashing it', async () => {
    await facet.generate(identityId)
    await expect(facet.verify(identityId, 'A'.repeat(5000))).rejects.toMatchObject({
      code: 'AUTH_RECOVERY_TOKEN_INVALID',
    })
  })
})
