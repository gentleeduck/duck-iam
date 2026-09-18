/**
 * `toApiKeysCfg` refuses a short `randomBytes`, and the comment above it names the failure: a length of
 * zero makes `randomToken` answer `''`, so every key it mints is the bare prefix. The same knob sits on
 * three classes in this folder, unchecked, and on the one that is wired it is a second factor.
 *
 * Measured before the guards, with `mfa({ backupCodeLen: 0 })`: all ten of an identity's codes came back
 * as the literal `-`, and `verifyBackupCode` answered `true` for `-` on an account it had never been
 * issued to. `1` leaves 31 possibilities and `3` leaves about thirty thousand. A count that is not a
 * positive whole number deleted the codes the identity had and minted none.
 */
import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { randomToken, sha256 } from '~/core/crypto'
import type { Events } from '~/core/events'
import { identityInput } from '~/test/store-inputs'
import { BackupCodesFacet, DEFAULT_BACKUP_CODES_CONFIG } from '../internal/backup-codes'
import { DEFAULT_REMEMBER_ME_CONFIG, RememberMeFacet } from '../internal/remember-me'
import { MfaImpl } from '../mfa'

const CRYPTO = { authRandomToken: randomToken, authSha256: sha256 }
const bus = { emit: async () => {}, off: () => {}, on: () => () => {} } as unknown as Events.IBus

let seq = 0
async function identity(adapter: MemoryAdapter): Promise<string> {
  const n = seq++
  const row = await adapter.identities.create(
    identityInput({ profile: { email: `a${n}@b.com`, username: `u${n}` }, providers: [] }),
  )
  return row.id
}

/** The refusal's `detail`, since `AuthError.message` is the bare code. */
function refusal(build: () => unknown): string {
  try {
    build()
    return 'constructed'
  } catch (err) {
    return (err as { meta: { detail: string } }).meta.detail
  }
}

describe('MfaImpl refuses a backup-code shape that is not a secret', () => {
  const mfa = (cfg: { backupCodeCount?: number; backupCodeLen?: number }) =>
    new MfaImpl(new MemoryAdapter().credentials, bus, cfg)

  it.each([0, 1, 7, 65, Number.NaN, Number.POSITIVE_INFINITY, -1, 10.5])('backupCodeLen %s', (backupCodeLen) => {
    expect(refusal(() => mfa({ backupCodeLen }))).toContain('backupCodeLen must be a whole number between 8 and 64')
  })

  it.each([0, 65, Number.NaN, Number.POSITIVE_INFINITY, -5, 2.5])('backupCodeCount %s', (backupCodeCount) => {
    expect(refusal(() => mfa({ backupCodeCount }))).toContain('backupCodeCount must be a whole number between 1 and 64')
  })

  it('constructs on the defaults and on either bound', () => {
    expect(refusal(() => mfa({}))).toBe('constructed')
    expect(refusal(() => mfa({ backupCodeCount: 1, backupCodeLen: 8 }))).toBe('constructed')
    expect(refusal(() => mfa({ backupCodeCount: 64, backupCodeLen: 64 }))).toBe('constructed')
  })

  it('mints distinct codes at the shortest length it now allows, and one identity cannot spend another', async () => {
    const adapter = new MemoryAdapter()
    const impl = new MfaImpl(adapter.credentials, bus, { backupCodeLen: 8 })
    const [a, b] = [await identity(adapter), await identity(adapter)]
    const codes = await impl.regenerateBackupCodes(a)
    await impl.regenerateBackupCodes(b)
    expect(codes).toHaveLength(10)
    expect(new Set(codes).size).toBe(10)
    for (const code of codes) expect(code).toMatch(/^[a-z2-9]{5}-[a-z2-9]{3}$/)
    expect(await impl.verifyBackupCode(b, codes[0] as string)).toBe(false)
    expect(await impl.verifyBackupCode(a, codes[0] as string)).toBe(true)
  })
})

describe('BackupCodesFacet, the second implementation, refuses the same two', () => {
  const facet = (cfg: Partial<BackupCodesFacet.Cfg>) =>
    new BackupCodesFacet(new MemoryAdapter().credentials, CRYPTO, { ...DEFAULT_BACKUP_CODES_CONFIG, ...cfg })

  it.each([0, 4, 65, Number.NaN, -1, 5.5])('byteLength %s', (byteLength) => {
    expect(refusal(() => facet({ byteLength }))).toContain('byteLength must be a whole number between 5 and 64')
  })

  it.each([0, 65, Number.NaN, -3])('count %s', (count) => {
    expect(refusal(() => facet({ count }))).toContain('count must be a whole number between 1 and 64')
  })

  it('still generates and verifies on its own defaults', async () => {
    const adapter = new MemoryAdapter()
    const f = new BackupCodesFacet(adapter.credentials, CRYPTO)
    const id = await identity(adapter)
    const { codes } = await f.generate(id)
    expect(codes).toHaveLength(10)
    for (const code of codes) expect(code).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/)
    expect(await f.verify(id, codes[0] as string)).toBe(true)
  })
})

describe('RememberMeFacet mints a token that skips the factor for ninety days', () => {
  const facet = (cfg: Partial<RememberMeFacet.Cfg>) =>
    new RememberMeFacet(new MemoryAdapter().credentials, CRYPTO, { ...DEFAULT_REMEMBER_ME_CONFIG, ...cfg })

  it.each([0, 15, 129, Number.NaN, -1, 32.5])('byteLength %s', (byteLength) => {
    expect(refusal(() => facet({ byteLength }))).toContain('byteLength must be a whole number between 16 and 128')
  })

  it.each([0, Number.NaN, -1, Number.POSITIVE_INFINITY])('ttlMs %s', (ttlMs) => {
    expect(refusal(() => facet({ ttlMs }))).toContain('ttlMs must be a positive number')
  })

  it('still issues a token that verifies on its own defaults', async () => {
    const adapter = new MemoryAdapter()
    const f = new RememberMeFacet(adapter.credentials, CRYPTO)
    const id = await identity(adapter)
    const issued = await f.issue(id)
    expect(issued.token.length).toBeGreaterThan(40)
    await expect(f.verify(issued.token)).resolves.toMatchObject({ identityId: id })
  })
})
