import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { randomToken, sha256 } from '~/core/crypto'
import { identityInput } from '~/test/store-inputs'
import { BackupCodesFacet } from '../internal/backup-codes'

describe('AuthBackupCodesFacet', () => {
  let adapter: MemoryAdapter
  let facet: BackupCodesFacet
  let identityId: string

  beforeEach(async () => {
    adapter = new MemoryAdapter()
    facet = new BackupCodesFacet(adapter.credentials, { authRandomToken: randomToken, authSha256: sha256 })
    const ident = await adapter.identities.create(
      identityInput({ profile: { email: 'a@b.com', username: 'a' }, providers: [] }),
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

  it('two verifications racing on one code do not both succeed', async () => {
    // The test above is sequential, so it never opens the window. `verify` lists the codes, checks the
    // match is not revoked, and revokes it at the end - and `revoke` is unconditional, so two reads that
    // both land before either write both see a live row.
    let gatedId: string | null = null
    let calls = 0
    let release = (): void => {}
    const held = new Promise<void>((resolve) => {
      release = resolve
    })
    const ad = new MemoryAdapter()
    const raced = new BackupCodesFacet(
      {
        ...ad.credentials,
        revoke: async (id, ctx) => {
          if (id === gatedId) {
            calls += 1
            if (calls === 1) await held
          }
          return ad.credentials.revoke(id, ctx)
        },
      },
      { authRandomToken: randomToken, authSha256: sha256 },
    )
    const ident = await ad.identities.create(
      identityInput({ profile: { email: 'r@b.com', username: 'r' }, providers: [] }),
    )
    const { codes } = await raced.generate(ident.id)
    const code = codes[0]!
    const rows = await ad.credentials.listByIdentity(ident.id, 'recovery', {})
    gatedId = rows.find((r) => r.secret === sha256(code))?.id ?? null

    const winner = raced.verify(ident.id, code)
    await vi.waitFor(() => {
      if (calls === 0) throw new Error('the winner has not reached its revoke yet')
    })

    // One code, one success.
    expect(await raced.verify(ident.id, code)).toBe(false)
    release()
    expect(await winner).toBe(true)
  })

  it('verify returns false for wrong code without throwing', async () => {
    await facet.generate(identityId)
    expect(await facet.verify(identityId, 'WRONG-CODE')).toBe(false)
  })

  it('verify throws AUTH_RECOVERY_TOKEN_INVALID on obviously bogus input', async () => {
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
