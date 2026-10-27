import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { authAesGcmDataAtRest } from '~/core/dataAtRest'
import { InMemoryEvents } from '~/core/events'
import { ScryptHasher } from '~/providers/passwords'
import { authTestDataAtRest, createTest } from '~/test'
import { credentialInput } from '~/test/store-inputs'
import { TOTP_DEFAULTS, totpAt } from '../internal/totp'
import { MfaImpl } from '../mfa'
import type { Mfa } from '../mfa.types'

/** A TOTP secret is the second factor itself, so whoever reads it from the database holds the factor. */
describe('a TOTP secret is stored encrypted under the provider key', () => {
  const dataAtRest = authTestDataAtRest()
  let adapter: MemoryAdapter
  let facet: MfaImpl

  beforeEach(() => {
    adapter = new MemoryAdapter()
    facet = new MfaImpl(adapter.credentials, new InMemoryEvents(), { dataAtRest })
  })

  function step(): number {
    return Math.floor(Date.now() / 1000 / TOTP_DEFAULTS.periodSec)
  }

  async function storedSecret(identityId: string): Promise<string> {
    const [row] = await adapter.credentials.listByIdentity(identityId, 'totp', {})
    if (!row) throw new Error(`no totp row for ${identityId}`)
    return row.secret
  }

  it('refuses to build without a key', () => {
    const noKey: Mfa.CfgInput = Object.assign({ dataAtRest }, { dataAtRest: undefined })
    expect(() => new MfaImpl(adapter.credentials, new InMemoryEvents(), noKey)).toThrow('AUTH_MISCONFIGURED')
  })

  it('refuses a key that is not an adapter, such as a raw string from the environment', () => {
    const rawKey: Mfa.CfgInput = Object.assign({ dataAtRest }, { dataAtRest: 'k'.repeat(32) })
    expect(() => new MfaImpl(adapter.credentials, new InMemoryEvents(), rawKey)).toThrow('AUTH_MISCONFIGURED')
  })

  /** Each member, written out, so a test can take one away. */
  const complete = {
    decrypt: async (cipher: string) => cipher,
    encrypt: async (plain: string) => plain,
    id: 'plain-object',
    needsReEncrypt: () => false,
  }

  it('builds with any adapter that has every member', () => {
    expect(() => new MfaImpl(adapter.credentials, new InMemoryEvents(), { dataAtRest: complete })).not.toThrow()
  })

  it.each(['decrypt', 'encrypt', 'id', 'needsReEncrypt'])('refuses an adapter with no %s', (member) => {
    const partial = Object.fromEntries(Object.entries(complete).filter(([name]) => name !== member))
    const cfg: Mfa.CfgInput = Object.assign({ dataAtRest }, { dataAtRest: partial })
    expect(() => new MfaImpl(adapter.credentials, new InMemoryEvents(), cfg)).toThrow('AUTH_MISCONFIGURED')
  })

  it('stores the secret encrypted, and confirms and steps up against it', async () => {
    const { secret } = await facet.beginTotpEnrollment('u', 'ada@example.com', null)
    expect(await storedSecret('u')).not.toContain(secret)
    const now = step()
    expect(await facet.confirmTotpEnrollment('u', totpAt(secret, now), null)).toMatchObject({ ok: true })
    expect(await facet.verifyTotp('u', totpAt(secret, now + 1))).toBe(true)
  })

  it('never reads a secret stored in plaintext', async () => {
    const plain = 'JBSWY3DPEHPK3PXP'
    await adapter.credentials.create(
      credentialInput({ identityId: 'u', kind: 'totp', secret: plain, metadata: { confirmed: true } }),
      {},
    )
    await expect(facet.verifyTotp('u', totpAt(plain, step()))).rejects.toThrow('AUTH_INVALID_PARAMETERS')
  })

  it('binds the secret to its owner, so a row copied to another account opens nothing', async () => {
    const { secret } = await facet.beginTotpEnrollment('u', 'ada@example.com', null)
    const now = step()
    await facet.confirmTotpEnrollment('u', totpAt(secret, now), null)
    await adapter.credentials.create(
      credentialInput({
        identityId: 'v',
        kind: 'totp',
        secret: await storedSecret('u'),
        metadata: { confirmed: true },
      }),
      {},
    )
    await expect(facet.verifyTotp('v', totpAt(secret, now + 1))).rejects.toThrow('AUTH_INVALID_PARAMETERS')
    expect(await facet.verifyTotp('u', totpAt(secret, now + 1))).toBe(true)
  })

  it('moves the secret to a rotated key on its next good code, so the old key can be retired', async () => {
    const oldKey = { kid: 'v1', masterKey: 'a'.repeat(32) }
    const newKey = { kid: 'v2', masterKey: 'b'.repeat(32) }
    const events = new InMemoryEvents()
    const before = new MfaImpl(adapter.credentials, events, { dataAtRest: authAesGcmDataAtRest(oldKey) })
    const rotated = authAesGcmDataAtRest({ ...newKey, previousKeys: [oldKey] })
    const after = new MfaImpl(adapter.credentials, events, { dataAtRest: rotated })

    const { secret } = await before.beginTotpEnrollment('u', 'ada@example.com', null)
    const now = step()
    await before.confirmTotpEnrollment('u', totpAt(secret, now), null)
    expect(await after.verifyTotp('u', totpAt(secret, now + 1))).toBe(true)

    const stored = await storedSecret('u')
    expect(rotated.needsReEncrypt(stored)).toBe(false)
    await expect(authAesGcmDataAtRest(newKey).decrypt(stored, { field: 'totp', identityId: 'u' })).resolves.toBe(secret)
  })
})

describe('an account whose TOTP secret was stored before encryption', () => {
  it('signs in with a backup code and enrolls again, and the plaintext row goes', async () => {
    const adapter = new MemoryAdapter()
    const auth = createTest({ adapter, passwords: { hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) } })
    const { id } = await auth.identities.create({ profile: { email: 'ada@example.com', username: 'ada' } })
    await auth.passwords.set(id, 'correct-horse-battery', adapter.credentials, null, {})
    const { secret } = await auth.mfa.beginTotpEnrollment(id, 'ada@example.com', null)
    const step = (): number => Math.floor(Date.now() / 1000 / TOTP_DEFAULTS.periodSec)
    const enrolled = await auth.mfa.confirmTotpEnrollment(id, totpAt(secret, step()), null)
    const [code = ''] = enrolled.ok ? enrolled.backupCodes : []
    const [row] = await adapter.credentials.listByIdentity(id, 'totp', {})
    if (!row) throw new Error('enrollment wrote no row')
    // What an install wrote before the upgrade: the secret itself.
    await adapter.credentials.rotate(row.id, secret, row.version, {})

    const signIn = await auth.flows.signIn({
      input: { email: 'ada@example.com', password: 'correct-horse-battery' },
      providerId: 'password',
    })
    const token = signIn.challenge?.token ?? ''
    const byTotp = auth.flows.completeStepUp({ challenge: token, code: totpAt(secret, step() + 1), method: 'totp' })
    await expect(byTotp).rejects.toThrow('AUTH_INVALID_PARAMETERS')

    const { session } = await auth.flows.completeStepUp({ challenge: token, code, method: 'backup-code' })
    expect(session.aal).toBe(2)

    const fresh = await auth.mfa.beginTotpEnrollment(id, 'ada@example.com', session)
    expect(await auth.mfa.confirmTotpEnrollment(id, totpAt(fresh.secret, step()), session)).toMatchObject({ ok: true })
    expect(await auth.mfa.verifyTotp(id, totpAt(fresh.secret, step() + 1))).toBe(true)
    const rows = await adapter.credentials.listByIdentity(id, 'totp', {})
    expect(rows.map((r) => r.secret)).not.toContain(secret)
    expect(rows).toHaveLength(1)
  })
})
