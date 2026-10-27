import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { InMemoryEvents } from '~/core/events'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { authTestDataAtRest } from '~/test'
import { makeSession } from '~/test/store-inputs'
import { MfaImpl, mfa as mfaProvider } from '../mfa'

describe('MfaImpl backup codes', () => {
  const identityId = 'identity-1'
  let adapter: MemoryAdapter
  let events: InMemoryEvents
  let mfa: MfaImpl

  beforeEach(() => {
    adapter = new MemoryAdapter()
    events = new InMemoryEvents()
    mfa = new MfaImpl(adapter.credentials, events, { dataAtRest: authTestDataAtRest() })
  })

  it('stores no code in the clear', async () => {
    const codes = await mfa.regenerateBackupCodes(identityId, makeSession({ aal: 2, identityId: identityId }))
    const rows = await adapter.credentials.listByIdentity(identityId, 'recovery', {})
    expect(rows).toHaveLength(codes.length)
    expect(rows.filter((r) => codes.includes(r.secret))).toEqual([])
  })

  it.each([8, 10, 63, 64])(
    'a %s-character code verifies as shown, bare, spaced or uppercased',
    async (backupCodeLen) => {
      const sized = new MfaImpl(adapter.credentials, events, { backupCodeLen, dataAtRest: authTestDataAtRest() })
      const [shown = '', bare = '', spaced = '', upper = ''] = await sized.regenerateBackupCodes(
        identityId,
        makeSession({ aal: 2, identityId: identityId }),
      )
      expect(shown).toHaveLength(backupCodeLen + 1)
      expect(await sized.verifyBackupCode(identityId, shown)).toBe(true)
      expect(await sized.verifyBackupCode(identityId, bare.replace('-', ''))).toBe(true)
      expect(await sized.verifyBackupCode(identityId, ` ${spaced.replace('-', ' ')} `)).toBe(true)
      expect(await sized.verifyBackupCode(identityId, upper.toUpperCase())).toBe(true)
      expect(await sized.verifyBackupCode(identityId, shown)).toBe(false)
    },
  )

  it.each(['', '---', 'x'.repeat(129)])('refuses %j without matching anything', async (code) => {
    await mfa.regenerateBackupCodes(identityId, makeSession({ aal: 2, identityId: identityId }))
    expect(await mfa.verifyBackupCode(identityId, code)).toBe(false)
    expect(await mfa.remainingBackupCodes(identityId)).toBe(10)
  })

  it('counts the codes left, one fewer per spend', async () => {
    const [code = ''] = await mfa.regenerateBackupCodes(identityId, makeSession({ aal: 2, identityId: identityId }))
    expect(await mfa.remainingBackupCodes(identityId)).toBe(10)
    expect(await mfa.verifyBackupCode(identityId, code)).toBe(true)
    expect(await mfa.remainingBackupCodes(identityId)).toBe(9)
  })

  it('removes every code, answers how many, and emits mfa.removed', async () => {
    const removed: unknown[] = []
    events.on('mfa.removed', (p) => {
      removed.push(p)
    })
    const [code = ''] = await mfa.regenerateBackupCodes(identityId, makeSession({ aal: 2, identityId: identityId }))

    expect(await mfa.removeBackupCodes(identityId, makeSession({ aal: 2, identityId: identityId }))).toEqual({
      removed: 10,
    })

    expect(await mfa.verifyBackupCode(identityId, code)).toBe(false)
    expect(await mfa.remainingBackupCodes(identityId)).toBe(0)
    expect(removed).toEqual([{ identityId, method: 'backup-code' }])
    expect(await mfa.removeBackupCodes(identityId, makeSession({ aal: 2, identityId: identityId }))).toEqual({
      removed: 0,
    })
  })
})

describe('a backup code through completeStepUp', () => {
  it('steps up with a 64-character code typed with a space, once', async () => {
    const adapter = new MemoryAdapter<{ username: string; email: string }>()
    const auth = new AuthEngine<{ username: string; email: string }>({
      baseUrl: 'https://x',
      limiter: new MemoryLimiter({ max: 99, windowMs: 60_000 }),
      providers: [mfaProvider({ backupCodeLen: 64, dataAtRest: authTestDataAtRest() })],
      stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
      transport: new CookieTransport({ name: 'duck-sid' }),
    })
    const { id } = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a' } })
    const [code = ''] = await auth.mfa.regenerateBackupCodes(id, makeSession({ aal: 2, identityId: id }))
    const { sid } = await auth.sessions.create({
      identityId: id,
      kind: 'user',
      aal: 1,
      factors: [{ method: 'password', completedAt: new Date() }],
    })

    const stepped = await auth.flows.completeStepUp({
      code: code.replace('-', ' '),
      currentSid: sid,
      method: 'backup-code',
    })

    expect(stepped.session.aal).toBe(2)
    await expect(
      auth.flows.completeStepUp({ code, currentSid: stepped.sid, method: 'backup-code' }),
    ).rejects.toMatchObject({ code: 'AUTH_INVALID_CREDENTIALS' })
  })
})
