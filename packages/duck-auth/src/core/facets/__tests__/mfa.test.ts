import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAuthAdapter } from '../../../adapters/memory'
import { InMemoryEvents } from '../../events'
import { totpAt } from '../../mfa/totp'
import { DEFAULT_MFA_CONFIG, MfaFacet } from '../mfa'

describe('MfaFacet — TOTP', () => {
  let adapter: MemoryAuthAdapter
  let events: InMemoryEvents
  let facet: MfaFacet

  beforeEach(() => {
    adapter = new MemoryAuthAdapter()
    events = new InMemoryEvents()
    facet = new MfaFacet(adapter.credentials, events, DEFAULT_MFA_CONFIG)
  })

  describe('enrollment', () => {
    it('beginTotpEnrollment persists an unconfirmed credential + returns secret+uri', async () => {
      const challenge = await facet.beginTotpEnrollment('user-1', 'alice@x.com')
      expect(challenge.secret).toMatch(/^[A-Z2-7]{32}$/)
      expect(challenge.uri).toMatch(/^otpauth:\/\/totp\/.*alice%40x\.com/)
      const rows = await adapter.credentials.listByIdentity('user-1', 'totp', {})
      expect(rows).toHaveLength(1)
      expect((rows[0]?.metadata as { confirmed?: boolean }).confirmed).toBe(false)
    })

    it('hasTotp returns false for unconfirmed enrollment', async () => {
      await facet.beginTotpEnrollment('user-1', 'alice@x.com')
      expect(await facet.hasTotp('user-1')).toBe(false)
    })

    it('confirmTotpEnrollment with right code flips confirmed=true, emits mfa.enrolled, returns backup codes', async () => {
      const challenge = await facet.beginTotpEnrollment('user-1', 'alice@x.com')
      const code = totpAt(challenge.secret, Math.floor(Date.now() / 1000 / 30))
      const handler = vi.fn()
      events.on('mfa.enrolled', handler)

      const result = await facet.confirmTotpEnrollment('user-1', code)
      expect(result.ok).toBe(true)
      if (result.ok) {
        expect(result.backupCodes).toHaveLength(DEFAULT_MFA_CONFIG.backupCodeCount)
        expect(result.backupCodes[0]).toMatch(/^[a-z2-9]{5}-[a-z2-9]{5}$/)
      }
      expect(handler).toHaveBeenCalledOnce()
      expect(await facet.hasTotp('user-1')).toBe(true)
    })

    it('confirmTotpEnrollment with wrong code returns ok:false', async () => {
      await facet.beginTotpEnrollment('user-1', 'alice@x.com')
      const result = await facet.confirmTotpEnrollment('user-1', '000000')
      expect(result.ok).toBe(false)
      expect(await facet.hasTotp('user-1')).toBe(false)
    })

    it('confirmTotpEnrollment without prior begin throws AUTH/MFA_REQUIRED', async () => {
      await expect(facet.confirmTotpEnrollment('user-1', '123456')).rejects.toMatchObject({
        code: 'AUTH/MFA_REQUIRED',
      })
    })
  })

  describe('verifyTotp', () => {
    it('verifies the current code against a confirmed enrollment', async () => {
      const challenge = await facet.beginTotpEnrollment('user-1', 'alice@x.com')
      const code = totpAt(challenge.secret, Math.floor(Date.now() / 1000 / 30))
      await facet.confirmTotpEnrollment('user-1', code)
      const verify = totpAt(challenge.secret, Math.floor(Date.now() / 1000 / 30))
      expect(await facet.verifyTotp('user-1', verify)).toBe(true)
    })

    it('returns false when no confirmed enrollment exists', async () => {
      expect(await facet.verifyTotp('user-1', '123456')).toBe(false)
    })

    it('returns false for the wrong code on a confirmed enrollment', async () => {
      const challenge = await facet.beginTotpEnrollment('user-1', 'alice@x.com')
      const code = totpAt(challenge.secret, Math.floor(Date.now() / 1000 / 30))
      await facet.confirmTotpEnrollment('user-1', code)
      expect(await facet.verifyTotp('user-1', '000000')).toBe(false)
    })
  })

  describe('removeTotp', () => {
    it('drops the credential and emits mfa.removed', async () => {
      const challenge = await facet.beginTotpEnrollment('user-1', 'alice@x.com')
      const code = totpAt(challenge.secret, Math.floor(Date.now() / 1000 / 30))
      await facet.confirmTotpEnrollment('user-1', code)
      const handler = vi.fn()
      events.on('mfa.removed', handler)
      await facet.removeTotp('user-1')
      expect(await facet.hasTotp('user-1')).toBe(false)
      expect(handler).toHaveBeenCalledOnce()
    })
  })
})

describe('MfaFacet — backup codes', () => {
  let adapter: MemoryAuthAdapter
  let events: InMemoryEvents
  let facet: MfaFacet

  beforeEach(() => {
    adapter = new MemoryAuthAdapter()
    events = new InMemoryEvents()
    facet = new MfaFacet(adapter.credentials, events, DEFAULT_MFA_CONFIG)
  })

  it('regenerated backup codes are single-use and case-insensitive on verify', async () => {
    const codes = await facet.regenerateBackupCodes('user-1')
    const code = codes[0]
    if (!code) throw new Error('no codes')
    expect(await facet.verifyBackupCode('user-1', code.toUpperCase())).toBe(true)
    // Replay defeated.
    expect(await facet.verifyBackupCode('user-1', code)).toBe(false)
  })

  it('wrong backup code returns false (no enumeration)', async () => {
    await facet.regenerateBackupCodes('user-1')
    expect(await facet.verifyBackupCode('user-1', 'wrong-xxxx-yy')).toBe(false)
  })

  it('regenerate revokes all previous codes', async () => {
    const old = await facet.regenerateBackupCodes('user-1')
    const oldFirst = old[0]
    if (!oldFirst) throw new Error('no codes')
    await facet.regenerateBackupCodes('user-1')
    expect(await facet.verifyBackupCode('user-1', oldFirst)).toBe(false)
  })
})
