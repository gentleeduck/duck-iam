import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '../../../adapters/memory'
import { authSha256 } from '../../crypto'
import { AuthInMemoryEvents } from '../../events'
import { totpAt } from '../../mfa/totp'
import { DEFAULT_MFA_CONFIG, MfaFacet } from '../mfa'

describe('MfaFacet - TOTP', () => {
  let adapter: MemoryAdapter
  let events: AuthInMemoryEvents
  let facet: MfaFacet

  beforeEach(() => {
    adapter = new MemoryAdapter()
    events = new AuthInMemoryEvents()
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

  describe('authVerifyTotp', () => {
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

    describe('revoked credential gating', () => {
      it('authVerifyTotp ignores a TOTP enrollment with revokedAt === 0 (legitimate epoch number, previously slipped past `!r.revokedAt`)', async () => {
        const challenge = await facet.beginTotpEnrollment('user-1', 'alice@x.com')
        const code = totpAt(challenge.secret, Math.floor(Date.now() / 1000 / 30))
        await facet.confirmTotpEnrollment('user-1', code)
        // Directly tag the underlying credential row with revokedAt:0
        // (an adapter could legitimately write this; the AAL-2 gate must
        // still treat it as revoked).
        const rows = await adapter.credentials.listByIdentity('user-1', 'totp', {})
        const row = rows[0]
        if (!row) throw new Error('row missing')
        row.revokedAt = 0
        const verify = totpAt(challenge.secret, Math.floor(Date.now() / 1000 / 30))
        expect(await facet.verifyTotp('user-1', verify)).toBe(false)
        expect(await facet.hasTotp('user-1')).toBe(false)
      })

      it('authVerifyTotp ignores a TOTP enrollment with non-numeric revokedAt', async () => {
        const challenge = await facet.beginTotpEnrollment('user-1', 'alice@x.com')
        const code = totpAt(challenge.secret, Math.floor(Date.now() / 1000 / 30))
        await facet.confirmTotpEnrollment('user-1', code)
        const rows = await adapter.credentials.listByIdentity('user-1', 'totp', {})
        const row = rows[0]
        if (!row) throw new Error('row missing')
        // @ts-expect-error: SEC test intentionally violates the typed shape
        row.revokedAt = 'compromise-marker'
        const verify = totpAt(challenge.secret, Math.floor(Date.now() / 1000 / 30))
        expect(await facet.verifyTotp('user-1', verify)).toBe(false)
      })
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

describe('MfaFacet - backup codes', () => {
  let adapter: MemoryAdapter
  let events: AuthInMemoryEvents
  let facet: MfaFacet

  beforeEach(() => {
    adapter = new MemoryAdapter()
    events = new AuthInMemoryEvents()
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

  it('verifyBackupCode rejects a code whose row has revokedAt === 0 (would otherwise allow consumed-code replay)', async () => {
    const codes = await facet.regenerateBackupCodes('user-1')
    const code = codes[0]
    if (!code) throw new Error('no codes')
    const codeHash = authSha256(code.trim().toLowerCase())
    const rows = await adapter.credentials.listByIdentity('user-1', 'recovery', {})
    const matching = rows.find((r) => r.secret === codeHash)
    if (!matching) throw new Error('matching row missing')
    matching.revokedAt = 0
    expect(await facet.verifyBackupCode('user-1', code)).toBe(false)
  })

  it('regenerate revokes all previous codes', async () => {
    const old = await facet.regenerateBackupCodes('user-1')
    const oldFirst = old[0]
    if (!oldFirst) throw new Error('no codes')
    await facet.regenerateBackupCodes('user-1')
    expect(await facet.verifyBackupCode('user-1', oldFirst)).toBe(false)
  })
})

describe('MfaFacet - WebAuthn-MFA', () => {
  let adapter: MemoryAdapter
  let events: AuthInMemoryEvents
  let facet: MfaFacet
  let identityId: string

  function makeMockWebauthn(): MfaFacet.IWebauthnLibrary {
    return {
      generateRegistrationOptions: vi.fn(async () => ({
        challenge: 'reg-challenge',
        rp: { id: 'app.test', name: 'app' },
        user: { id: 'aaa', name: 'a@x.com' },
      })),
      verifyRegistrationResponse: vi.fn(async () => ({
        verified: true,
        registrationInfo: {
          credential: { id: 'wa-mfa-1', publicKey: new Uint8Array([1, 2, 3]), counter: 0, transports: ['internal'] },
        },
      })),
      generateAuthenticationOptions: vi.fn(async () => ({
        challenge: 'auth-challenge',
        rpId: 'app.test',
      })),
      verifyAuthenticationResponse: vi.fn(async () => ({
        verified: true,
        authenticationInfo: { newCounter: 1, credentialID: 'wa-mfa-1', userVerified: true },
      })),
    }
  }

  function makeStore(): MfaFacet.IWebauthnChallengeStore {
    const store = new Map<string, { challenge: string; expiresAt: number }>()
    return {
      async put(key, challenge, ttlMs) {
        store.set(key, { challenge, expiresAt: Date.now() + ttlMs })
      },
      async take(key) {
        const entry = store.get(key)
        if (!entry || entry.expiresAt < Date.now()) return null
        store.delete(key)
        return entry.challenge
      },
    }
  }

  beforeEach(() => {
    adapter = new MemoryAdapter()
    events = new AuthInMemoryEvents()
    facet = new MfaFacet(adapter.credentials, events, DEFAULT_MFA_CONFIG)
    identityId = 'user-wa-mfa-1'
  })

  it('beginWebauthnMfaEnrollment + confirmWebauthnMfaEnrollment persists a webauthn-mfa credential', async () => {
    const challengeStore = makeStore()
    const webauthn = makeMockWebauthn()
    await facet.beginWebauthnMfaEnrollment(identityId, {
      rpID: 'app.test',
      rpName: 'app',
      userName: 'a@x.com',
      expectedOrigins: 'https://app.test',
      challengeStore,
      challengeKey: 'sess-1',
      webauthnModule: webauthn,
    })
    const r = await facet.confirmWebauthnMfaEnrollment(identityId, {
      rpID: 'app.test',
      expectedOrigins: 'https://app.test',
      challengeStore,
      challengeKey: 'sess-1',
      response: { id: 'wa-mfa-1' },
      webauthnModule: webauthn,
    })
    expect(r.credentialId).toBeDefined()
    expect(await facet.hasWebauthnMfa(identityId)).toBe(true)
  })

  it('verifyWebauthnMfa returns true on a valid assertion and false on rollback', async () => {
    const challengeStore = makeStore()
    const webauthn = makeMockWebauthn()
    await facet.beginWebauthnMfaEnrollment(identityId, {
      rpID: 'app.test',
      rpName: 'app',
      userName: 'a@x.com',
      expectedOrigins: 'https://app.test',
      challengeStore,
      challengeKey: 'sess-2',
      webauthnModule: webauthn,
    })
    await facet.confirmWebauthnMfaEnrollment(identityId, {
      rpID: 'app.test',
      expectedOrigins: 'https://app.test',
      challengeStore,
      challengeKey: 'sess-2',
      response: { id: 'wa-mfa-1' },
      webauthnModule: webauthn,
    })

    // Happy path
    await facet.beginWebauthnMfaVerify(identityId, {
      rpID: 'app.test',
      challengeStore,
      challengeKey: 'verify-1',
      webauthnModule: webauthn,
    })
    const ok = await facet.verifyWebauthnMfa(identityId, {
      rpID: 'app.test',
      expectedOrigins: 'https://app.test',
      challengeStore,
      challengeKey: 'verify-1',
      response: { id: 'wa-mfa-1' },
      webauthnModule: webauthn,
    })
    expect(ok).toBe(true)

    // Counter rollback (stored counter advanced to 1; reply newCounter=0)
    await facet.beginWebauthnMfaVerify(identityId, {
      rpID: 'app.test',
      challengeStore,
      challengeKey: 'verify-2',
      webauthnModule: webauthn,
    })
    // Patch the cred row's counter to 5; then the next assertion returning newCounter=0 should be rejected.
    const creds = await adapter.credentials.listByIdentity(identityId, 'webauthn-mfa', {})
    const cred = creds[0]
    if (!cred) throw new Error('expected credential')
    ;(cred.metadata as { counter: number }).counter = 5
    const verifyAuth = webauthn.verifyAuthenticationResponse as ReturnType<typeof vi.fn>
    verifyAuth.mockResolvedValueOnce({
      verified: true,
      authenticationInfo: { newCounter: 1, credentialID: 'wa-mfa-1', userVerified: true },
    })
    const ok2 = await facet.verifyWebauthnMfa(identityId, {
      rpID: 'app.test',
      expectedOrigins: 'https://app.test',
      challengeStore,
      challengeKey: 'verify-2',
      response: { id: 'wa-mfa-1' },
      webauthnModule: webauthn,
    })
    expect(ok2).toBe(false)
  })

  it('removeWebauthnMfa wipes the credential', async () => {
    const challengeStore = makeStore()
    const webauthn = makeMockWebauthn()
    await facet.beginWebauthnMfaEnrollment(identityId, {
      rpID: 'app.test',
      rpName: 'app',
      userName: 'a@x.com',
      expectedOrigins: 'https://app.test',
      challengeStore,
      challengeKey: 'sess-3',
      webauthnModule: webauthn,
    })
    await facet.confirmWebauthnMfaEnrollment(identityId, {
      rpID: 'app.test',
      expectedOrigins: 'https://app.test',
      challengeStore,
      challengeKey: 'sess-3',
      response: { id: 'wa-mfa-1' },
      webauthnModule: webauthn,
    })
    expect(await facet.hasWebauthnMfa(identityId)).toBe(true)
    await facet.removeWebauthnMfa(identityId)
    expect(await facet.hasWebauthnMfa(identityId)).toBe(false)
  })
})
