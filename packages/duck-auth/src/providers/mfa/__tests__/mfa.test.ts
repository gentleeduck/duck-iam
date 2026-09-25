import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { sha256 } from '~/core/crypto'
import { AuthError } from '~/core/errors'
import { InMemoryEvents } from '~/core/events'
import type { Passkey } from '~/providers/passkey/passkey.types'
import { totpAt } from '../internal/totp'
import { MfaImpl } from '../mfa'
import { DEFAULT_MFA_CONFIG } from '../mfa.constants'
import type { Mfa } from '../mfa.types'

describe('MfaFacet - TOTP', () => {
  let adapter: MemoryAdapter
  let events: InMemoryEvents
  let facet: MfaImpl

  beforeEach(() => {
    adapter = new MemoryAdapter()
    events = new InMemoryEvents()
    facet = new MfaImpl(adapter.credentials, events, DEFAULT_MFA_CONFIG)
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

    it('confirmTotpEnrollment without prior begin throws AUTH_MFA_REQUIRED', async () => {
      await expect(facet.confirmTotpEnrollment('user-1', '123456')).rejects.toMatchObject({
        code: 'AUTH_MFA_REQUIRED',
      })
    })
  })

  describe('verifyTotp', () => {
    it('verifies the current code against a confirmed enrollment', async () => {
      const challenge = await facet.beginTotpEnrollment('user-1', 'alice@x.com')
      const step = Math.floor(Date.now() / 1000 / 30)
      await facet.confirmTotpEnrollment('user-1', totpAt(challenge.secret, step))
      // A later step, because confirming spends the code it was given. This test
      // used to re-present the confirming code, which is the replay now refused.
      expect(await facet.verifyTotp('user-1', totpAt(challenge.secret, step + 1))).toBe(true)
    })

    it('refuses a code that was already spent', async () => {
      // NIST SP 800-63B: a verifier accepts a given time-based OTP only once in
      // its validity period. The drift window is three steps wide, so a captured
      // code would otherwise stay usable for about ninety seconds.
      const challenge = await facet.beginTotpEnrollment('user-1', 'alice@x.com')
      const step = Math.floor(Date.now() / 1000 / 30)
      await facet.confirmTotpEnrollment('user-1', totpAt(challenge.secret, step))
      const code = totpAt(challenge.secret, step + 1)

      expect(await facet.verifyTotp('user-1', code)).toBe(true)
      expect(await facet.verifyTotp('user-1', code)).toBe(false)
      expect(await facet.verifyTotp('user-1', code)).toBe(false)
    })

    it('two verifications racing on one code do not both succeed', async () => {
      // The replay test above is sequential, so it never opens the window. Gating the metadata write
      // holds the winner between its read and its record, which is where a second verification used to
      // read a stale `lastTotpStep` and pass the same comparison.
      let gated = false
      let calls = 0
      let release = (): void => {}
      const held = new Promise<void>((resolve) => {
        release = resolve
      })
      const ad = new MemoryAdapter()
      const raced = new MfaImpl(
        {
          ...ad.credentials,
          patchMetadata: async (id, patch, ctx, expectedVersion) => {
            if (gated) {
              calls += 1
              if (calls === 1) await held
            }
            return ad.credentials.patchMetadata(id, patch, ctx, expectedVersion)
          },
        },
        new InMemoryEvents(),
        DEFAULT_MFA_CONFIG,
      )
      const challenge = await raced.beginTotpEnrollment('user-1', 'alice@x.com')
      const step = Math.floor(Date.now() / 1000 / 30)
      await raced.confirmTotpEnrollment('user-1', totpAt(challenge.secret, step))
      gated = true
      const code = totpAt(challenge.secret, step + 1)

      const held_at_write = raced.verifyTotp('user-1', code)
      await vi.waitFor(() => {
        if (calls === 0) throw new Error('the first verification has not reached its write yet')
      })
      const second = await raced.verifyTotp('user-1', code)
      release()
      const first = await held_at_write

      // One code, one step-up. Which of the two wins is down to whose conditional write lands first -
      // here the second, because the first is held inside its own - and either way the other is refused.
      expect([first, second].filter(Boolean)).toHaveLength(1)
    })

    it('refuses an older code once a newer step has been spent', async () => {
      // Rewinding inside the drift window is the same replay by another route.
      const challenge = await facet.beginTotpEnrollment('user-1', 'alice@x.com')
      const step = Math.floor(Date.now() / 1000 / 30)
      await facet.confirmTotpEnrollment('user-1', totpAt(challenge.secret, step - 1))

      expect(await facet.verifyTotp('user-1', totpAt(challenge.secret, step + 1))).toBe(true)
      expect(await facet.verifyTotp('user-1', totpAt(challenge.secret, step))).toBe(false)
    })

    it('confirming spends its own code, so it cannot be replayed into a step-up', async () => {
      const challenge = await facet.beginTotpEnrollment('user-1', 'alice@x.com')
      const step = Math.floor(Date.now() / 1000 / 30)
      const code = totpAt(challenge.secret, step)
      await facet.confirmTotpEnrollment('user-1', code)
      expect(await facet.verifyTotp('user-1', code)).toBe(false)
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
      it('verifyTotp ignores a TOTP enrollment with revokedAt === 0 (legitimate epoch number, previously slipped past `!r.revokedAt`)', async () => {
        const challenge = await facet.beginTotpEnrollment('user-1', 'alice@x.com')
        const code = totpAt(challenge.secret, Math.floor(Date.now() / 1000 / 30))
        await facet.confirmTotpEnrollment('user-1', code)
        // Directly tag the underlying credential row with revokedAt:0
        // (an adapter could legitimately write this; the AAL-2 gate must
        // still treat it as revoked).
        const rows = await adapter.credentials.listByIdentity('user-1', 'totp', {})
        const row = rows[0]
        if (!row) throw new Error('row missing')
        adapter.raw.credentials.set(row.id, { ...row, revokedAt: new Date(0) })
        const verify = totpAt(challenge.secret, Math.floor(Date.now() / 1000 / 30))
        expect(await facet.verifyTotp('user-1', verify)).toBe(false)
        expect(await facet.hasTotp('user-1')).toBe(false)
      })

      it('verifyTotp ignores a TOTP enrollment with non-numeric revokedAt', async () => {
        const challenge = await facet.beginTotpEnrollment('user-1', 'alice@x.com')
        const code = totpAt(challenge.secret, Math.floor(Date.now() / 1000 / 30))
        await facet.confirmTotpEnrollment('user-1', code)
        const rows = await adapter.credentials.listByIdentity('user-1', 'totp', {})
        const row = rows[0]
        if (!row) throw new Error('row missing')
        // @ts-expect-error: SEC test intentionally violates the typed shape
        adapter.raw.credentials.set(row.id, { ...row, revokedAt: 'compromise-marker' })
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
      const gone = await facet.removeTotp('user-1')
      // How many factors went. `0` is the difference between "MFA turned off"
      // and "there was nothing to turn off" - the rows themselves stay put,
      // they carry the shared secret.
      expect(gone).toEqual({ removed: 1 })
      expect(await facet.hasTotp('user-1')).toBe(false)
      expect(handler).toHaveBeenCalledOnce()
    })

    it('answers removed:0 for an identity that had no totp, and for a rejected id', async () => {
      expect(await facet.removeTotp('never-enrolled')).toEqual({ removed: 0 })
      expect(await facet.removeTotp('')).toEqual({ removed: 0 })
      expect(await facet.removeTotp('x'.repeat(300))).toEqual({ removed: 0 })
    })
  })
})

describe('MfaFacet - backup codes', () => {
  let adapter: MemoryAdapter
  let events: InMemoryEvents
  let facet: MfaImpl

  beforeEach(() => {
    adapter = new MemoryAdapter()
    events = new InMemoryEvents()
    facet = new MfaImpl(adapter.credentials, events, DEFAULT_MFA_CONFIG)
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
    const codeHash = sha256(code.trim().toLowerCase())
    const rows = await adapter.credentials.listByIdentity('user-1', 'recovery', {})
    const matching = rows.find((r) => r.secret === codeHash)
    if (!matching) throw new Error('matching row missing')
    adapter.raw.credentials.set(matching.id, { ...matching, revokedAt: new Date(0) })
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
  let events: InMemoryEvents
  let facet: MfaImpl
  let identityId: string

  function makeMockWebauthn(): Mfa.WebauthnLibrary {
    return {
      generateRegistrationOptions: vi.fn(async () => ({
        challenge: 'reg-challenge',
        rp: { id: 'app.test', name: 'app' },
        user: { id: 'aaa', name: 'a@x.com' },
        pubKeyCredParams: [{ alg: -7, type: 'public-key' as const }],
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

  function makeStore(): Passkey.ChallengeStore {
    const store = new Map<string, { challenge: string; expiresAt: number }>()
    return {
      async put(key, challenge, ttlMs) {
        store.set(key, { challenge, expiresAt: Date.now() + ttlMs })
      },
      async take(key) {
        const entry = store.get(key)
        // Missing and expired are one refusal, as the contract has it.
        if (!entry || entry.expiresAt < Date.now()) throw new AuthError('AUTH_CREDENTIAL_NOT_FOUND')
        store.delete(key)
        return entry.challenge
      },
    }
  }

  beforeEach(() => {
    adapter = new MemoryAdapter()
    events = new InMemoryEvents()
    facet = new MfaImpl(adapter.credentials, events, DEFAULT_MFA_CONFIG)
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
    await adapter.credentials.patchMetadata(cred.id, { counter: 5 }, {})
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

  it('a second assertion reusing an accepted count is refused, which needs the first one recorded', async () => {
    const challengeStore = makeStore()
    const webauthn = makeMockWebauthn()
    await facet.beginWebauthnMfaEnrollment(identityId, {
      challengeKey: 'sess-clone',
      challengeStore,
      expectedOrigins: 'https://app.test',
      rpID: 'app.test',
      rpName: 'app',
      userName: 'a@x.com',
      webauthnModule: webauthn,
    })
    await facet.confirmWebauthnMfaEnrollment(identityId, {
      challengeKey: 'sess-clone',
      challengeStore,
      expectedOrigins: 'https://app.test',
      response: { id: 'wa-mfa-1' },
      rpID: 'app.test',
      webauthnModule: webauthn,
    })

    // An authenticator at count 9 and a clone of it at the same count. The second is the rollback
    // WebAuthn L2 6.1.3 exists to catch, and it is only catchable if the first one's count was written
    // down: left at its enrollment value, every later assertion is measured against a baseline the
    // authenticator passed long ago.
    const verifyAuth = webauthn.verifyAuthenticationResponse as ReturnType<typeof vi.fn>
    verifyAuth.mockResolvedValue({
      authenticationInfo: { credentialID: 'wa-mfa-1', newCounter: 9, userVerified: true },
      verified: true,
    })
    const assertOnce = async (key: string): Promise<boolean> => {
      await facet.beginWebauthnMfaVerify(identityId, {
        challengeKey: key,
        challengeStore,
        rpID: 'app.test',
        webauthnModule: webauthn,
      })
      return facet.verifyWebauthnMfa(identityId, {
        challengeKey: key,
        challengeStore,
        expectedOrigins: 'https://app.test',
        response: { id: 'wa-mfa-1' },
        rpID: 'app.test',
        webauthnModule: webauthn,
      })
    }

    expect(await assertOnce('clone-1')).toBe(true)
    expect(await assertOnce('clone-2')).toBe(false)

    const rows = await adapter.credentials.listByIdentity(identityId, 'webauthn-mfa', {})
    expect(rows[0]?.metadata).toMatchObject({ counter: 9 })
  })

  it('two assertions racing on the same stored count do not both get in', async () => {
    const challengeStore = makeStore()
    const webauthn = makeMockWebauthn()
    await facet.beginWebauthnMfaEnrollment(identityId, {
      challengeKey: 'sess-race',
      challengeStore,
      expectedOrigins: 'https://app.test',
      rpID: 'app.test',
      rpName: 'app',
      userName: 'a@x.com',
      webauthnModule: webauthn,
    })
    await facet.confirmWebauthnMfaEnrollment(identityId, {
      challengeKey: 'sess-race',
      challengeStore,
      expectedOrigins: 'https://app.test',
      response: { id: 'wa-mfa-1' },
      rpID: 'app.test',
      webauthnModule: webauthn,
    })
    const verifyAuth = webauthn.verifyAuthenticationResponse as ReturnType<typeof vi.fn>
    verifyAuth.mockResolvedValue({
      authenticationInfo: { credentialID: 'wa-mfa-1', newCounter: 9, userVerified: true },
      verified: true,
    })

    // Two concurrent calls would not show this: both reads land before either write. So the winner is
    // held inside its own write, and the clone presents while it is there.
    const base = adapter.credentials
    let release: (() => void) | undefined
    let calls = 0
    const raced = new MfaImpl(
      {
        ...base,
        patchMetadata: async (...args: Parameters<typeof base.patchMetadata>) => {
          calls += 1
          if (calls === 1) {
            await new Promise<void>((resolve) => {
              release = resolve
            })
          }
          return base.patchMetadata(...args)
        },
      },
      events,
      DEFAULT_MFA_CONFIG,
    )
    const assertOnce = async (key: string): Promise<boolean> => {
      await raced.beginWebauthnMfaVerify(identityId, {
        challengeKey: key,
        challengeStore,
        rpID: 'app.test',
        webauthnModule: webauthn,
      })
      return raced.verifyWebauthnMfa(identityId, {
        challengeKey: key,
        challengeStore,
        expectedOrigins: 'https://app.test',
        response: { id: 'wa-mfa-1' },
        rpID: 'app.test',
        webauthnModule: webauthn,
      })
    }

    const held = assertOnce('race-1')
    await vi.waitFor(() => {
      if (calls === 0) throw new Error('the first assertion has not reached its write yet')
    })
    const second = await assertOnce('race-2')
    release?.()
    const first = await held

    // Which of the two wins is down to whose conditional write lands first - here the second, because the
    // first is held inside its own - and either way the other is refused.
    expect([first, second].filter(Boolean)).toHaveLength(1)
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
    expect(await facet.removeWebauthnMfa(identityId)).toEqual({ removed: 1 })
    expect(await facet.hasWebauthnMfa(identityId)).toBe(false)
    expect(await facet.removeWebauthnMfa(identityId)).toEqual({ removed: 0 })
  })
})
