/**
 * The WebAuthn signature counter is the only clone-detection signal a relying
 * party gets, and the whole of it is one comparison. It is also the comparison
 * most implementations get subtly wrong, in one of three ways: refusing every
 * synced passkey because they all report zero forever, accepting a rollback
 * because a NaN counter short-circuits `<=`, or persisting a counter that went
 * backwards and thereby lowering the bar for the next assertion.
 *
 * Sources: WebAuthn Level 2 section 6.1.3, and the practical caveat that
 * iCloud Keychain and other synced credentials return zero on every login, so a
 * zero must never be treated as a regression.
 *
 * The provider mocks `verifyAuthenticationResponse`, so these cases drive the
 * counter branch directly by choosing what the verifier reports.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { randomToken, sha256, timingSafeEqual } from '~/core/crypto'
import { InMemoryEvents } from '~/core/events'
import type { Identities } from '~/core/identities'
import { MemoryLimiter } from '~/limiters/memory'
import { identityInput } from '~/test/store-inputs'
import { AuthMemoryPasskeyChallengeStore, passkey } from '../index'
import type { Passkey } from '../passkey.types'

interface ProfileShape extends Identities.ProfileMetadataBase {}

/** What the verifier will claim the authenticator's counter now reads. */
let reportedCounter = 1

function makeContext(adapter: MemoryAdapter<ProfileShape>, events: InMemoryEvents) {
  return {
    baseUrl: 'https://app.test',
    crypto: { authRandomToken: randomToken, authSha256: sha256, authTimingSafeEqual: timingSafeEqual },
    events,
    limiter: new MemoryLimiter(),
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    tenant: {},
  }
}

function makeWebauthn(): Passkey.SimpleWebAuthnServerModule {
  return {
    generateAuthenticationOptions: vi.fn(async (input) => ({
      allowCredentials: input.allowCredentials,
      challenge: `auth-${randomToken(8)}`,
      rpId: input.rpID,
      userVerification: input.userVerification,
    })),
    generateRegistrationOptions: vi.fn(async (input) => ({
      challenge: `reg-${randomToken(8)}`,
      pubKeyCredParams: [{ alg: -7, type: 'public-key' as const }],
      rp: { id: input.rpID, name: input.rpName },
      user: { id: Buffer.from(input.userID).toString('base64url'), name: input.userName },
    })),
    verifyAuthenticationResponse: vi.fn(async () => ({
      authenticationInfo: { credentialID: 'webauthn-cred-1', newCounter: reportedCounter, userVerified: true },
      verified: true,
    })),
    verifyRegistrationResponse: vi.fn(async () => ({
      registrationInfo: {
        aaguid: 'aaguid-1',
        credential: {
          counter: 0,
          id: 'webauthn-cred-1',
          publicKey: new Uint8Array([1, 2, 3, 4]),
          transports: ['internal'],
        },
        credentialBackedUp: false,
        credentialDeviceType: 'singleDevice' as const,
      },
      verified: true,
    })),
  }
}

describe('passkey signature counter', () => {
  let adapter: MemoryAdapter<ProfileShape>
  let events: InMemoryEvents
  let identityId: string
  let provider: ReturnType<typeof passkey>
  let ctx: ReturnType<typeof makeContext>
  let credentialId: string

  /** Put the stored counter at a chosen value, as a prior assertion would have. */
  async function setStoredCounter(counter: unknown): Promise<void> {
    await adapter.credentials.patchMetadata(credentialId, { counter } as never, {})
  }

  const storedCounter = async (): Promise<unknown> => {
    const row = await adapter.credentials.findById(credentialId, {})
    return (row?.metadata as { counter?: unknown } | undefined)?.counter
  }

  /** One authentication attempt, with the verifier reporting `counter`. */
  let attempt = 0
  async function authenticate(counter: number): Promise<unknown> {
    reportedCounter = counter
    const sessionId = `login-${(attempt += 1)}`
    await provider.begin(ctx, { sessionId } as never)
    return provider.complete(ctx, { response: { id: 'webauthn-cred-1' }, sessionId } as never)
  }

  beforeEach(async () => {
    adapter = new MemoryAdapter<ProfileShape>()
    events = new InMemoryEvents()
    const identity = await adapter.identities.create(
      identityInput({ profile: { email: 'a@b.com', username: 'a' }, providers: [] }),
    )
    identityId = identity.id
    ctx = makeContext(adapter, events)
    provider = passkey({
      challengeStore: new AuthMemoryPasskeyChallengeStore(),
      expectedOrigins: 'https://app.test',
      findIdentityByEmail: async () => ({ id: identityId }),
      rpID: 'app.test',
      rpName: 'Test App',
      webauthnModule: makeWebauthn(),
    })

    const credential = await adapter.credentials.upsert(
      {
        expiresAt: null,
        identityId,
        kind: 'passkey',
        lastUsedAt: null,
        metadata: { counter: 5, credentialId: 'webauthn-cred-1', publicKey: 'AQIDBA' },
        revokedAt: null,
        secret: 'webauthn-cred-1',
        tenantId: null,
      },
      {},
    )
    credentialId = credential.id
  })

  describe('a counter that goes backwards is a clone signal', () => {
    it('refuses a counter lower than the stored one', async () => {
      await expect(authenticate(4)).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
    })

    it('refuses a counter equal to the stored one', async () => {
      // Equality matters as much as regression: a replayed assertion reuses the
      // same counter, so accepting it accepts the replay.
      await expect(authenticate(5)).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
    })

    it('refuses a counter far below the stored one', async () => {
      await expect(authenticate(1)).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
    })

    it('emits a suspicious signal naming the rollback, so an operator can see it', async () => {
      const seen: Array<Record<string, unknown>> = []
      events.on('suspicious', (payload) => {
        seen.push(payload as unknown as Record<string, unknown>)
      })
      await authenticate(4).catch(() => undefined)

      expect(seen).toHaveLength(1)
      expect(seen[0]).toMatchObject({ identityId, signal: 'passkey-counter-rollback' })
    })

    it('does not lower the stored counter on a refused attempt', async () => {
      // Persisting the rollback would make the next, genuinely lower assertion
      // look valid: the clone would have moved the goalposts.
      await authenticate(2).catch(() => undefined)
      expect(await storedCounter()).toBe(5)
    })
  })

  describe('a counter that moves forward is accepted and remembered', () => {
    it('accepts the next value up', async () => {
      await expect(authenticate(6)).resolves.toBeDefined()
    })

    it('accepts a large jump forward, since counters may skip', async () => {
      await expect(authenticate(5000)).resolves.toBeDefined()
    })

    it('persists the new value for the next comparison', async () => {
      await authenticate(9)
      expect(await storedCounter()).toBe(9)
    })

    it('a replay of the accepted value is then refused', async () => {
      await authenticate(9)
      await expect(authenticate(9)).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
    })
  })

  describe('zero means the authenticator does not count', () => {
    it('accepts zero even when a positive counter is stored', async () => {
      // Every passkey synced through iCloud Keychain reports zero on every login,
      // which the specification permits. Treating that as a rollback would refuse
      // an entire class of authenticator.
      await expect(authenticate(0)).resolves.toBeDefined()
    })

    it('leaves the stored counter alone rather than resetting it to zero', async () => {
      await authenticate(0)
      expect(await storedCounter()).toBe(5)
    })

    it('accepts zero repeatedly, which is the normal case for a synced passkey', async () => {
      for (let i = 0; i < 5; i++) await expect(authenticate(0)).resolves.toBeDefined()
    })

    it('accepts zero against a stored zero', async () => {
      await setStoredCounter(0)
      await expect(authenticate(0)).resolves.toBeDefined()
    })

    it('still accepts a forward move after a zero-reporting login', async () => {
      await authenticate(0)
      await expect(authenticate(6)).resolves.toBeDefined()
    })
  })

  describe('counters that are not usable numbers fail closed', () => {
    it('refuses a NaN counter from the verifier', async () => {
      // The trap this guards: `NaN !== 0` is true and `NaN <= 5` is false, so a
      // naive check would fall through and accept it.
      await expect(authenticate(Number.NaN)).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
    })

    it('refuses an infinite counter', async () => {
      await expect(authenticate(Number.POSITIVE_INFINITY)).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
    })

    it('refuses a negative infinite counter', async () => {
      await expect(authenticate(Number.NEGATIVE_INFINITY)).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
    })

    it('refuses when the stored counter is NaN', async () => {
      await setStoredCounter(Number.NaN)
      await expect(authenticate(10)).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
    })

    it('refuses when the stored counter is a string', async () => {
      // The metadata parser rejects an unparseable counter, so the credential
      // reads as unusable rather than as counter zero.
      await setStoredCounter('5')
      await expect(authenticate(10)).rejects.toThrow()
    })

    it('refuses a negative counter, which no authenticator should report', async () => {
      await expect(authenticate(-1)).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
    })
  })

  describe('the stored counter starts from a sensible place', () => {
    it('treats a missing counter as zero rather than as unusable', async () => {
      await adapter.credentials.patchMetadata(
        credentialId,
        { counter: undefined, credentialId: 'webauthn-cred-1', publicKey: 'AQIDBA' } as never,
        {},
      )
      await expect(authenticate(1)).resolves.toBeDefined()
    })

    it('accepts the first non-zero assertion against a zero baseline', async () => {
      await setStoredCounter(0)
      await expect(authenticate(1)).resolves.toBeDefined()
      expect(await storedCounter()).toBe(1)
    })
  })
})
