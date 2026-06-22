import { beforeEach, describe, expect, it, vi } from 'vitest'
import { AuthMemoryAdapter } from '../../../adapters/memory'
import { authRandomToken, authSha256, authTimingSafeEqual } from '../../../core/crypto'
import { AuthInMemoryEvents } from '../../../core/events'
import { AuthMemoryLimiter } from '../../../limiters/memory'
import type { AuthPasskeyProvider } from '../index'
import {
  AuthMemoryPasskeyChallengeStore,
  authBeginPasskeyRegistration,
  authCompletePasskeyRegistration,
  authPasskey,
} from '../index'
import type { AuthPasskeyTypes } from '../types'

interface ProfileShape {
  email: string
}

function makeContext(adapter: AuthMemoryAdapter<ProfileShape>) {
  return {
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    tenant: {},
    baseUrl: 'https://app.test',
    limiter: new AuthMemoryLimiter(),
    events: new AuthInMemoryEvents(),
    crypto: { authRandomToken, authSha256, authTimingSafeEqual },
  }
}

function makeMockWebAuthn(): AuthPasskeyTypes.ISimpleWebAuthnServerModule {
  return {
    generateRegistrationOptions: vi.fn(async (input) => ({
      challenge: 'reg-challenge-' + Math.random().toString(36).slice(2),
      rp: { id: input.rpID, name: input.rpName },
      user: { id: Buffer.from(input.userID).toString('base64url'), name: input.userName },
      pubKeyCredParams: [{ alg: -7, type: 'public-key' as const }],
    })),
    verifyRegistrationResponse: vi.fn(async () => ({
      verified: true,
      registrationInfo: {
        credential: {
          id: 'webauthn-cred-1',
          publicKey: new Uint8Array([1, 2, 3, 4]),
          counter: 0,
          transports: ['internal'],
        },
        aaguid: 'aaguid-1',
        credentialDeviceType: 'singleDevice' as const,
        credentialBackedUp: false,
      },
    })),
    generateAuthenticationOptions: vi.fn(async (input) => ({
      challenge: 'auth-challenge-' + Math.random().toString(36).slice(2),
      rpId: input.rpID,
      allowCredentials: input.allowCredentials,
      userVerification: input.userVerification,
    })),
    verifyAuthenticationResponse: vi.fn(async () => ({
      verified: true,
      authenticationInfo: {
        newCounter: 1,
        credentialID: 'webauthn-cred-1',
        userVerified: true,
      },
    })),
  }
}

describe('passkey provider - registration', () => {
  let adapter: AuthMemoryAdapter<ProfileShape>
  let identityId: string
  let opts: AuthPasskeyProvider.IOptions
  let mockWebauthn: AuthPasskeyTypes.ISimpleWebAuthnServerModule
  let challengeStore: AuthMemoryPasskeyChallengeStore

  beforeEach(async () => {
    adapter = new AuthMemoryAdapter<ProfileShape>()
    const identity = await adapter.identities.create({ profile: { email: 'a@b.com' }, providers: [] }, {})
    identityId = identity.id
    mockWebauthn = makeMockWebAuthn()
    challengeStore = new AuthMemoryPasskeyChallengeStore()
    opts = {
      rpName: 'Test App',
      rpID: 'app.test',
      expectedOrigins: 'https://app.test',
      findIdentityByEmail: async () => ({ id: identityId }),
      webauthnModule: mockWebauthn,
      challengeStore,
    }
  })

  it('beginRegistration returns options + persists challenge under reg:{sessionId}', async () => {
    const options = await authBeginPasskeyRegistration(opts, {
      identityId,
      userName: 'a@b.com',
      sessionId: 's1',
    })
    expect(options.challenge).toMatch(/^reg-challenge-/)
    expect(mockWebauthn.generateRegistrationOptions).toHaveBeenCalledWith(
      expect.objectContaining({ rpID: 'app.test', rpName: 'Test App', userName: 'a@b.com' }),
    )
    const stored = await challengeStore.take('reg:s1')
    expect(stored).toBe(options.challenge)
  })

  it('completeRegistration persists a passkey credential + returns its id', async () => {
    await authBeginPasskeyRegistration(opts, { identityId, userName: 'a@b.com', sessionId: 's1' })
    const credId = await authCompletePasskeyRegistration(opts, {
      identityId,
      sessionId: 's1',
      response: { id: 'webauthn-cred-1' },
      credentialStore: adapter.credentials,
      tenant: {},
    })
    expect(credId).toBeTruthy()
    const list = await adapter.credentials.listByIdentity(identityId, 'passkey', {})
    expect(list).toHaveLength(1)
    expect(list[0]!.secret).toBe('webauthn-cred-1')
    expect((list[0]!.metadata as { publicKey: string }).publicKey).toBeTruthy()
  })

  it('completeRegistration without prior begin throws AUTH/PASSKEY_MISMATCH', async () => {
    await expect(
      authCompletePasskeyRegistration(opts, {
        identityId,
        sessionId: 'stale',
        response: { id: 'x' },
        credentialStore: adapter.credentials,
        tenant: {},
      }),
    ).rejects.toMatchObject({ code: 'AUTH/PASSKEY_MISMATCH' })
  })

  it('completeRegistration with verified:false throws AUTH/PASSKEY_MISMATCH', async () => {
    mockWebauthn.verifyRegistrationResponse = vi.fn(async () => ({ verified: false }))
    await authBeginPasskeyRegistration(opts, { identityId, userName: 'a@b.com', sessionId: 's2' })
    await expect(
      authCompletePasskeyRegistration(opts, {
        identityId,
        sessionId: 's2',
        response: { id: 'webauthn-cred-1' },
        credentialStore: adapter.credentials,
        tenant: {},
      }),
    ).rejects.toMatchObject({ code: 'AUTH/PASSKEY_MISMATCH' })
  })
})

describe('passkey provider - sign-in', () => {
  let adapter: AuthMemoryAdapter<ProfileShape>
  let identityId: string
  let opts: AuthPasskeyProvider.IOptions
  let mockWebauthn: AuthPasskeyTypes.ISimpleWebAuthnServerModule
  let challengeStore: AuthMemoryPasskeyChallengeStore

  beforeEach(async () => {
    adapter = new AuthMemoryAdapter<ProfileShape>()
    const identity = await adapter.identities.create({ profile: { email: 'a@b.com' }, providers: [] }, {})
    identityId = identity.id
    mockWebauthn = makeMockWebAuthn()
    challengeStore = new AuthMemoryPasskeyChallengeStore()
    opts = {
      rpName: 'Test App',
      rpID: 'app.test',
      expectedOrigins: 'https://app.test',
      findIdentityByEmail: async () => ({ id: identityId }),
      webauthnModule: mockWebauthn,
      challengeStore,
    }
    await authBeginPasskeyRegistration(opts, { identityId, userName: 'a@b.com', sessionId: 'reg-s1' })
    await authCompletePasskeyRegistration(opts, {
      identityId,
      sessionId: 'reg-s1',
      response: { id: 'webauthn-cred-1' },
      credentialStore: adapter.credentials,
      tenant: {},
    })
  })

  it('begin returns json Intent with AuthenticationOptions + persists challenge', async () => {
    const provider = authPasskey<ProfileShape>(opts)
    const intents = await provider.begin(makeContext(adapter), {
      email: 'a@b.com',
      sessionId: 'login-1',
    })
    expect(intents).toHaveLength(1)
    expect(intents[0]!.type).toBe('json')
    const body = (intents[0] as { body: { challenge: string } }).body
    expect(body.challenge).toMatch(/^auth-challenge-/)
    const stored = await challengeStore.take('auth:login-1')
    expect(stored).toBe(body.challenge)
  })

  it('begin omits allowCredentials when no email hint', async () => {
    const provider = authPasskey<ProfileShape>(opts)
    await provider.begin(makeContext(adapter), { sessionId: 'login-2' })
    const call = (mockWebauthn.generateAuthenticationOptions as ReturnType<typeof vi.fn>).mock.calls[0]![0] as {
      allowCredentials?: unknown[]
    }
    expect(call.allowCredentials).toEqual([])
  })

  it('begin populates allowCredentials when email hint resolves an identity', async () => {
    const provider = authPasskey<ProfileShape>(opts)
    await provider.begin(makeContext(adapter), { email: 'a@b.com', sessionId: 'login-3' })
    const call = (mockWebauthn.generateAuthenticationOptions as ReturnType<typeof vi.fn>).mock.calls[0]![0] as {
      allowCredentials?: Array<{ id: string }>
    }
    expect(call.allowCredentials).toHaveLength(1)
    expect(call.allowCredentials![0]!.id).toBe('webauthn-cred-1')
  })

  it('complete emits startSession intent on verified assertion', async () => {
    const provider = authPasskey<ProfileShape>(opts)
    await provider.begin(makeContext(adapter), { sessionId: 'login-4' })
    const intents = await provider.complete(makeContext(adapter), {
      sessionId: 'login-4',
      response: { id: 'webauthn-cred-1' },
    })
    expect(intents).toHaveLength(1)
    expect(intents[0]!.type).toBe('startSession')
    expect((intents[0] as { identityId: string }).identityId).toBe(identityId)
    expect((intents[0] as { aal: number }).aal).toBe(2)
  })

  it('complete without prior begin throws AUTH/PASSKEY_MISMATCH', async () => {
    const provider = authPasskey<ProfileShape>(opts)
    await expect(
      provider.complete(makeContext(adapter), {
        sessionId: 'stale',
        response: { id: 'webauthn-cred-1' },
      }),
    ).rejects.toMatchObject({ code: 'AUTH/PASSKEY_MISMATCH' })
  })

  it('complete with unknown credential id throws AUTH/PASSKEY_MISMATCH', async () => {
    const provider = authPasskey<ProfileShape>(opts)
    await provider.begin(makeContext(adapter), { sessionId: 'login-5' })
    await expect(
      provider.complete(makeContext(adapter), {
        sessionId: 'login-5',
        response: { id: 'not-registered' },
      }),
    ).rejects.toMatchObject({ code: 'AUTH/PASSKEY_MISMATCH' })
  })

  it('complete with verified:false throws AUTH/PASSKEY_MISMATCH', async () => {
    mockWebauthn.verifyAuthenticationResponse = vi.fn(async () => ({
      verified: false,
      authenticationInfo: { newCounter: 0, credentialID: '', userVerified: false },
    }))
    const provider = authPasskey<ProfileShape>(opts)
    await provider.begin(makeContext(adapter), { sessionId: 'login-6' })
    await expect(
      provider.complete(makeContext(adapter), {
        sessionId: 'login-6',
        response: { id: 'webauthn-cred-1' },
      }),
    ).rejects.toMatchObject({ code: 'AUTH/PASSKEY_MISMATCH' })
  })

  it('begin/complete rejects missing sessionId with MISCONFIGURED', async () => {
    const provider = authPasskey<ProfileShape>(opts)
    await expect(provider.begin(makeContext(adapter), { sessionId: '' })).rejects.toMatchObject({
      code: 'AUTH/MISCONFIGURED',
    })
    await expect(provider.complete(makeContext(adapter), { sessionId: '', response: {} })).rejects.toMatchObject({
      code: 'AUTH/MISCONFIGURED',
    })
  })

  it('complete rejects when email hint resolves to a different identity than the credential', async () => {
    // Register a second identity + credential, then attempt to sign in with
    // the second identity's email hint but the FIRST identity's credential.
    const otherIdentity = await adapter.identities.create({ profile: { email: 'other@x.com' }, providers: [] }, {})
    opts.findIdentityByEmail = async (email) => {
      if (email === 'other@x.com') return { id: otherIdentity.id }
      if (email === 'alice@x.com') return { id: identityId }
      return null
    }
    const provider = authPasskey<ProfileShape>(opts)
    await provider.begin(makeContext(adapter), { sessionId: 'login-confusion' })
    await expect(
      provider.complete(makeContext(adapter), {
        sessionId: 'login-confusion',
        // Email of other-identity but credential of first identity.
        email: 'other@x.com',
        response: { id: 'webauthn-cred-1' },
      }),
    ).rejects.toMatchObject({ code: 'AUTH/PASSKEY_MISMATCH' })
  })

  it('complete rejects on counter rollback (newCounter <= stored)', async () => {
    // Authenticator presents a counter of 0 against a stored counter of 5.
    // Forcing a stored counter requires editing the credential row.
    const creds = await adapter.credentials.listByIdentity(identityId, 'passkey', {})
    const cred = creds[0]
    if (!cred) throw new Error('expected credential')
    ;(cred.metadata as { counter?: number }).counter = 5

    mockWebauthn.verifyAuthenticationResponse = vi.fn(async () => ({
      verified: true,
      authenticationInfo: {
        newCounter: 3, // regression vs stored=5
        credentialID: 'webauthn-cred-1',
        userVerified: true,
      },
    }))
    const provider = authPasskey<ProfileShape>(opts)
    await provider.begin(makeContext(adapter), { sessionId: 'login-rollback' })
    await expect(
      provider.complete(makeContext(adapter), {
        sessionId: 'login-rollback',
        response: { id: 'webauthn-cred-1' },
      }),
    ).rejects.toMatchObject({ code: 'AUTH/PASSKEY_MISMATCH' })
  })

  it('complete rejects when response.userHandle does not match the credential identity', async () => {
    mockWebauthn.verifyAuthenticationResponse = vi.fn(async () => ({
      verified: true,
      authenticationInfo: { newCounter: 0, credentialID: 'webauthn-cred-1', userVerified: true },
    }))
    const provider = authPasskey<ProfileShape>(opts)
    await provider.begin(makeContext(adapter), { sessionId: 'login-handle' })
    const bogusHandle = Buffer.from(new Uint8Array([9, 9, 9, 9])).toString('base64url')
    await expect(
      provider.complete(makeContext(adapter), {
        sessionId: 'login-handle',
        response: { id: 'webauthn-cred-1', response: { userHandle: bogusHandle } } as never,
      }),
    ).rejects.toMatchObject({ code: 'AUTH/PASSKEY_MISMATCH' })
  })

  describe('entry-point input caps (DoS defense)', () => {
    it('begin refuses an oversize sessionId (>256 chars)', async () => {
      const provider = authPasskey<ProfileShape>(opts)
      await expect(provider.begin(makeContext(adapter), { sessionId: 'x'.repeat(257) })).rejects.toMatchObject({
        code: 'AUTH/MISCONFIGURED',
      })
    })

    it('begin refuses a non-string sessionId', async () => {
      const provider = authPasskey<ProfileShape>(opts)
      await expect(provider.begin(makeContext(adapter), { sessionId: 42 as unknown as string })).rejects.toMatchObject({
        code: 'AUTH/MISCONFIGURED',
      })
    })

    it('begin refuses an oversize email (>254 chars per RFC 5321)', async () => {
      const provider = authPasskey<ProfileShape>(opts)
      await expect(
        provider.begin(makeContext(adapter), { sessionId: 's1', email: 'a'.repeat(255) }),
      ).rejects.toMatchObject({ code: 'AUTH/INVALID_CREDENTIALS' })
    })

    it('complete refuses an oversize sessionId', async () => {
      const provider = authPasskey<ProfileShape>(opts)
      await expect(
        provider.complete(makeContext(adapter), {
          sessionId: 'x'.repeat(257),
          response: { id: 'webauthn-cred-1' } as never,
        }),
      ).rejects.toMatchObject({ code: 'AUTH/MISCONFIGURED' })
    })
  })
})

describe('AuthMemoryPasskeyChallengeStore', () => {
  it('take returns the stored challenge once + removes it', async () => {
    const store = new AuthMemoryPasskeyChallengeStore()
    await store.put('k1', 'c1', 60_000)
    expect(await store.take('k1')).toBe('c1')
    expect(await store.take('k1')).toBeNull()
  })

  it('take returns null on TTL expiry', async () => {
    const store = new AuthMemoryPasskeyChallengeStore()
    await store.put('k1', 'c1', 5)
    await new Promise((r) => setTimeout(r, 10))
    expect(await store.take('k1')).toBeNull()
  })
})
