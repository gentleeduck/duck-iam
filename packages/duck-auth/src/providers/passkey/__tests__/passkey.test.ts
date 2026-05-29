/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAuthAdapter } from '../../../adapters/memory'
import { randomToken, sha256, timingSafeEqual } from '../../../core/crypto'
import { InMemoryEvents } from '../../../core/events'
import { MemoryLimiter } from '../../../limiters/memory'
import type { PasskeyProviderOptions } from '../index'
import { beginPasskeyRegistration, completePasskeyRegistration, MemoryPasskeyChallengeStore, passkey } from '../index'
import type { SimpleWebAuthnServerModule } from '../types'

interface ProfileShape {
  email: string
}

function makeContext(adapter: MemoryAuthAdapter<ProfileShape>) {
  return {
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    tenant: {},
    baseUrl: 'https://app.test',
    limiter: new MemoryLimiter(),
    events: new InMemoryEvents(),
    crypto: { randomToken, sha256, timingSafeEqual },
  }
}

function makeMockWebAuthn(): SimpleWebAuthnServerModule {
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
  let adapter: MemoryAuthAdapter<ProfileShape>
  let identityId: string
  let opts: PasskeyProviderOptions
  let mockWebauthn: SimpleWebAuthnServerModule
  let challengeStore: MemoryPasskeyChallengeStore

  beforeEach(async () => {
    adapter = new MemoryAuthAdapter<ProfileShape>()
    const identity = await adapter.identities.create({ profile: { email: 'a@b.com' }, providers: [] }, {})
    identityId = identity.id
    mockWebauthn = makeMockWebAuthn()
    challengeStore = new MemoryPasskeyChallengeStore()
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
    const options = await beginPasskeyRegistration(opts, {
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
    await beginPasskeyRegistration(opts, { identityId, userName: 'a@b.com', sessionId: 's1' })
    const credId = await completePasskeyRegistration(opts, {
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
      completePasskeyRegistration(opts, {
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
    await beginPasskeyRegistration(opts, { identityId, userName: 'a@b.com', sessionId: 's2' })
    await expect(
      completePasskeyRegistration(opts, {
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
  let adapter: MemoryAuthAdapter<ProfileShape>
  let identityId: string
  let opts: PasskeyProviderOptions
  let mockWebauthn: SimpleWebAuthnServerModule
  let challengeStore: MemoryPasskeyChallengeStore

  beforeEach(async () => {
    adapter = new MemoryAuthAdapter<ProfileShape>()
    const identity = await adapter.identities.create({ profile: { email: 'a@b.com' }, providers: [] }, {})
    identityId = identity.id
    mockWebauthn = makeMockWebAuthn()
    challengeStore = new MemoryPasskeyChallengeStore()
    opts = {
      rpName: 'Test App',
      rpID: 'app.test',
      expectedOrigins: 'https://app.test',
      findIdentityByEmail: async () => ({ id: identityId }),
      webauthnModule: mockWebauthn,
      challengeStore,
    }
    await beginPasskeyRegistration(opts, { identityId, userName: 'a@b.com', sessionId: 'reg-s1' })
    await completePasskeyRegistration(opts, {
      identityId,
      sessionId: 'reg-s1',
      response: { id: 'webauthn-cred-1' },
      credentialStore: adapter.credentials,
      tenant: {},
    })
  })

  it('begin returns json Intent with AuthenticationOptions + persists challenge', async () => {
    const provider = passkey<ProfileShape>(opts)
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
    const provider = passkey<ProfileShape>(opts)
    await provider.begin(makeContext(adapter), { sessionId: 'login-2' })
    const call = (mockWebauthn.generateAuthenticationOptions as ReturnType<typeof vi.fn>).mock.calls[0]![0] as {
      allowCredentials?: unknown[]
    }
    expect(call.allowCredentials).toEqual([])
  })

  it('begin populates allowCredentials when email hint resolves an identity', async () => {
    const provider = passkey<ProfileShape>(opts)
    await provider.begin(makeContext(adapter), { email: 'a@b.com', sessionId: 'login-3' })
    const call = (mockWebauthn.generateAuthenticationOptions as ReturnType<typeof vi.fn>).mock.calls[0]![0] as {
      allowCredentials?: Array<{ id: string }>
    }
    expect(call.allowCredentials).toHaveLength(1)
    expect(call.allowCredentials![0]!.id).toBe('webauthn-cred-1')
  })

  it('complete emits startSession intent on verified assertion', async () => {
    const provider = passkey<ProfileShape>(opts)
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
    const provider = passkey<ProfileShape>(opts)
    await expect(
      provider.complete(makeContext(adapter), {
        sessionId: 'stale',
        response: { id: 'webauthn-cred-1' },
      }),
    ).rejects.toMatchObject({ code: 'AUTH/PASSKEY_MISMATCH' })
  })

  it('complete with unknown credential id throws AUTH/PASSKEY_MISMATCH', async () => {
    const provider = passkey<ProfileShape>(opts)
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
    const provider = passkey<ProfileShape>(opts)
    await provider.begin(makeContext(adapter), { sessionId: 'login-6' })
    await expect(
      provider.complete(makeContext(adapter), {
        sessionId: 'login-6',
        response: { id: 'webauthn-cred-1' },
      }),
    ).rejects.toMatchObject({ code: 'AUTH/PASSKEY_MISMATCH' })
  })

  it('begin/complete rejects missing sessionId with MISCONFIGURED', async () => {
    const provider = passkey<ProfileShape>(opts)
    await expect(provider.begin(makeContext(adapter), { sessionId: '' })).rejects.toMatchObject({
      code: 'AUTH/MISCONFIGURED',
    })
    await expect(provider.complete(makeContext(adapter), { sessionId: '', response: {} })).rejects.toMatchObject({
      code: 'AUTH/MISCONFIGURED',
    })
  })
})

describe('MemoryPasskeyChallengeStore', () => {
  it('take returns the stored challenge once + removes it', async () => {
    const store = new MemoryPasskeyChallengeStore()
    await store.put('k1', 'c1', 60_000)
    expect(await store.take('k1')).toBe('c1')
    expect(await store.take('k1')).toBeNull()
  })

  it('take returns null on TTL expiry', async () => {
    const store = new MemoryPasskeyChallengeStore()
    await store.put('k1', 'c1', 5)
    await new Promise((r) => setTimeout(r, 10))
    expect(await store.take('k1')).toBeNull()
  })
})
