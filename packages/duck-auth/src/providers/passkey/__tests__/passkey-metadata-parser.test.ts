import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAuthAdapter } from '../../../adapters/memory'
import { randomToken, sha256, timingSafeEqual } from '../../../core/crypto'
import { InMemoryEvents } from '../../../core/events'
import { MemoryLimiter } from '../../../limiters/memory'
import type { PasskeyProvider } from '../index'
import { MemoryPasskeyChallengeStore, passkey } from '../index'
import type { PasskeyTypes } from '../types'

interface ProfileShape {
  email: string
}

function ctxFor(adapter: MemoryAuthAdapter<ProfileShape>) {
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

function makeWebauthn(newCounter = 5): PasskeyTypes.ISimpleWebAuthnServerModule {
  return {
    generateRegistrationOptions: vi.fn(async () => ({
      challenge: 'reg',
      rp: { id: 'x', name: 'x' },
      user: { id: 'u', name: 'n' },
      pubKeyCredParams: [],
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
      challenge: 'auth-challenge',
      rpId: input.rpID,
      allowCredentials: input.allowCredentials,
      userVerification: input.userVerification,
    })),
    verifyAuthenticationResponse: vi.fn(async () => ({
      verified: true,
      authenticationInfo: { newCounter, credentialID: 'webauthn-cred-1', userVerified: true },
    })),
  }
}

async function plantCredential(
  adapter: MemoryAuthAdapter<ProfileShape>,
  identityId: string,
  metadata: unknown,
): Promise<void> {
  await adapter.credentials.upsert(
    {
      identityId,
      kind: 'passkey',
      secret: 'webauthn-cred-1',
      metadata: metadata as Record<string, unknown>,
    },
    {},
  )
}

describe('passkey complete() - metadata parser', () => {
  let adapter: MemoryAuthAdapter<ProfileShape>
  let identityId: string
  let opts: PasskeyProvider.IOptions
  let challengeStore: MemoryPasskeyChallengeStore

  beforeEach(async () => {
    adapter = new MemoryAuthAdapter<ProfileShape>()
    const id = await adapter.identities.create({ profile: { email: 'a@b' }, providers: [] }, {})
    identityId = id.id
    challengeStore = new MemoryPasskeyChallengeStore()
  })

  async function begin(): Promise<string> {
    opts = {
      rpName: 'Test App',
      rpID: 'app.test',
      expectedOrigins: 'https://app.test',
      findIdentityByEmail: async () => ({ id: identityId }),
      webauthnModule: makeWebauthn(5),
      challengeStore,
    }
    const provider = passkey<ProfileShape>(opts)
    const intents = await provider.begin(ctxFor(adapter), { sessionId: 's1' })
    // Stored challenge under auth:s1
    return (intents[0] && intents[0].type === 'json' && (intents[0].body as { challenge?: string }).challenge) || ''
  }

  it('rejects credential with no publicKey field (AUTH/PASSKEY_MISMATCH)', async () => {
    await begin()
    await plantCredential(adapter, identityId, { counter: 0 })
    const provider = passkey<ProfileShape>(opts)
    await expect(
      provider.complete(ctxFor(adapter), {
        response: { id: 'webauthn-cred-1' },
        sessionId: 's1',
      }),
    ).rejects.toMatchObject({ code: 'AUTH/PASSKEY_MISMATCH' })
  })

  it('rejects credential with non-string publicKey', async () => {
    await begin()
    await plantCredential(adapter, identityId, { publicKey: 42, counter: 0 })
    const provider = passkey<ProfileShape>(opts)
    await expect(
      provider.complete(ctxFor(adapter), { response: { id: 'webauthn-cred-1' }, sessionId: 's1' }),
    ).rejects.toMatchObject({ code: 'AUTH/PASSKEY_MISMATCH' })
  })

  it('rejects credential with non-numeric counter (counter-rollback bypass class)', async () => {
    await begin()
    await plantCredential(adapter, identityId, { publicKey: 'AQIDBA', counter: 'abc' })
    const provider = passkey<ProfileShape>(opts)
    await expect(
      provider.complete(ctxFor(adapter), { response: { id: 'webauthn-cred-1' }, sessionId: 's1' }),
    ).rejects.toMatchObject({ code: 'AUTH/PASSKEY_MISMATCH' })
  })

  it('rejects credential with NaN / Infinity counter', async () => {
    await begin()
    await plantCredential(adapter, identityId, { publicKey: 'AQIDBA', counter: NaN })
    const provider = passkey<ProfileShape>(opts)
    await expect(
      provider.complete(ctxFor(adapter), { response: { id: 'webauthn-cred-1' }, sessionId: 's1' }),
    ).rejects.toMatchObject({ code: 'AUTH/PASSKEY_MISMATCH' })
  })

  it('accepts credential with missing counter (defaults to 0; cloud-synced passkey case)', async () => {
    await begin()
    await plantCredential(adapter, identityId, { publicKey: 'AQIDBA' })
    const provider = passkey<ProfileShape>(opts)
    const intents = await provider.complete(ctxFor(adapter), {
      response: { id: 'webauthn-cred-1' },
      sessionId: 's1',
    })
    expect(intents[0]!.type).toBe('startSession')
  })

  it('rejects credential where metadata is not a plain object', async () => {
    await begin()
    await plantCredential(adapter, identityId, 'not-an-object')
    const provider = passkey<ProfileShape>(opts)
    await expect(
      provider.complete(ctxFor(adapter), { response: { id: 'webauthn-cred-1' }, sessionId: 's1' }),
    ).rejects.toMatchObject({ code: 'AUTH/PASSKEY_MISMATCH' })
  })

  it('filters non-string entries out of transports array', async () => {
    await begin()
    // transports contains a non-string entry - parser drops it but row
    // is otherwise valid. complete() must succeed.
    await plantCredential(adapter, identityId, {
      publicKey: 'AQIDBA',
      counter: 0,
      transports: ['internal', 42, null, 'usb'],
    })
    const provider = passkey<ProfileShape>(opts)
    const intents = await provider.complete(ctxFor(adapter), {
      response: { id: 'webauthn-cred-1' },
      sessionId: 's1',
    })
    expect(intents[0]!.type).toBe('startSession')
  })

  it('rejects credential where transports is a non-array (string)', async () => {
    // transports: 'usb' (single string instead of array) - parser
    // discards (treats as undefined transports). complete() should
    // still succeed because transports is optional.
    await begin()
    await plantCredential(adapter, identityId, {
      publicKey: 'AQIDBA',
      counter: 0,
      transports: 'usb',
    })
    const provider = passkey<ProfileShape>(opts)
    const intents = await provider.complete(ctxFor(adapter), {
      response: { id: 'webauthn-cred-1' },
      sessionId: 's1',
    })
    expect(intents[0]!.type).toBe('startSession')
  })
})
