import { createHash, randomBytes } from 'node:crypto'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { orNull } from '~/core/answer'
import { randomToken, sha256, timingSafeEqual } from '~/core/crypto'
import { AuthError } from '~/core/errors'
import { InMemoryEvents } from '~/core/events'
import { Identities } from '~/core/identities'
import { MemoryLimiter } from '~/limiters/memory'
import { type SoftAuthenticator, softAuthenticator } from '~/test/soft-authenticator'
import { identityInput } from '~/test/store-inputs'
import {
  AuthMemoryPasskeyChallengeStore,
  beginPasskeyRegistration,
  completePasskeyRegistration,
  passkey,
} from '../index'
import type { Passkey } from '../passkey.types'

interface ProfileShape extends Identities.ProfileMetadataBase {}

function makeContext(adapter: MemoryAdapter<ProfileShape>) {
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
    crypto: { authRandomToken: randomToken, authSha256: sha256, authTimingSafeEqual: timingSafeEqual },
  }
}

function makeMockWebAuthn(): Passkey.SimpleWebAuthnServerModule {
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
  let adapter: MemoryAdapter<ProfileShape>
  let identityId: string
  let opts: Passkey.Options
  let mockWebauthn: Passkey.SimpleWebAuthnServerModule
  let challengeStore: AuthMemoryPasskeyChallengeStore

  beforeEach(async () => {
    adapter = new MemoryAdapter<ProfileShape>()
    const identity = await adapter.identities.create(
      identityInput({ profile: { email: 'a@b.com', username: 'a' }, providers: [] }),
    )
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
    const options = await beginPasskeyRegistration(opts, {
      identityId,
      userName: 'a@b.com',
      sessionId: 's1',
      credentialStore: adapter.credentials,
      tenant: {},
    })
    expect(options.challenge).toMatch(/^reg-challenge-/)
    expect(mockWebauthn.generateRegistrationOptions).toHaveBeenCalledWith(
      expect.objectContaining({ rpID: 'app.test', rpName: 'Test App', userName: 'a@b.com' }),
    )
    const stored = await challengeStore.take('reg:s1')
    expect(stored).toBe(options.challenge)
  })

  it('completeRegistration persists a passkey credential + returns its id', async () => {
    await beginPasskeyRegistration(opts, {
      identityId,
      userName: 'a@b.com',
      sessionId: 's1',
      credentialStore: adapter.credentials,
      tenant: {},
    })
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
    expect(list[0]?.metadata?.publicKey).toBeTruthy()
  })

  it('completeRegistration stores the transports the library names, once each, whatever the client sent', async () => {
    vi.mocked(mockWebauthn.verifyRegistrationResponse).mockResolvedValueOnce({
      registrationInfo: {
        credential: {
          counter: 0,
          id: 'webauthn-cred-1',
          publicKey: new Uint8Array([1, 2, 3, 4]),
          transports: JSON.parse('["usb", {"x": 1}, "usb", "nfc", 7]'),
        },
      },
      verified: true,
    })
    const input = { credentialStore: adapter.credentials, identityId, sessionId: 's1', tenant: {} }
    await beginPasskeyRegistration(opts, { ...input, userName: 'a@b.com' })
    await completePasskeyRegistration(opts, { ...input, response: { id: 'webauthn-cred-1' } })
    const [row] = await adapter.credentials.listByIdentity(identityId, 'passkey', {})
    expect(row?.metadata).toMatchObject({ transports: ['usb', 'nfc'] })
  })

  it('completeRegistration without prior begin throws AUTH_PASSKEY_MISMATCH', async () => {
    await expect(
      completePasskeyRegistration(opts, {
        identityId,
        sessionId: 'stale',
        response: { id: 'x' },
        credentialStore: adapter.credentials,
        tenant: {},
      }),
    ).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
  })

  it('completeRegistration turns a throwing verifier into AUTH_PASSKEY_MISMATCH', async () => {
    // The real verifier reports a bad origin, a wrong rpID or an unparseable attestation by throwing a
    // plain Error. Nothing upstream catches one, so it used to leave as an unmapped 500 carrying the
    // library's own wording.
    mockWebauthn.verifyRegistrationResponse = vi.fn(async () => {
      throw new Error('Unexpected registration response origin "https://evil.test"')
    })
    await beginPasskeyRegistration(opts, {
      identityId,
      userName: 'a@b.com',
      sessionId: 's3',
      credentialStore: adapter.credentials,
      tenant: {},
    })
    await expect(
      completePasskeyRegistration(opts, {
        identityId,
        sessionId: 's3',
        response: { id: 'webauthn-cred-1' },
        credentialStore: adapter.credentials,
        tenant: {},
      }),
    ).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
  })

  it('completeRegistration with verified:false throws AUTH_PASSKEY_MISMATCH', async () => {
    mockWebauthn.verifyRegistrationResponse = vi.fn(async () => ({ verified: false }))
    await beginPasskeyRegistration(opts, {
      identityId,
      userName: 'a@b.com',
      sessionId: 's2',
      credentialStore: adapter.credentials,
      tenant: {},
    })
    await expect(
      completePasskeyRegistration(opts, {
        identityId,
        sessionId: 's2',
        response: { id: 'webauthn-cred-1' },
        credentialStore: adapter.credentials,
        tenant: {},
      }),
    ).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
  })
})

describe('passkey provider - a credential id already registered', () => {
  it('is refused, so the account that holds it can still sign in with it', async () => {
    const adapter = new MemoryAdapter<ProfileShape>()
    const owner = await adapter.identities.create(
      identityInput({ profile: { email: 'owner@b.com', username: 'owner' }, providers: [] }),
    )
    const other = await adapter.identities.create(
      identityInput({ profile: { email: 'other@b.com', username: 'other' }, providers: [] }),
    )
    const store = new AuthMemoryPasskeyChallengeStore()
    let challenge = ''
    const opts: Passkey.Options = {
      challengeStore: {
        put: (key, value, ttlMs) => {
          challenge = value
          return store.put(key, value, ttlMs)
        },
        take: (key) => store.take(key),
      },
      expectedOrigins: 'https://app.test',
      findIdentityByEmail: async () => ({ id: owner.id }),
      rpID: 'app.test',
      rpName: 'Test App',
    }
    const register = async (identityId: string, key: SoftAuthenticator): Promise<string> => {
      const input = { credentialStore: adapter.credentials, identityId, sessionId: identityId, tenant: {} }
      await beginPasskeyRegistration(opts, { ...input, userName: identityId })
      return completePasskeyRegistration(opts, { ...input, response: key.register(challenge) })
    }
    const owned = softAuthenticator('app.test', 'https://app.test')
    await register(owner.id, owned)

    // The id is no secret: `begin` offers it to anyone who names the owner's address.
    const claimed = softAuthenticator('app.test', 'https://app.test', { id: owned.id })
    await expect(register(other.id, claimed)).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
    await expect(register(other.id, softAuthenticator('app.test', 'https://app.test'))).resolves.toBeTruthy()

    const provider = passkey(opts)
    const ctx = makeContext(adapter)
    await provider.begin(ctx, { email: 'owner@b.com', sessionId: 'login' })
    await expect(provider.complete(ctx, { response: owned.assert(challenge, 1), sessionId: 'login' })).resolves.toEqual(
      [expect.objectContaining({ identityId: owner.id, type: 'startSession' })],
    )
  })
})

describe('passkey provider - with the real verifier', () => {
  let adapter: MemoryAdapter<ProfileShape>
  let opts: Passkey.Options
  let challenge = ''

  beforeEach(() => {
    adapter = new MemoryAdapter<ProfileShape>()
    const store = new AuthMemoryPasskeyChallengeStore()
    opts = {
      challengeStore: {
        put: (key, value, ttlMs) => {
          challenge = value
          return store.put(key, value, ttlMs)
        },
        take: (key) => store.take(key),
      },
      expectedOrigins: 'https://app.test',
      findIdentityByEmail: async () => null,
      rpID: 'app.test',
      rpName: 'Test App',
    }
  })

  const register = async (key: SoftAuthenticator): Promise<string> => {
    const input = { credentialStore: adapter.credentials, identityId: 'u1', sessionId: 'reg', tenant: {} }
    await beginPasskeyRegistration(opts, { ...input, userName: 'u1' })
    return completePasskeyRegistration(opts, { ...input, response: key.register(challenge) })
  }

  it('refuses a key under an algorithm it did not offer, and takes one it did', async () => {
    // ES512 is an algorithm the verifier knows and registration does not offer.
    const es512 = softAuthenticator('app.test', 'https://app.test', { curve: 'P-521' })
    await expect(register(es512)).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
    await expect(register(softAuthenticator('app.test', 'https://app.test'))).resolves.toBeTruthy()
  })

  it('takes a credential id of 1023 bytes, which then signs in, and refuses one of 1024', async () => {
    const over = softAuthenticator('app.test', 'https://app.test', { id: randomBytes(1024).toString('base64url') })
    await expect(register(over)).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
    expect(await adapter.credentials.listByIdentity('u1', 'passkey', {})).toEqual([])

    const longest = softAuthenticator('app.test', 'https://app.test', { id: randomBytes(1023).toString('base64url') })
    await register(longest)
    const provider = passkey(opts)
    await provider.begin(makeContext(adapter), { sessionId: 'login' })
    await expect(
      provider.complete(makeContext(adapter), { response: longest.assert(challenge, 1), sessionId: 'login' }),
    ).resolves.toEqual([expect.objectContaining({ identityId: 'u1', type: 'startSession' })])
  })

  it('signs in at AAL 2 when the authenticator verified the user, and at AAL 1 on presence alone', async () => {
    const key = softAuthenticator('app.test', 'https://app.test')
    await register(key)
    const provider = passkey(opts)
    await provider.begin(makeContext(adapter), { sessionId: 'verified' })
    await expect(
      provider.complete(makeContext(adapter), { response: key.assert(challenge, 1), sessionId: 'verified' }),
    ).resolves.toEqual([expect.objectContaining({ aal: 2 })])
    await provider.begin(makeContext(adapter), { sessionId: 'present' })
    await expect(
      provider.complete(makeContext(adapter), {
        response: key.assert(challenge, 2, { verified: false }),
        sessionId: 'present',
      }),
    ).resolves.toEqual([expect.objectContaining({ aal: 1 })])
  })
})

describe('passkey provider - sign-in', () => {
  let adapter: MemoryAdapter<ProfileShape>
  let identityId: string
  let opts: Passkey.Options
  let mockWebauthn: Passkey.SimpleWebAuthnServerModule
  let challengeStore: AuthMemoryPasskeyChallengeStore

  beforeEach(async () => {
    adapter = new MemoryAdapter<ProfileShape>()
    const identity = await adapter.identities.create(
      identityInput({ profile: { email: 'a@b.com', username: 'a' }, providers: [] }),
    )
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
    await beginPasskeyRegistration(opts, {
      identityId,
      userName: 'a@b.com',
      sessionId: 'reg-s1',
      credentialStore: adapter.credentials,
      tenant: {},
    })
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
    const stored = await challengeStore.take('auth:login-1')
    expect(stored).toMatch(/^auth-challenge-/)
    expect(intents[0]).toMatchObject({ body: { challenge: stored }, type: 'json' })
  })

  it('begin omits allowCredentials when no email hint', async () => {
    const provider = passkey<ProfileShape>(opts)
    await provider.begin(makeContext(adapter), { sessionId: 'login-2' })
    expect(vi.mocked(mockWebauthn.generateAuthenticationOptions).mock.calls[0]?.[0].allowCredentials).toEqual([])
  })

  it('begin populates allowCredentials when email hint resolves an identity', async () => {
    const provider = passkey<ProfileShape>(opts)
    await provider.begin(makeContext(adapter), { email: 'a@b.com', sessionId: 'login-3' })
    expect(vi.mocked(mockWebauthn.generateAuthenticationOptions).mock.calls[0]?.[0].allowCredentials).toEqual([
      expect.objectContaining({ id: 'webauthn-cred-1' }),
    ])
  })

  it('complete emits startSession intent on verified assertion', async () => {
    const provider = passkey<ProfileShape>(opts)
    await provider.begin(makeContext(adapter), { sessionId: 'login-4' })
    const intents = await provider.complete(makeContext(adapter), {
      sessionId: 'login-4',
      response: { id: 'webauthn-cred-1' },
    })
    expect(intents).toEqual([expect.objectContaining({ aal: 2, identityId, type: 'startSession' })])
  })

  it('complete without prior begin throws AUTH_PASSKEY_MISMATCH', async () => {
    const provider = passkey<ProfileShape>(opts)
    await expect(
      provider.complete(makeContext(adapter), {
        sessionId: 'stale',
        response: { id: 'webauthn-cred-1' },
      }),
    ).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
  })

  it('complete with unknown credential id throws AUTH_PASSKEY_MISMATCH', async () => {
    const provider = passkey<ProfileShape>(opts)
    await provider.begin(makeContext(adapter), { sessionId: 'login-5' })
    await expect(
      provider.complete(makeContext(adapter), {
        sessionId: 'login-5',
        response: { id: 'not-registered' },
      }),
    ).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
  })

  it.each([null, undefined, 'webauthn-cred-1'])('complete refuses a response of %o as a mismatch', async (response) => {
    const provider = passkey<ProfileShape>(opts)
    await provider.begin(makeContext(adapter), { sessionId: 'login-7' })
    await expect(provider.complete(makeContext(adapter), { response, sessionId: 'login-7' })).rejects.toMatchObject({
      code: 'AUTH_PASSKEY_MISMATCH',
    })
    await provider.begin(makeContext(adapter), { sessionId: 'login-8' })
    await expect(
      provider.complete(makeContext(adapter), { response: { id: 'webauthn-cred-1' }, sessionId: 'login-8' }),
    ).resolves.toHaveLength(1)
  })

  it('complete with verified:false throws AUTH_PASSKEY_MISMATCH', async () => {
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
    ).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
  })

  it('begin/complete rejects missing sessionId with MISCONFIGURED', async () => {
    const provider = passkey<ProfileShape>(opts)
    await expect(provider.begin(makeContext(adapter), { sessionId: '' })).rejects.toMatchObject({
      code: 'AUTH_MISCONFIGURED',
    })
    await expect(provider.complete(makeContext(adapter), { sessionId: '', response: {} })).rejects.toMatchObject({
      code: 'AUTH_MISCONFIGURED',
    })
  })

  it('complete rejects when email hint resolves to a different identity than the credential', async () => {
    // Register a second identity + credential, then attempt to sign in with
    // the second identity's email hint but the FIRST identity's credential.
    const otherIdentity = await adapter.identities.create(
      identityInput({ profile: { email: 'other@x.com', username: 'o' }, providers: [] }),
    )
    opts.findIdentityByEmail = async (email) => {
      if (email === 'other@x.com') return { id: otherIdentity.id }
      if (email === 'alice@x.com') return { id: identityId }
      return null
    }
    const provider = passkey<ProfileShape>(opts)
    await provider.begin(makeContext(adapter), { sessionId: 'login-confusion' })
    await expect(
      provider.complete(makeContext(adapter), {
        sessionId: 'login-confusion',
        // Email of other-identity but credential of first identity.
        email: 'other@x.com',
        response: { id: 'webauthn-cred-1' },
      }),
    ).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
  })

  it('begin answers an empty allow list when the host lookup rejects, rather than failing the ceremony', async () => {
    // `auth.identities.getByEmail` is the wiring a host writes, and it rejects on a miss. An unknown
    // address has to stay indistinguishable from a known one holding no passkeys.
    opts.findIdentityByEmail = () => Promise.reject(new AuthError('AUTH_IDENTITY_NOT_FOUND'))
    const provider = passkey<ProfileShape>(opts)

    await provider.begin(makeContext(adapter), { email: 'nobody@x.com', sessionId: 'login-absent' })

    expect(vi.mocked(mockWebauthn.generateAuthenticationOptions).mock.calls[0]?.[0].allowCredentials).toEqual([])
  })

  it('complete answers a rejecting host lookup as a mismatch, not as a missing identity', async () => {
    opts.findIdentityByEmail = () => Promise.reject(new AuthError('AUTH_IDENTITY_NOT_FOUND'))
    const provider = passkey<ProfileShape>(opts)
    await provider.begin(makeContext(adapter), { sessionId: 'login-absent-hint' })

    // AUTH_IDENTITY_NOT_FOUND here would tell an unknown address apart from one belonging to someone else.
    await expect(
      provider.complete(makeContext(adapter), {
        sessionId: 'login-absent-hint',
        email: 'nobody@x.com',
        response: { id: 'webauthn-cred-1' },
      }),
    ).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
  })

  it('complete rejects on counter rollback (newCounter <= stored)', async () => {
    // Authenticator presents a counter of 3 against a stored counter of 5. The zero-against-nonzero case
    // is the one section 6.1.3 turns on and lives in `passkey-counter.test.ts`.
    // Forcing a stored counter requires editing the credential row.
    const creds = await adapter.credentials.listByIdentity(identityId, 'passkey', {})
    const cred = creds[0]
    if (!cred) throw new Error('expected credential')
    await adapter.credentials.patchMetadata(cred.id, { counter: 5 }, {})

    mockWebauthn.verifyAuthenticationResponse = vi.fn(async () => ({
      verified: true,
      authenticationInfo: {
        newCounter: 3, // regression vs stored=5
        credentialID: 'webauthn-cred-1',
        userVerified: true,
      },
    }))
    const provider = passkey<ProfileShape>(opts)
    await provider.begin(makeContext(adapter), { sessionId: 'login-rollback' })
    await expect(
      provider.complete(makeContext(adapter), {
        sessionId: 'login-rollback',
        response: { id: 'webauthn-cred-1' },
      }),
    ).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
  })

  it('complete rejects when response.userHandle does not match the credential identity', async () => {
    mockWebauthn.verifyAuthenticationResponse = vi.fn(async () => ({
      verified: true,
      authenticationInfo: { newCounter: 0, credentialID: 'webauthn-cred-1', userVerified: true },
    }))
    const provider = passkey<ProfileShape>(opts)
    await provider.begin(makeContext(adapter), { sessionId: 'login-handle' })
    const bogusHandle = Buffer.from(new Uint8Array([9, 9, 9, 9])).toString('base64url')
    await expect(
      provider.complete(makeContext(adapter), {
        sessionId: 'login-handle',
        response: { id: 'webauthn-cred-1', response: { userHandle: bogusHandle } },
      }),
    ).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
  })

  it('complete refuses a userHandle that is not a string rather than skipping the binding', async () => {
    // `Buffer.from` throws on a number, the decoder answered null for it, and the caller read that null
    // as "no handle was sent" - so a request could switch the binding off by sending one.
    mockWebauthn.verifyAuthenticationResponse = vi.fn(async () => ({
      verified: true,
      authenticationInfo: { newCounter: 0, credentialID: 'webauthn-cred-1', userVerified: true },
    }))
    const provider = passkey<ProfileShape>(opts)
    await provider.begin(makeContext(adapter), { sessionId: 'login-handle-type' })
    await expect(
      provider.complete(makeContext(adapter), {
        sessionId: 'login-handle-type',
        response: { id: 'webauthn-cred-1', response: { userHandle: 12345 } },
      }),
    ).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
  })

  it('complete accepts the identity own handle, so the refusal above is the type and not the check', async () => {
    mockWebauthn.verifyAuthenticationResponse = vi.fn(async () => ({
      verified: true,
      authenticationInfo: { newCounter: 0, credentialID: 'webauthn-cred-1', userVerified: true },
    }))
    const provider = passkey<ProfileShape>(opts)
    await provider.begin(makeContext(adapter), { sessionId: 'login-handle-ok' })
    const handle = createHash('sha256').update(identityId, 'utf8').digest('base64url')
    await expect(
      provider.complete(makeContext(adapter), {
        sessionId: 'login-handle-ok',
        response: { id: 'webauthn-cred-1', response: { userHandle: handle } },
      }),
    ).resolves.toBeDefined()
  })

  describe('entry-point input caps (DoS defense)', () => {
    it('begin refuses an oversize sessionId (>256 chars)', async () => {
      const provider = passkey<ProfileShape>(opts)
      await expect(provider.begin(makeContext(adapter), { sessionId: 'x'.repeat(257) })).rejects.toMatchObject({
        code: 'AUTH_MISCONFIGURED',
      })
    })

    it('begin refuses a non-string sessionId', async () => {
      const provider = passkey<ProfileShape>(opts)
      // @ts-expect-error a number where the contract takes a string
      await expect(provider.begin(makeContext(adapter), { sessionId: 42 })).rejects.toMatchObject({
        code: 'AUTH_MISCONFIGURED',
      })
    })

    it('begin refuses an oversize email (>254 chars per RFC 5321)', async () => {
      const provider = passkey<ProfileShape>(opts)
      await expect(
        provider.begin(makeContext(adapter), { sessionId: 's1', email: 'a'.repeat(255) }),
      ).rejects.toMatchObject({ code: 'AUTH_INVALID_CREDENTIALS' })
    })

    it('complete refuses an oversize sessionId', async () => {
      const provider = passkey<ProfileShape>(opts)
      await expect(
        provider.complete(makeContext(adapter), {
          sessionId: 'x'.repeat(257),
          response: { id: 'webauthn-cred-1' },
        }),
      ).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
    })
  })

  it('complete refuses a revoked credential whose marker is an epoch int, not a Date', async () => {
    const provider = passkey<ProfileShape>(opts)
    await provider.begin(makeContext(adapter), { sessionId: 'login-revoked' })
    const live = await adapter.credentials.findByHashedSecret('webauthn-cred-1', 'passkey', {})
    // What a store keeping timestamps as epoch ints answers for a row revoked at the epoch. `Date | null`
    // & `number` is `never`, so this stays assignable without a cast, and stays falsy.
    const epochMarker = Object.assign({ ...live }, { revokedAt: 0 })
    const ctx = makeContext(adapter)
    ctx.stores.credentials = new Proxy(adapter.credentials, {
      get: (target, prop, receiver) => {
        if (prop === 'findByHashedSecret') return async () => epochMarker
        const value = Reflect.get(target, prop, receiver)
        return typeof value === 'function' ? (...args: unknown[]) => value.apply(target, args) : value
      },
    })

    await expect(
      provider.complete(ctx, { sessionId: 'login-revoked', response: { id: 'webauthn-cred-1' } }),
    ).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
  })
})

describe('passkey provider - the challenge lifetime', () => {
  const opts = {
    expectedOrigins: 'https://app.test',
    findIdentityByEmail: async () => null,
    rpID: 'app.test',
    rpName: 'Test App',
  }

  function recordingStore(): Passkey.ChallengeStore & { ttls: number[] } {
    const ttls: number[] = []
    return {
      ttls,
      async put(_key, _challenge, ttlMs) {
        ttls.push(ttlMs)
      },
      async take() {
        throw new AuthError('AUTH_CREDENTIAL_NOT_FOUND')
      },
    }
  }

  const register = (challengeStore: Passkey.ChallengeStore, challengeTtlMs: number) =>
    beginPasskeyRegistration(
      { ...opts, challengeStore, challengeTtlMs, webauthnModule: makeMockWebAuthn() },
      {
        credentialStore: new MemoryAdapter<ProfileShape>().credentials,
        identityId: 'id-1',
        sessionId: 's1',
        tenant: {},
        userName: 'a@b.com',
      },
    )

  it.each([Number.NaN, 0, -1, Number.POSITIVE_INFINITY])(
    'refuses challengeTtlMs %o at construction and before registering',
    async (challengeTtlMs) => {
      expect(() => passkey<ProfileShape>({ ...opts, challengeTtlMs })).toThrow(
        expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
      )
      const store = recordingStore()
      await expect(register(store, challengeTtlMs)).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
      expect(store.ttls).toEqual([])
    },
  )

  it('stores both ceremonies for the lifetime it was given', async () => {
    const store = recordingStore()
    const provider = passkey<ProfileShape>({
      ...opts,
      challengeStore: store,
      challengeTtlMs: 60_000,
      webauthnModule: makeMockWebAuthn(),
    })
    await provider.begin(makeContext(new MemoryAdapter<ProfileShape>()), { sessionId: 's1' })
    await register(store, 60_000)
    expect(store.ttls).toEqual([60_000, 60_000])
  })
})

describe('AuthMemoryPasskeyChallengeStore', () => {
  it('take returns the stored challenge once, then rejects because it consumed it', async () => {
    const store = new AuthMemoryPasskeyChallengeStore()
    await store.put('k1', 'c1', 60_000)
    expect(await store.take('k1')).toBe('c1')
    await expect(store.take('k1')).rejects.toMatchObject({ code: 'AUTH_CREDENTIAL_NOT_FOUND' })
  })

  it('take rejects on TTL expiry', async () => {
    const store = new AuthMemoryPasskeyChallengeStore()
    await store.put('k1', 'c1', 5)
    await new Promise((r) => setTimeout(r, 10))
    await expect(store.take('k1')).rejects.toMatchObject({ code: 'AUTH_CREDENTIAL_NOT_FOUND' })
  })

  it('take rejects a key that was never put, and orNull reads every refusal back as null', async () => {
    const store = new AuthMemoryPasskeyChallengeStore()
    await expect(store.take('never-put')).rejects.toMatchObject({ code: 'AUTH_CREDENTIAL_NOT_FOUND' })
    await expect(orNull(store.take('never-put'))).resolves.toBeNull()
  })
})

describe('passkey provider - begin is rate limited', () => {
  /** `allowCredentials` is populated for an address that exists and empty for one that does not, so an
   *  unbounded `begin` lets a caller read account existence off address after address. Every other
   *  credential-presenting provider bounds its entry point; this asserts passkey does too. */
  it('refuses once the per-address bucket is spent', async () => {
    const adapter = new MemoryAdapter<ProfileShape>()
    const identity = await adapter.identities.create(
      identityInput({ profile: { email: 'a@b.com', username: 'a' }, providers: [] }),
    )
    const ctx = { ...makeContext(adapter), limiter: new MemoryLimiter({ max: 2, windowMs: 60_000 }) }
    const provider = passkey<ProfileShape>({
      expectedOrigins: 'https://app.test',
      findIdentityByEmail: async () => ({ id: identity.id }),
      rpID: 'app.test',
      rpName: 'Test App',
      webauthnModule: makeMockWebAuthn(),
    })

    await provider.begin(ctx, { email: 'a@b.com', sessionId: 's1' })
    await provider.begin(ctx, { email: 'a@b.com', sessionId: 's2' })
    await expect(provider.begin(ctx, { email: 'a@b.com', sessionId: 's3' })).rejects.toMatchObject({
      code: 'AUTH_RATE_LIMITED',
    })
  })

  it('keys the bucket on the address, so one caller cannot spend another address budget', async () => {
    const adapter = new MemoryAdapter<ProfileShape>()
    const identity = await adapter.identities.create(
      identityInput({ profile: { email: 'a@b.com', username: 'a' }, providers: [] }),
    )
    const ctx = { ...makeContext(adapter), limiter: new MemoryLimiter({ max: 1, windowMs: 60_000 }) }
    const provider = passkey<ProfileShape>({
      expectedOrigins: 'https://app.test',
      findIdentityByEmail: async () => ({ id: identity.id }),
      rpID: 'app.test',
      rpName: 'Test App',
      webauthnModule: makeMockWebAuthn(),
    })

    await provider.begin(ctx, { email: 'a@b.com', sessionId: 's1' })
    // A different address, and the same spent session id: a shared bucket would refuse this.
    await expect(provider.begin(ctx, { email: 'other@b.com', sessionId: 's1' })).resolves.toBeDefined()
  })
})
