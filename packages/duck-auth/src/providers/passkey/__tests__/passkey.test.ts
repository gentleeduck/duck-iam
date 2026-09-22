import { createHash } from 'node:crypto'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { orNull } from '~/core/answer'
import { randomToken, sha256, timingSafeEqual } from '~/core/crypto'
import { AuthError } from '~/core/errors'
import { InMemoryEvents } from '~/core/events'
import { Identities } from '~/core/identities'
import { MemoryLimiter } from '~/limiters/memory'
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
    expect((list[0]!.metadata as { publicKey: string }).publicKey).toBeTruthy()
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

    const call = (mockWebauthn.generateAuthenticationOptions as ReturnType<typeof vi.fn>).mock.calls[0]![0] as {
      allowCredentials?: unknown[]
    }
    expect(call.allowCredentials).toEqual([])
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
        response: { id: 'webauthn-cred-1', response: { userHandle: bogusHandle } } as never,
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
        response: { id: 'webauthn-cred-1', response: { userHandle: 12345 } } as never,
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
        response: { id: 'webauthn-cred-1', response: { userHandle: handle } } as never,
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
      await expect(provider.begin(makeContext(adapter), { sessionId: 42 as unknown as string })).rejects.toMatchObject({
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
          response: { id: 'webauthn-cred-1' } as never,
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
