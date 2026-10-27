/**
 * A challenge belongs to the ceremony that minted it. Ported from better-auth's `passkey.test.ts`. The two
 * ceremonies are kept apart only by a key prefix - `reg:` against `auth:` - set in functions that never read
 * each other; the mock verifier passes anything, so a shared keyspace signs someone in.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { randomToken, sha256, timingSafeEqual } from '~/core/crypto'
import { InMemoryEvents } from '~/core/events'
import type { Identities } from '~/core/identities'
import { MemoryLimiter } from '~/limiters/memory'
import { identityInput, makeSession } from '~/test/store-inputs'
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
    baseUrl: 'https://app.test',
    crypto: { authRandomToken: randomToken, authSha256: sha256, authTimingSafeEqual: timingSafeEqual },
    events: new InMemoryEvents(),
    limiter: new MemoryLimiter(),
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    tenant: {},
  }
}

/** Verifies everything it is handed, so a refusal below can only come from the challenge lookup. */
function makeMockWebAuthn(): Passkey.SimpleWebAuthnServerModule {
  return {
    generateAuthenticationOptions: vi.fn(async (input) => ({
      allowCredentials: input.allowCredentials,
      challenge: `auth-challenge-${Math.random().toString(36).slice(2)}`,
      rpId: input.rpID,
      userVerification: input.userVerification,
    })),
    generateRegistrationOptions: vi.fn(async (input) => ({
      challenge: `reg-challenge-${Math.random().toString(36).slice(2)}`,
      pubKeyCredParams: [{ alg: -7, type: 'public-key' as const }],
      rp: { id: input.rpID, name: input.rpName },
      user: { id: Buffer.from(input.userID).toString('base64url'), name: input.userName },
    })),
    verifyAuthenticationResponse: vi.fn(async () => ({
      authenticationInfo: { credentialID: 'webauthn-cred-1', newCounter: 1, userVerified: true },
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

describe('a challenge belongs to the ceremony that minted it', () => {
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
      challengeStore,
      expectedOrigins: 'https://app.test',
      findIdentityByEmail: async () => ({ id: identityId }),
      rpID: 'app.test',
      rpName: 'Test App',
      webauthnModule: mockWebauthn,
    }
  })

  it('refuses an authentication that reuses a registration challenge', async () => {
    const provider = passkey<ProfileShape>(opts)
    // Enrolled first: without a credential the authentication refuses at the lookup and proves nothing.
    await beginPasskeyRegistration(opts, {
      session: makeSession({ aal: 2, identityId }),
      credentialStore: adapter.credentials,
      identityId,
      sessionId: 'setup',
      tenant: {},
      userName: 'a@b.com',
    })
    await completePasskeyRegistration(opts, {
      session: makeSession({ aal: 2, identityId }),
      credentialStore: adapter.credentials,
      identityId,
      response: { id: 'webauthn-cred-1' },
      sessionId: 'setup',
      tenant: {},
    })
    await beginPasskeyRegistration(opts, {
      session: makeSession({ aal: 2, identityId }),
      credentialStore: adapter.credentials,
      identityId,
      sessionId: 'shared',
      tenant: {},
      userName: 'a@b.com',
    })
    // The registration's own session id: one keyspace would spend that challenge here.
    await expect(
      provider.complete(makeContext(adapter), { response: { id: 'webauthn-cred-1' }, sessionId: 'shared' }),
    ).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
    expect(mockWebauthn.verifyAuthenticationResponse).not.toHaveBeenCalled()
  })

  it('leaves the registration challenge spendable, so the real ceremony still finishes', async () => {
    await beginPasskeyRegistration(opts, {
      session: makeSession({ aal: 2, identityId }),
      credentialStore: adapter.credentials,
      identityId,
      sessionId: 'shared',
      tenant: {},
      userName: 'a@b.com',
    })
    const provider = passkey<ProfileShape>(opts)
    await expect(
      provider.complete(makeContext(adapter), { response: { id: 'webauthn-cred-1' }, sessionId: 'shared' }),
    ).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
    // A refused attempt must not consume what it could not use, or it cancels an enrollment.
    await expect(
      completePasskeyRegistration(opts, {
        session: makeSession({ aal: 2, identityId }),
        credentialStore: adapter.credentials,
        identityId,
        response: { id: 'webauthn-cred-1' },
        sessionId: 'shared',
        tenant: {},
      }),
    ).resolves.toBeTruthy()
  })

  it('refuses a registration that reuses an authentication challenge', async () => {
    const provider = passkey<ProfileShape>(opts)
    await provider.begin(makeContext(adapter), { email: 'a@b.com', sessionId: 'shared' })
    await expect(
      completePasskeyRegistration(opts, {
        session: makeSession({ aal: 2, identityId }),
        credentialStore: adapter.credentials,
        identityId,
        response: { id: 'webauthn-cred-1' },
        sessionId: 'shared',
        tenant: {},
      }),
    ).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
    expect(mockWebauthn.verifyRegistrationResponse).not.toHaveBeenCalled()
  })

  it('leaves the authentication challenge spendable after a refused registration', async () => {
    const provider = passkey<ProfileShape>(opts)
    // An authentication reaches its challenge only once a credential exists.
    await beginPasskeyRegistration(opts, {
      session: makeSession({ aal: 2, identityId }),
      credentialStore: adapter.credentials,
      identityId,
      sessionId: 'setup',
      tenant: {},
      userName: 'a@b.com',
    })
    await completePasskeyRegistration(opts, {
      session: makeSession({ aal: 2, identityId }),
      credentialStore: adapter.credentials,
      identityId,
      response: { id: 'webauthn-cred-1' },
      sessionId: 'setup',
      tenant: {},
    })
    await provider.begin(makeContext(adapter), { email: 'a@b.com', sessionId: 'shared' })
    await expect(
      completePasskeyRegistration(opts, {
        session: makeSession({ aal: 2, identityId }),
        credentialStore: adapter.credentials,
        identityId,
        response: { id: 'webauthn-cred-1' },
        sessionId: 'shared',
        tenant: {},
      }),
    ).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
    await expect(
      provider.complete(makeContext(adapter), { response: { id: 'webauthn-cred-1' }, sessionId: 'shared' }),
    ).resolves.toBeTruthy()
  })

  it('hands each verifier the challenge its own ceremony minted', async () => {
    const provider = passkey<ProfileShape>(opts)
    const regOptions = await beginPasskeyRegistration(opts, {
      session: makeSession({ aal: 2, identityId }),
      credentialStore: adapter.credentials,
      identityId,
      sessionId: 'reg-side',
      tenant: {},
      userName: 'a@b.com',
    })
    await provider.begin(makeContext(adapter), { email: 'a@b.com', sessionId: 'auth-side' })
    await completePasskeyRegistration(opts, {
      session: makeSession({ aal: 2, identityId }),
      credentialStore: adapter.credentials,
      identityId,
      response: { id: 'webauthn-cred-1' },
      sessionId: 'reg-side',
      tenant: {},
    })
    await provider.complete(makeContext(adapter), {
      response: { id: 'webauthn-cred-1' },
      sessionId: 'auth-side',
    })
    // Both live at once, so a lookup keyed on the session id alone crosses them whatever the call order.
    expect(vi.mocked(mockWebauthn.verifyRegistrationResponse).mock.calls[0]?.[0].expectedChallenge).toBe(
      regOptions.challenge,
    )
    expect(vi.mocked(mockWebauthn.verifyAuthenticationResponse).mock.calls[0]?.[0].expectedChallenge).toMatch(
      /^auth-challenge-/,
    )
  })
})
