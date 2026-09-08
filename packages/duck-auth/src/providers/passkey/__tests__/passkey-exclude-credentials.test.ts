import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { toCredentialUpsert } from '~/core/credentials/credentials'
import type { Identities } from '~/core/identities'
import { identityInput } from '~/test/store-inputs'
import { AuthMemoryPasskeyChallengeStore, beginPasskeyRegistration } from '../index'
import type { Passkey } from '../passkey.types'

interface ProfileShape extends Identities.ProfileMetadataBase {}

/** Only `generateRegistrationOptions` matters here; it records what it was handed. */
function makeMockWebAuthn() {
  return {
    generateAuthenticationOptions: vi.fn(),
    generateRegistrationOptions: vi.fn(async (input) => ({
      challenge: 'reg-challenge',
      pubKeyCredParams: [{ alg: -7, type: 'public-key' as const }],
      rp: { id: input.rpID, name: input.rpName },
      user: { id: 'u', name: input.userName },
    })),
    verifyAuthenticationResponse: vi.fn(),
    verifyRegistrationResponse: vi.fn(),
  } as unknown as Passkey.SimpleWebAuthnServerModule
}

/**
 * `excludeCredentials` is how a WebAuthn ceremony says "this account already has
 * a key on this authenticator, do not mint another". The field was declared on
 * `RegistrationOptionsInput` from the start and never populated, so every
 * re-registration silently succeeded and left the user with indistinguishable
 * duplicate passkeys.
 */
describe('beginPasskeyRegistration excludes the keys the identity already holds', () => {
  let adapter: MemoryAdapter<ProfileShape>
  let identityId: string
  let opts: Passkey.Options
  let mockWebauthn: Passkey.SimpleWebAuthnServerModule

  beforeEach(async () => {
    adapter = new MemoryAdapter<ProfileShape>()
    const identity = await adapter.identities.create(
      identityInput({ profile: { email: 'a@b.com', username: 'a' }, providers: [] }),
    )
    identityId = identity.id
    mockWebauthn = makeMockWebAuthn()
    opts = {
      challengeStore: new AuthMemoryPasskeyChallengeStore(),
      expectedOrigins: 'https://app.test',
      findIdentityByEmail: async () => ({ id: identityId }),
      rpID: 'app.test',
      rpName: 'Test App',
      webauthnModule: mockWebauthn,
    }
  })

  async function begin() {
    await beginPasskeyRegistration(opts, {
      credentialStore: adapter.credentials,
      identityId,
      sessionId: 's1',
      tenant: {},
      userName: 'a@b.com',
    })
    const calls = vi.mocked(mockWebauthn.generateRegistrationOptions).mock.calls
    return calls.at(-1)?.[0]?.excludeCredentials
  }

  async function addPasskey(id: string, metadata: Record<string, unknown>, revokedAt?: Date) {
    const row = await adapter.credentials.upsert(
      toCredentialUpsert({ identityId, kind: 'passkey', metadata, secret: id }),
      {},
    )
    if (revokedAt) await adapter.credentials.revoke(row.id, {})
    return row
  }

  it('sends an empty list for a first-time registration', async () => {
    expect(await begin()).toEqual([])
  })

  it('names an existing key by its credential id and transports', async () => {
    await addPasskey('cred-1', { counter: 0, publicKey: 'pk', transports: ['internal', 'hybrid'] })
    expect(await begin()).toEqual([{ id: 'cred-1', transports: ['internal', 'hybrid'], type: 'public-key' }])
  })

  it('omits transports rather than guessing when the authenticator reported none', async () => {
    await addPasskey('cred-1', { counter: 0, publicKey: 'pk', transports: [] })
    expect(await begin()).toEqual([{ id: 'cred-1', type: 'public-key' }])
  })

  it('names every live key, not just the newest', async () => {
    await addPasskey('cred-1', { counter: 0, publicKey: 'pk' })
    await addPasskey('cred-2', { counter: 0, publicKey: 'pk' })
    expect((await begin())?.map((c) => c.id).sort()).toEqual(['cred-1', 'cred-2'])
  })

  it('leaves a revoked key out, so re-enrolling that authenticator still works', async () => {
    await addPasskey('cred-live', { counter: 0, publicKey: 'pk' })
    await addPasskey('cred-gone', { counter: 0, publicKey: 'pk' }, new Date())
    expect((await begin())?.map((c) => c.id)).toEqual(['cred-live'])
  })

  it('ignores credentials of other kinds', async () => {
    await adapter.credentials.upsert(
      toCredentialUpsert({ identityId, kind: 'password', metadata: {}, secret: 'hash' }),
      {},
    )
    expect(await begin()).toEqual([])
  })
})
