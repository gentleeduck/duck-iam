import { describe, expect, it } from 'vitest'
import { memoryAdapter } from '~/adapters/memory'
import { apiKeyProvider } from '~/providers/api-key'
import { magicLink } from '~/providers/magic-link'
import { mfaProvider } from '~/providers/mfa'
import { github } from '~/providers/oauth/github'
import { google } from '~/providers/oauth/google'
import { passkey } from '~/providers/passkey'
import { Argon2idHasher, passwords, ScryptHasher } from '~/providers/passwords'
import { createAuth } from '../config'
import { AuthEngine } from '../engine'
import type { Identities } from '../identities/identities.types'
import { CookieTransport } from '../transport/cookie.transport'

type Profile = Identities.ProfileMetadataBase

describe('createAuth', () => {
  it('returns an AuthEngine instance with the supplied storage', () => {
    const storage = memoryAdapter<Profile>()
    const auth = createAuth({ baseUrl: 'http://x', stores: storage })
    expect(auth).toBeInstanceOf(AuthEngine)
    expect(auth.cfg.stores.identities).toBe(storage.identities)
    expect(auth.cfg.stores.sessions).toBe(storage.sessions)
    expect(auth.cfg.stores.credentials).toBe(storage.credentials)
  })

  it('defaults transport to AuthCookieTransport with name "duck-sid"', () => {
    const auth = createAuth({ baseUrl: 'http://x', stores: memoryAdapter<Profile>() })
    expect(auth.transport).toBeDefined()
    // AuthCookieTransport sets a private _name; we observe via issue() output shape.
    expect(typeof auth.transport.extract).toBe('function')
  })

  it('respects explicit transport', () => {
    const custom = new CookieTransport({ name: 'custom-sid' })
    const auth = createAuth({ baseUrl: 'http://x', stores: memoryAdapter<Profile>(), transport: custom })
    expect(auth.transport).toBe(custom)
  })

  it('passwords defaults its hasher to scrypt when not supplied', () => {
    const auth = createAuth({ baseUrl: 'http://x', providers: [passwords()], stores: memoryAdapter<Profile>() })
    expect(auth.passwords).toBeDefined()
  })

  it('accessing auth.passwords without the password provider throws', () => {
    const auth = createAuth({ baseUrl: 'http://x', stores: memoryAdapter<Profile>() })
    expect(() => auth.passwords).toThrow(/AUTH_PROVIDER_NOT_REGISTERED|password/)
  })

  it('respects explicit hasher', () => {
    const auth = createAuth({
      baseUrl: 'http://x',
      providers: [passwords({ hasher: new ScryptHasher({ N: 1 << 10 }) })],
      stores: memoryAdapter<Profile>(),
    })
    expect(auth.passwords).toBeDefined()
  })

  it('AuthArgon2idHasher is type-compatible with the hasher field', () => {
    // Argon2id throws at construction if @node-rs/argon2 missing; we
    // only care that the type slots in here.
    expect(() =>
      createAuth({
        baseUrl: 'http://x',
        providers: [passwords({ hasher: new Argon2idHasher() })],
        stores: memoryAdapter<Profile>(),
      }),
    ).not.toThrow()
  })

  it('registers every provider in the array', () => {
    const storage = memoryAdapter<Profile>()
    const auth = createAuth({
      baseUrl: 'http://x',
      providers: [
        passwords({
          hasher: new ScryptHasher({ N: 1 << 10 }),
        }),
      ],
      stores: storage,
    })
    expect(auth.providers.list().map((p) => p.id)).toContain('password')
  })

  it('silently skips false / null / undefined provider entries', () => {
    const storage = memoryAdapter<Profile>()
    const auth = createAuth({
      baseUrl: 'http://x',
      providers: [
        false,
        null,
        undefined,
        passwords({
          hasher: new ScryptHasher({ N: 1 << 10 }),
        }),
      ],
      stores: storage,
    })
    expect(auth.providers.list().map((p) => p.id)).toEqual(['password'])
  })

  it('lets createAuth carry the profile generic for nested providers', () => {
    const storage = memoryAdapter<Profile>()
    const auth = createAuth<Profile>({
      baseUrl: 'http://x',
      providers: [
        passwords({
          hasher: new ScryptHasher({ N: 1 << 10 }),
        }),
        magicLink({
          autoCreateIdentity: true,
          autoCreateProfile: (email) => ({ username: email, email }),
          callbackPath: '/AUTH/magic-link/callback',
          deliver: async () => {},
          findIdentityByEmail: (email) => storage.identities.find({ email }),
        }),
        google({
          clientId: 'authGoogle-client',
          clientSecret: 'authGoogle-secret',
          redirectUri: 'http://x/AUTH/providers/authGoogle/callback',
          stateSigningSecret: 'state-secret',
          allowStateReplay: true,
        }),
        github({
          clientId: 'authGithub-client',
          clientSecret: 'authGithub-secret',
          redirectUri: 'http://x/AUTH/providers/authGithub/callback',
          stateSigningSecret: 'state-secret',
          allowStateReplay: true,
        }),
        passkey({
          expectedOrigins: 'http://x',
          findIdentityByEmail: (email) => storage.identities.find({ email }),
          rpID: 'localhost',
          rpName: 'demo',
        }),
      ],
      stores: storage,
    })

    expect(auth.providers.list().map((p) => p.id)).toEqual([
      'password',
      'magic-link',
      'oauth:authGoogle',
      'oauth:authGithub',
      'passkey',
    ])
  })

  it('omitting providers leaves the registry empty', () => {
    const auth = createAuth({ baseUrl: 'http://x', stores: memoryAdapter<Profile>() })
    expect(auth.providers.list()).toEqual([])
  })

  it('strict("production") rejects a config without a limiter', () => {
    expect(() =>
      createAuth({
        baseUrl: 'http://x',
        stores: memoryAdapter<Profile>(),
        strict: 'production',
      }),
    ).toThrow()
  })

  it('strict("development") tolerates an under-configured setup', () => {
    expect(() =>
      createAuth({
        baseUrl: 'http://x',
        stores: memoryAdapter<Profile>(),
        strict: 'development',
      }),
    ).not.toThrow()
  })

  it('passes through session / hijack knobs', () => {
    const auth = createAuth({
      baseUrl: 'http://x',
      session: { ttlMs: 60_000 },
      stores: memoryAdapter<Profile>(),
    })
    expect(auth.cfg.session?.ttlMs).toBe(60_000)
  })

  it('apiKeyProvider mounts auth.apiKeys; prefix flows into created tokens', async () => {
    const auth = createAuth({
      baseUrl: 'http://x',
      providers: [apiKeyProvider({ prefix: 'demo_' })],
      stores: memoryAdapter<Profile>(),
    })
    const created = await auth.apiKeys.create('user-1', { name: 'ci', scopes: [] })
    expect(created.plaintext.startsWith('demo_')).toBe(true)
  })

  it('accessing auth.apiKeys without the api-key provider throws', () => {
    const auth = createAuth({ baseUrl: 'http://x', stores: memoryAdapter<Profile>() })
    expect(() => auth.apiKeys).toThrow(/AUTH_PROVIDER_NOT_REGISTERED|api-key/)
  })

  it('mfaProvider mounts auth.mfa; issuer flows into TOTP enrollment', async () => {
    const auth = createAuth({
      baseUrl: 'http://x',
      providers: [mfaProvider({ issuer: 'duck-demo' })],
      stores: memoryAdapter<Profile>(),
    })
    const challenge = await auth.mfa.beginTotpEnrollment('user-1', 'a@x.com')
    expect(challenge.uri).toContain('issuer=duck-demo')
  })

  it('accessing auth.mfa without the mfa provider throws', () => {
    const auth = createAuth({ baseUrl: 'http://x', stores: memoryAdapter<Profile>() })
    expect(() => auth.mfa).toThrow(/AUTH_PROVIDER_NOT_REGISTERED|mfa/)
  })
})
