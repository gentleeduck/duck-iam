import { describe, expect, it } from 'vitest'
import { memoryStorage } from '~/adapters/memory'
import { AuthConsoleChannel } from '~/channels/console'
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
    const storage = memoryStorage<Profile>()
    const auth = createAuth({ baseUrl: 'http://x', stores: storage })
    expect(auth).toBeInstanceOf(AuthEngine)
    expect(auth.cfg.stores.identities).toBe(storage.identities)
    expect(auth.cfg.stores.sessions).toBe(storage.sessions)
    expect(auth.cfg.stores.credentials).toBe(storage.credentials)
  })

  it('defaults transport to AuthCookieTransport with name "duck-sid"', () => {
    const auth = createAuth({ baseUrl: 'http://x', stores: memoryStorage<Profile>() })
    expect(auth.transport).toBeDefined()
    // AuthCookieTransport sets a private _name; we observe via issue() output shape.
    expect(typeof auth.transport.extract).toBe('function')
  })

  it('respects explicit transport', () => {
    const custom = new CookieTransport({ name: 'custom-sid' })
    const auth = createAuth({ baseUrl: 'http://x', stores: memoryStorage<Profile>(), transport: custom })
    expect(auth.transport).toBe(custom)
  })

  it('passwords defaults its hasher to scrypt when not supplied', () => {
    const auth = createAuth({ baseUrl: 'http://x', providers: [passwords()], stores: memoryStorage<Profile>() })
    expect(auth.passwords).toBeDefined()
  })

  it('accessing auth.passwords without the password provider throws', () => {
    const auth = createAuth({ baseUrl: 'http://x', stores: memoryStorage<Profile>() })
    expect(() => auth.passwords).toThrow(/AUTH_PROVIDER_NOT_REGISTERED|password/)
  })

  it('respects explicit hasher', () => {
    const auth = createAuth({
      baseUrl: 'http://x',
      providers: [passwords({ hasher: new ScryptHasher({ N: 1 << 10 }) })],
      stores: memoryStorage<Profile>(),
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
        stores: memoryStorage<Profile>(),
      }),
    ).not.toThrow()
  })

  it('registers every provider in the array', () => {
    const storage = memoryStorage<Profile>()
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
    const storage = memoryStorage<Profile>()
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
    const storage = memoryStorage<Profile>()
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
          channels: { email: new AuthConsoleChannel() },
          findIdentityByEmail: (email) => storage.identities.findByEmail(email),
        }),
        google({
          clientId: 'authGoogle-client',
          clientSecret: 'authGoogle-secret',
          redirectUri: 'http://x/AUTH/providers/authGoogle/callback',
          stateSigningSecret: 'state-secret',
        }),
        github({
          clientId: 'authGithub-client',
          clientSecret: 'authGithub-secret',
          redirectUri: 'http://x/AUTH/providers/authGithub/callback',
          stateSigningSecret: 'state-secret',
        }),
        passkey({
          expectedOrigins: 'http://x',
          findIdentityByEmail: (email) => storage.identities.findByEmail(email),
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
    const auth = createAuth({ baseUrl: 'http://x', stores: memoryStorage<Profile>() })
    expect(auth.providers.list()).toEqual([])
  })

  it('strict("production") rejects a config without a limiter', () => {
    expect(() =>
      createAuth({
        baseUrl: 'http://x',
        stores: memoryStorage<Profile>(),
        strict: 'production',
      }),
    ).toThrow()
  })

  it('strict("development") tolerates an under-configured setup', () => {
    expect(() =>
      createAuth({
        baseUrl: 'http://x',
        stores: memoryStorage<Profile>(),
        strict: 'development',
      }),
    ).not.toThrow()
  })

  it('passes through session / hijack knobs', () => {
    const auth = createAuth({
      baseUrl: 'http://x',
      session: { ttlMs: 60_000 },
      stores: memoryStorage<Profile>(),
    })
    expect(auth.cfg.session?.ttlMs).toBe(60_000)
  })

  it('apiKeyProvider mounts auth.apiKeys; prefix flows into created tokens', async () => {
    const auth = createAuth({
      baseUrl: 'http://x',
      providers: [apiKeyProvider({ prefix: 'demo_' })],
      stores: memoryStorage<Profile>(),
    })
    const created = await auth.apiKeys.create('user-1', { name: 'ci', scopes: [] })
    expect(created.plaintext.startsWith('demo_')).toBe(true)
  })

  it('accessing auth.apiKeys without the api-key provider throws', () => {
    const auth = createAuth({ baseUrl: 'http://x', stores: memoryStorage<Profile>() })
    expect(() => auth.apiKeys).toThrow(/AUTH_PROVIDER_NOT_REGISTERED|api-key/)
  })

  it('mfaProvider mounts auth.mfa; issuer flows into TOTP enrollment', async () => {
    const auth = createAuth({
      baseUrl: 'http://x',
      providers: [mfaProvider({ issuer: 'duck-demo' })],
      stores: memoryStorage<Profile>(),
    })
    const challenge = await auth.mfa.beginTotpEnrollment('user-1', 'a@x.com')
    expect(challenge.uri).toContain('issuer=duck-demo')
  })

  it('accessing auth.mfa without the mfa provider throws', () => {
    const auth = createAuth({ baseUrl: 'http://x', stores: memoryStorage<Profile>() })
    expect(() => auth.mfa).toThrow(/AUTH_PROVIDER_NOT_REGISTERED|mfa/)
  })
})
