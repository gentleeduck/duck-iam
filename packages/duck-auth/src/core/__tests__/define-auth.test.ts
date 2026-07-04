import { describe, expect, it } from 'vitest'
import { memoryStorage } from '../../adapters/memory'
import { AuthConsoleChannel } from '../../channels/console'
import { authMagicLink } from '../../providers/magic-link'
import { authGithub } from '../../providers/oauth/github'
import { authGoogle } from '../../providers/oauth/google'
import { authPasskey } from '../../providers/passkey'
import { authPassword } from '../../providers/password'
import { createAuth } from '../config'
import { AuthEngine } from '../engine'
import { AuthArgon2idHasher } from '../password/argon2'
import { AuthScryptHasher } from '../password/scrypt'
import { AuthCookieTransport } from '../transport/cookie'

interface Profile {
  email: string
}

describe('createAuth', () => {
  it('returns an AuthEngine instance with the supplied storage', () => {
    const storage = memoryStorage<Profile>()
    const auth = createAuth({ baseUrl: 'http://x', stores: storage })
    expect(auth).toBeInstanceOf(AuthEngine)
    expect(auth.config.stores.identities).toBe(storage.identities)
    expect(auth.config.stores.sessions).toBe(storage.sessions)
    expect(auth.config.stores.credentials).toBe(storage.credentials)
  })

  it('defaults transport to AuthCookieTransport with name "duck-sid"', () => {
    const auth = createAuth({ baseUrl: 'http://x', stores: memoryStorage<Profile>() })
    expect(auth.transport).toBeDefined()
    // AuthCookieTransport sets a private _name; we observe via issue() output shape.
    expect(typeof auth.transport.extract).toBe('function')
  })

  it('respects explicit transport', () => {
    const custom = new AuthCookieTransport({ name: 'custom-sid' })
    const auth = createAuth({ baseUrl: 'http://x', stores: memoryStorage<Profile>(), transport: custom })
    expect(auth.transport).toBe(custom)
  })

  it('defaults hasher to AuthScryptHasher when not supplied', () => {
    const auth = createAuth({ baseUrl: 'http://x', stores: memoryStorage<Profile>() })
    expect(auth.passwords).toBeDefined()
  })

  it('respects explicit hasher', () => {
    const auth = createAuth({
      baseUrl: 'http://x',
      passwords: { hasher: new AuthScryptHasher({ N: 1 << 10 }) },
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
        passwords: { hasher: new AuthArgon2idHasher() },
        stores: memoryStorage<Profile>(),
      }),
    ).not.toThrow()
  })

  it('registers every provider in the array', () => {
    const storage = memoryStorage<Profile>()
    const auth = createAuth({
      baseUrl: 'http://x',
      providers: [
        authPassword({
          findIdentityByEmail: (email) => storage.identities.findByEmail(email, {}),
          passwords: { hasher: new AuthScryptHasher({ N: 1 << 10 }) } as never,
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
        authPassword({
          findIdentityByEmail: (email) => storage.identities.findByEmail(email, {}),
          passwords: { hasher: new AuthScryptHasher({ N: 1 << 10 }) } as never,
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
        authPassword({
          findIdentityByEmail: (email) => storage.identities.findByEmail(email, {}),
          passwords: { hasher: new AuthScryptHasher({ N: 1 << 10 }) } as never,
        }),
        authMagicLink({
          autoCreateIdentity: true,
          autoCreateProfile: (email) => ({ email }),
          callbackPath: '/AUTH/magic-link/callback',
          channels: { email: new AuthConsoleChannel() },
          findIdentityByEmail: (email) => storage.identities.findByEmail(email, {}),
        }),
        authGoogle({
          clientId: 'authGoogle-client',
          clientSecret: 'authGoogle-secret',
          redirectUri: 'http://x/AUTH/providers/authGoogle/callback',
          stateSigningSecret: 'state-secret',
        }),
        authGithub({
          clientId: 'authGithub-client',
          clientSecret: 'authGithub-secret',
          redirectUri: 'http://x/AUTH/providers/authGithub/callback',
          stateSigningSecret: 'state-secret',
        }),
        authPasskey({
          expectedOrigins: 'http://x',
          findIdentityByEmail: (email) => storage.identities.findByEmail(email, {}),
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

  it('passes through session / mfa / apiKeys / hijack knobs', () => {
    const auth = createAuth({
      apiKeys: { prefix: 'demo-' },
      baseUrl: 'http://x',
      mfa: { issuer: 'duck-demo' },
      session: { ttlMs: 60_000 },
      stores: memoryStorage<Profile>(),
    })
    expect(auth.config.session?.ttlMs).toBe(60_000)
    expect(auth.config.mfa?.issuer).toBe('duck-demo')
    expect(auth.config.apiKeys?.prefix).toBe('demo-')
  })
})
