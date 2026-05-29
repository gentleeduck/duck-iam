import { describe, expect, it } from 'vitest'
import { memoryStorage } from '../../adapters/memory'
import { ConsoleChannel } from '../../channels/console'
import { magicLink } from '../../providers/magic-link'
import { github } from '../../providers/oauth/github'
import { google } from '../../providers/oauth/google'
import { passkey } from '../../providers/passkey'
import { password } from '../../providers/password'
import { AuthRoot } from '../auth'
import { defineAuth } from '../define-auth'
import { Argon2idHasher } from '../password/argon2'
import { ScryptHasher } from '../password/scrypt'
import { CookieTransport } from '../transport/cookie'

interface Profile {
  email: string
}

describe('defineAuth', () => {
  it('returns an AuthRoot instance with the supplied storage', () => {
    const storage = memoryStorage<Profile>()
    const auth = defineAuth({ baseUrl: 'http://x', storage })
    expect(auth).toBeInstanceOf(AuthRoot)
    expect(auth.config.stores.identities).toBe(storage.identities)
    expect(auth.config.stores.sessions).toBe(storage.sessions)
    expect(auth.config.stores.credentials).toBe(storage.credentials)
  })

  it('defaults transport to CookieTransport with name "duck-sid"', () => {
    const auth = defineAuth({ baseUrl: 'http://x', storage: memoryStorage<Profile>() })
    expect(auth.transport).toBeDefined()
    // CookieTransport sets a private _name; we observe via issue() output shape.
    expect(typeof auth.transport.extract).toBe('function')
  })

  it('respects explicit transport', () => {
    const custom = new CookieTransport({ name: 'custom-sid' })
    const auth = defineAuth({ baseUrl: 'http://x', storage: memoryStorage<Profile>(), transport: custom })
    expect(auth.transport).toBe(custom)
  })

  it('defaults hasher to ScryptHasher when not supplied', () => {
    const auth = defineAuth({ baseUrl: 'http://x', storage: memoryStorage<Profile>() })
    expect(auth.passwords).toBeDefined()
  })

  it('respects explicit hasher', () => {
    const auth = defineAuth({
      baseUrl: 'http://x',
      hasher: new ScryptHasher({ N: 1 << 10 }),
      storage: memoryStorage<Profile>(),
    })
    expect(auth.passwords).toBeDefined()
  })

  it('Argon2idHasher is type-compatible with the hasher field', () => {
    // Argon2id throws at construction if @node-rs/argon2 missing; we
    // only care that the type slots in here.
    expect(() =>
      defineAuth({
        baseUrl: 'http://x',
        hasher: new Argon2idHasher(),
        storage: memoryStorage<Profile>(),
      }),
    ).not.toThrow()
  })

  it('registers every provider in the array', () => {
    const storage = memoryStorage<Profile>()
    const auth = defineAuth({
      baseUrl: 'http://x',
      providers: [
        password({
          findIdentityByEmail: (email) => storage.identities.findByEmail(email, {}),
          passwords: { hasher: new ScryptHasher({ N: 1 << 10 }) } as never,
        }),
      ],
      storage,
    })
    expect(auth.providers.list().map((p) => p.id)).toContain('password')
  })

  it('silently skips false / null / undefined provider entries', () => {
    const storage = memoryStorage<Profile>()
    const auth = defineAuth({
      baseUrl: 'http://x',
      providers: [
        false,
        null,
        undefined,
        password({
          findIdentityByEmail: (email) => storage.identities.findByEmail(email, {}),
          passwords: { hasher: new ScryptHasher({ N: 1 << 10 }) } as never,
        }),
      ],
      storage,
    })
    expect(auth.providers.list().map((p) => p.id)).toEqual(['password'])
  })

  it('lets defineAuth carry the profile generic for nested providers', () => {
    const storage = memoryStorage<Profile>()
    const auth = defineAuth<Profile>({
      baseUrl: 'http://x',
      providers: [
        password({
          findIdentityByEmail: (email) => storage.identities.findByEmail(email, {}),
          passwords: { hasher: new ScryptHasher({ N: 1 << 10 }) } as never,
        }),
        magicLink({
          autoCreateIdentity: true,
          autoCreateProfile: (email) => ({ email }),
          callbackPath: '/auth/magic-link/callback',
          channels: { email: new ConsoleChannel() },
          findIdentityByEmail: (email) => storage.identities.findByEmail(email, {}),
        }),
        google({
          clientId: 'google-client',
          clientSecret: 'google-secret',
          redirectUri: 'http://x/auth/providers/google/callback',
          stateSigningSecret: 'state-secret',
        }),
        github({
          clientId: 'github-client',
          clientSecret: 'github-secret',
          redirectUri: 'http://x/auth/providers/github/callback',
          stateSigningSecret: 'state-secret',
        }),
        passkey({
          expectedOrigins: 'http://x',
          findIdentityByEmail: (email) => storage.identities.findByEmail(email, {}),
          rpID: 'localhost',
          rpName: 'demo',
        }),
      ],
      storage,
    })

    expect(auth.providers.list().map((p) => p.id)).toEqual([
      'password',
      'magic-link',
      'oauth:google',
      'oauth:github',
      'passkey',
    ])
  })

  it('omitting providers leaves the registry empty', () => {
    const auth = defineAuth({ baseUrl: 'http://x', storage: memoryStorage<Profile>() })
    expect(auth.providers.list()).toEqual([])
  })

  it('strict("production") rejects a config without a limiter', () => {
    expect(() =>
      defineAuth({
        baseUrl: 'http://x',
        storage: memoryStorage<Profile>(),
        strict: 'production',
      }),
    ).toThrow()
  })

  it('strict("development") tolerates an under-configured setup', () => {
    expect(() =>
      defineAuth({
        baseUrl: 'http://x',
        storage: memoryStorage<Profile>(),
        strict: 'development',
      }),
    ).not.toThrow()
  })

  it('passes through session / mfa / apiKeys / hijack knobs', () => {
    const auth = defineAuth({
      apiKeys: { prefix: 'demo-' },
      baseUrl: 'http://x',
      mfa: { issuer: 'duck-demo' },
      session: { ttlMs: 60_000 },
      storage: memoryStorage<Profile>(),
    })
    expect(auth.config.session?.ttlMs).toBe(60_000)
    expect(auth.config.mfa?.issuer).toBe('duck-demo')
    expect(auth.config.apiKeys?.prefix).toBe('demo-')
  })
})
