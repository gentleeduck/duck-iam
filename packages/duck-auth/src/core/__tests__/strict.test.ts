import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { InMemoryEvents } from '~/core/events'
import type { Events } from '~/core/events/events.types'
import { memoryDPoPNonceStore } from '~/core/transport/dpop-nonce.memory'
import type { Transport } from '~/core/transport/transport.types'
import type { Limiter } from '~/limiters'
import { MemoryLimiter } from '~/limiters/memory'
import { NoopLimiter } from '~/limiters/mock'
import { apiKeyProvider } from '~/providers/api-key'
import { github } from '~/providers/oauth/github'
import { AuthEngine } from '../engine'
import type { Engine } from '../engine/engine.types'
import { AuthError } from '../errors'
import type { Identities } from '../identities/identities.types'
import { BearerTransport } from '../transport/bearer.transport'
import { CompositeTransport } from '../transport/composite.transport'
import { CookieTransport } from '../transport/cookie.transport'
import { JwtTransport } from '../transport/jwt.transport'

interface MyProfile extends Identities.ProfileMetadataBase {
  email: string
}

/** A bus carrying no in-process brand, which is what a fleet-safe one looks like to `strict()`. It
 *  keeps `listenerCount`, or the `lockout` check would be skipped rather than satisfied. */
function foreignEvents(): Events.IBus {
  const bus = new InMemoryEvents()
  return {
    emit: (event, payload) => bus.emit(event, payload),
    listenerCount: (event) => bus.listenerCount(event),
    on: (event, handler) => bus.on(event, handler),
  }
}

/** What `strict()` refused in production, or `''` when it booted. */
function detailOf(auth: AuthEngine<MyProfile>): string {
  try {
    auth.strict({ env: 'production' })
    return ''
  } catch (err) {
    return err instanceof AuthError ? String(err.meta.detail ?? '') : String(err)
  }
}

function makeAuth(
  overrides: Partial<{
    limiter: boolean
    secureCookie: boolean
    providers: boolean
    lockoutHandler: boolean
    transport: Transport.ITransport
  }> = {},
) {
  const adapter = new MemoryAdapter<MyProfile>()
  const o = {
    limiter: true,
    secureCookie: true,
    providers: true,
    lockoutHandler: true,
    ...overrides,
  }
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app.example.com',
    events: foreignEvents(),
    transport: o.transport ?? new CookieTransport({ secure: o.secureCookie, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    ...(o.limiter && { limiter: new MemoryLimiter({ max: 10, windowMs: 60_000 }) }),
  })
  if (o.providers) {
    auth.providers.register({
      id: 'fake',
      kind: 'password',
      async begin() {
        return []
      },
      async complete() {
        return []
      },
    })
  }
  if (o.lockoutHandler) {
    auth.events.on('lockout', () => {})
  }
  return auth
}

describe('AuthEngine.strict()', () => {
  it('returns silently in development/test mode regardless of config', () => {
    const auth = makeAuth({ limiter: false, providers: false, lockoutHandler: false })
    expect(() => auth.strict({ env: 'development' })).not.toThrow()
    expect(() => auth.strict({ env: 'test' })).not.toThrow()
  })

  describe('production rejections', () => {
    it('rejects missing Limiter', () => {
      const auth = makeAuth({ limiter: false })
      expect(() => auth.strict({ env: 'production' })).toThrow(
        expect.objectContaining({
          code: 'AUTH_MISCONFIGURED',
          meta: expect.objectContaining({ detail: expect.stringMatching(/Limiter adapter required/) }),
        }),
      )
    })

    it('rejects memory adapter', () => {
      const auth = makeAuth()
      expect(() => auth.strict({ env: 'production' })).toThrow(
        expect.objectContaining({
          code: 'AUTH_MISCONFIGURED',
          meta: expect.objectContaining({ detail: expect.stringMatching(/Memory adapter .*rejected/) }),
        }),
      )
    })

    it('rejects insecure cookies', () => {
      const auth = makeAuth({ secureCookie: false })
      expect(() => auth.strict({ env: 'production' })).toThrow(
        expect.objectContaining({
          code: 'AUTH_MISCONFIGURED',
          meta: expect.objectContaining({ detail: expect.stringMatching(/secure=false/) }),
        }),
      )
    })

    it('rejects when no provider is registered', () => {
      const auth = makeAuth({ providers: false })
      expect(() => auth.strict({ env: 'production' })).toThrow(
        expect.objectContaining({
          code: 'AUTH_MISCONFIGURED',
          meta: expect.objectContaining({ detail: expect.stringMatching(/no provider registered/) }),
        }),
      )
    })

    it('counts what registered, not the entries left out or answering nothing', () => {
      const adapter = new MemoryAdapter<MyProfile>()
      const signIn = {
        async begin() {
          return []
        },
        async complete() {
          return []
        },
        id: 'fake',
        kind: 'password',
      }
      const build = (providers: NonNullable<Engine.Cfg<MyProfile>['providers']>) =>
        new AuthEngine<MyProfile>({
          baseUrl: 'https://app.example.com',
          providers,
          stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
          transport: new CookieTransport({ name: 'duck-sid', secure: true }),
        })
      expect(detailOf(build([false, null, '', () => null]))).toMatch(/no provider registered/)
      expect(detailOf(build([false, signIn]))).not.toMatch(/no provider registered/)
      // An attach-only facet counts: an m2m-only deployment holds just the api-key facet.
      expect(detailOf(build([apiKeyProvider()]))).not.toMatch(/no provider registered/)
    })

    it('rejects when no `lockout` listener is subscribed', () => {
      const auth = makeAuth({ lockoutHandler: false })
      expect(() => auth.strict({ env: 'production' })).toThrow(
        expect.objectContaining({
          code: 'AUTH_MISCONFIGURED',
          meta: expect.objectContaining({ detail: expect.stringMatching(/lockout.*event handler/) }),
        }),
      )
    })

    it('rejects an explicitly-passed NoopLimiter (not just missing limiter)', async () => {
      const adapter = new MemoryAdapter<MyProfile>()
      const auth = new AuthEngine<MyProfile>({
        baseUrl: 'https://app.example.com',
        transport: new CookieTransport({ secure: true, name: 'duck-sid' }),
        stores: { identities: adapter.identities, sessions: adapter.sessions, credentials: adapter.credentials },
        limiter: new NoopLimiter(),
        providers: [
          {
            id: 'password',
            kind: 'password',
            async begin() {
              return []
            },
            async complete() {
              return []
            },
          },
        ],
      })
      auth.events.on('lockout', () => {})
      expect(() => auth.strict({ env: 'production' })).toThrow(
        expect.objectContaining({
          code: 'AUTH_MISCONFIGURED',
          meta: expect.objectContaining({ detail: expect.stringMatching(/\bNoopLimiter rejected/) }),
        }),
      )
    })

    it('aggregates multiple errors in one throw', () => {
      const detail = detailOf(makeAuth({ limiter: false, providers: false, lockoutHandler: false }))
      expect(detail).toMatch(/Limiter adapter required/)
      expect(detail).toMatch(/no provider registered/)
      expect(detail).toMatch(/lockout.*event handler/)
    })

    it('refuses http:// baseUrl in production', () => {
      const adapter = new MemoryAdapter<MyProfile>()
      const auth = new AuthEngine<MyProfile>({
        baseUrl: 'http://app.example.com',
        transport: new CookieTransport({ secure: true, name: 'duck-sid' }),
        stores: {
          identities: adapter.identities,
          sessions: adapter.sessions,
          credentials: adapter.credentials,
        },
        limiter: new MemoryLimiter({ max: 10, windowMs: 60_000 }),
      })
      auth.providers.register({
        id: 'fake',
        kind: 'password',
        async begin() {
          return []
        },
        async complete() {
          return []
        },
      })
      auth.events.on('lockout', () => {})
      expect(detailOf(auth)).toMatch(/must use https/)
    })
  })
})

describe('AuthEngine.strict() - signing secrets', () => {
  /** 32 bytes, the RFC 7518 floor for HMAC-SHA256. */
  const STRONG = 'secret-material-of-32-bytes-ok!!'
  const WEAK = 'short'

  function authWithJwtKey(key: string) {
    const adapter = new MemoryAdapter<MyProfile>()
    return new AuthEngine<MyProfile>({
      baseUrl: 'https://app.example.com',
      limiter: new MemoryLimiter({ max: 10, windowMs: 60_000 }),
      stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
      transport: new JwtTransport({
        issuer: 'https://app.example.com',
        signKey: { alg: 'HS256', key, kid: 'k1' },
        verifyKeys: [{ alg: 'HS256', key, kid: 'k1' }],
      }),
    })
  }

  function authWithStateSecret(stateSigningSecret: string) {
    const adapter = new MemoryAdapter<MyProfile>()
    return new AuthEngine<MyProfile>({
      baseUrl: 'https://app.example.com',
      limiter: new MemoryLimiter({ max: 10, windowMs: 60_000 }),
      providers: [
        github({
          clientId: 'c',
          clientSecret: 's',
          redirectUri: 'https://app.example.com/cb',
          stateSigningSecret,
          nonceStore: memoryDPoPNonceStore(),
        }),
      ],
      stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
      transport: new CookieTransport({ name: 'duck-sid', secure: true }),
    })
  }

  it('refuses an empty stateSigningSecret at construction, before strict() is ever called', () => {
    // `createHmac` accepts an empty key, so this is not an unsigned state; it is one anyone can sign.
    expect(() =>
      github({
        clientId: 'c',
        clientSecret: 's',
        redirectUri: 'https://app.example.com/cb',
        stateSigningSecret: '',
        nonceStore: memoryDPoPNonceStore(),
      }),
    ).toThrowError(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
  })

  it('rejects an HS256 signing key under 32 bytes', () => {
    expect(detailOf(authWithJwtKey(WEAK))).toMatch(/signing key is under 32 bytes/)
  })

  it('accepts a 32-byte HS256 signing key', () => {
    expect(detailOf(authWithJwtKey(STRONG))).not.toMatch(/signing key is under 32 bytes/)
  })

  it('rejects an oauth stateSigningSecret under 32 bytes', () => {
    expect(detailOf(authWithStateSecret(WEAK))).toMatch(/stateSigningSecret under 32 bytes/)
  })

  it('accepts a 32-byte stateSigningSecret', () => {
    expect(detailOf(authWithStateSecret(STRONG))).not.toMatch(/stateSigningSecret under 32 bytes/)
  })

  it('says nothing about key length outside production, matching every other check here', () => {
    expect(() => authWithJwtKey(WEAK).strict({ env: 'development' })).not.toThrow()
  })
})

/**
 * `strict()` rejects the in-process stores by brand and took the in-process limiter, which the engine also
 * falls back to. The gate's own message calls a limiter "brute-force protection"; a bucket held in one
 * process is that only for a deployment of one node that never restarts.
 *
 * Every other case in this file asserts a rejection by substring, which passes just as well against a gate
 * that refuses everything — so the control that a good production config boots is here too.
 */
describe('AuthEngine.strict() and the in-process limiter', () => {
  /** A limiter of the host's own: no brand to read, which is the case the gate must not refuse. */
  const foreignLimiter = {
    async consume() {
      return { ok: true, remaining: 9, resetAt: new Date(Date.now() + 60_000) }
    },
    async reset() {},
  }

  /** Stores of the host's own, for the same reason: unbranded, so nothing here is rejected by accident. */
  const foreignStores = () => {
    const a = new MemoryAdapter<MyProfile>()
    return {
      credentials: { ...a.credentials, __isMemoryStore: false },
      identities: { ...a.identities, __isMemoryStore: false },
      sessions: { ...a.sessions, __isMemoryStore: false },
    }
  }

  const production = (limiter: Limiter.Me) => {
    const auth = new AuthEngine<MyProfile>({
      baseUrl: 'https://app.example.com',
      events: foreignEvents(),
      limiter,
      stores: foreignStores(),
      transport: new CookieTransport({ name: 'duck-sid', secure: true }),
    })
    auth.providers.register({
      async begin() {
        return []
      },
      async complete() {
        return []
      },
      id: 'fake',
      kind: 'password',
    })
    auth.events.on('lockout', () => {})
    return auth
  }

  it('boots a production config that breaks none of the checks', () => {
    expect(detailOf(production(foreignLimiter))).toBe('')
  })

  it('refuses an AuthMemoryLimiter the operator supplied on purpose', () => {
    expect(detailOf(production(new MemoryLimiter()))).toMatch(/AuthMemoryLimiter rejected in production/)
  })

  it('still refuses the always-allow one, by its own name', () => {
    expect(detailOf(production(new NoopLimiter()))).toMatch(/\bNoopLimiter rejected in production/)
  })

  it('asks an operator who supplied none to supply one, rather than naming the fallback they never chose', () => {
    // The engine falls back to `MemoryLimiter`, so the object in hand is the in-process one either way;
    // only `cfg.limiter` distinguishes the operator who chose it from the one who chose nothing.
    const said = detailOf(makeAuth({ limiter: false }))
    expect(said).toMatch(/Limiter adapter required/)
    expect(said).not.toMatch(/AuthMemoryLimiter rejected/)
  })
})

describe('AuthEngine.strict() inside a CompositeTransport', () => {
  const cookie = (secure: boolean) => new CookieTransport({ name: 'duck-sid', secure })
  const jwt = (key: string) =>
    new JwtTransport({
      issuer: 'https://app.example.com',
      signKey: { alg: 'HS256', key, kid: 'k1' },
      verifyKeys: [{ alg: 'HS256', key, kid: 'k1' }],
    })
  const composite = (...parts: Transport.ITransport[]) =>
    detailOf(makeAuth({ transport: new CompositeTransport(parts) }))

  it('checks each part as if it were configured alone', () => {
    expect(composite(cookie(false), new BearerTransport())).toMatch(/secure=false/)
    expect(composite(cookie(true), jwt('short'))).toMatch(/signing key is under 32 bytes/)
  })

  it('checks the parts of a composite nested in another', () => {
    expect(composite(new CompositeTransport([cookie(false)]), new BearerTransport())).toMatch(/secure=false/)
  })

  it('says nothing of parts that would each pass alone', () => {
    const said = composite(cookie(true), jwt('secret-material-of-32-bytes-ok!!'), new BearerTransport())
    expect(said).not.toMatch(/secure=false/)
    expect(said).not.toMatch(/signing key/)
  })
})
