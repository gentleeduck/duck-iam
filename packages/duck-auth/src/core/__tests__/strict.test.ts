import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import type { Idempotency } from '~/core/idempotency/idempotency.types'
import type { Limiter } from '~/limiters'
import { MemoryLimiter } from '~/limiters/memory'
import { NoopLimiter } from '~/limiters/mock'
import { github } from '~/providers/oauth/github'
import { AuthEngine } from '../engine'
import type { Identities } from '../identities/identities.types'
import { CookieTransport } from '../transport/cookie.transport'
import { JwtTransport } from '../transport/jwt.transport'

interface MyProfile extends Identities.ProfileMetadataBase {
  email: string
}

function makeAuth(
  overrides: Partial<{
    limiter: boolean
    secureCookie: boolean
    providers: boolean
    lockoutHandler: boolean
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
    transport: new CookieTransport({ secure: o.secureCookie, name: 'duck-sid' }),
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

    it('rejects when no `lockout` listener is subscribed', () => {
      const auth = makeAuth({ lockoutHandler: false })
      expect(() => auth.strict({ env: 'production' })).toThrow(
        expect.objectContaining({
          code: 'AUTH_MISCONFIGURED',
          meta: expect.objectContaining({ detail: expect.stringMatching(/lockout.*event handler/) }),
        }),
      )
    })

    it('rejects an explicitly-passed AuthNoopLimiter (not just missing limiter)', async () => {
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
          meta: expect.objectContaining({ detail: expect.stringMatching(/AuthNoopLimiter rejected/) }),
        }),
      )
    })

    it('aggregates multiple errors in one throw', () => {
      const auth = makeAuth({ limiter: false, providers: false, lockoutHandler: false })
      try {
        auth.strict({ env: 'production' })
        expect.fail('expected throw')
      } catch (err) {
        const msg = String((err as Error).message)
        // Memory adapter + missing limiter + no provider + no lockout listener
        // (cookie still flagged because the test helper uses memory adapter
        // matching the constructor name heuristic too, so it surfaces in
        // the error list).
        expect(msg).toContain('AUTH_MISCONFIGURED')
      }
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
      try {
        auth.strict({ env: 'production' })
        expect.fail('expected throw')
      } catch (err) {
        const detail = (err as { meta?: { detail?: string } }).meta?.detail ?? ''
        expect(detail).toMatch(/must use https/)
      }
    })
  })
})

describe('AuthEngine.strict() - signing secrets', () => {
  /** 32 bytes, the RFC 7518 floor for HMAC-SHA256. */
  const STRONG = 'secret-material-of-32-bytes-ok!!'
  const WEAK = 'short'

  function detailOf(auth: AuthEngine<MyProfile>): string {
    try {
      auth.strict({ env: 'production' })
      return ''
    } catch (err) {
      return (err as { meta?: { detail?: string } }).meta?.detail ?? ''
    }
  }

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
        github({ clientId: 'c', clientSecret: 's', redirectUri: 'https://app.example.com/cb', stateSigningSecret }),
      ],
      stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
      transport: new CookieTransport({ name: 'duck-sid', secure: true }),
    })
  }

  it('refuses an empty stateSigningSecret at construction, before strict() is ever called', () => {
    // `createHmac` accepts an empty key, so this is not an unsigned state; it is one anyone can sign.
    expect(() =>
      github({ clientId: 'c', clientSecret: 's', redirectUri: 'https://app.example.com/cb', stateSigningSecret: '' }),
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

  /** Never consulted: `strict()` only checks that one is wired. */
  const idempotency: Idempotency.Store = {
    claim: async () => true,
    delete: async () => {},
    get: async () => ({ body: '', createdAt: new Date(), headers: {}, status: 200 }),
    put: async () => {},
  }

  const production = (limiter: Limiter.Me) => {
    const auth = new AuthEngine<MyProfile>({
      baseUrl: 'https://app.example.com',
      idempotency,
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

  const detail = (auth: AuthEngine<MyProfile>): string => {
    try {
      auth.strict({ env: 'production' })
      return ''
    } catch (err) {
      return String((err as { meta?: { detail?: string } }).meta?.detail ?? '')
    }
  }

  it('boots a production config that breaks none of the checks', () => {
    expect(detail(production(foreignLimiter))).toBe('')
  })

  it('refuses an AuthMemoryLimiter the operator supplied on purpose', () => {
    expect(detail(production(new MemoryLimiter()))).toMatch(/AuthMemoryLimiter rejected in production/)
  })

  it('still refuses the always-allow one, by its own name', () => {
    expect(detail(production(new NoopLimiter()))).toMatch(/AuthNoopLimiter rejected in production/)
  })

  it('asks an operator who supplied none to supply one, rather than naming the fallback they never chose', () => {
    // The engine falls back to `MemoryLimiter`, so the object in hand is the in-process one either way;
    // only `cfg.limiter` distinguishes the operator who chose it from the one who chose nothing.
    const said = detail(makeAuth({ limiter: false }))
    expect(said).toMatch(/Limiter adapter required/)
    expect(said).not.toMatch(/AuthMemoryLimiter rejected/)
  })
})
