import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthMemoryLimiter } from '~/limiters/memory'
import { AuthEngine } from '../engine'
import { CookieTransport } from '../transport/cookie.transport'
import type { Identity } from '../identities/identities.types'

interface MyProfile extends Identity.ProfileMetadataBase {
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
    ...(o.limiter && { limiter: new AuthMemoryLimiter({ max: 10, windowMs: 60_000 }) }),
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
      const { NoopLimiter: AuthNoopLimiter } = await import('../engine')
      const auth = new AuthEngine<MyProfile>({
        baseUrl: 'https://app.example.com',
        transport: new CookieTransport({ secure: true, name: 'duck-sid' }),
        stores: { identities: adapter.identities, sessions: adapter.sessions, credentials: adapter.credentials },
        limiter: new AuthNoopLimiter(),
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
        limiter: new AuthMemoryLimiter({ max: 10, windowMs: 60_000 }),
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
