/**
 * Two notions of "production" ship in this package: the one an operator declares by calling
 * `strict({ env: 'production' })`, and the one `MemoryIdempotency` and `AuthNullCaptchaVerifier` read out
 * of `NODE_ENV` in their own constructors. Where `NODE_ENV` is unset — which is the default on most
 * runtimes — only the first exists, and the constructors let both dev-only implementations through.
 *
 * `strict()` used to cover only half of the first case: `if (!engine.cfg.idempotency)` catches the store
 * left out, not the same class handed over by name, which is what `example.ts` does and what anyone copying
 * it does. The captcha verifier that passes every challenge was not checked at all.
 */
import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthNullCaptchaVerifier, AuthUnconfiguredCaptchaVerifier } from '~/core/captcha'
import { InMemoryEvents } from '~/core/events'
import type { Events } from '~/core/events/events.types'
import { memoryIdempotency } from '~/core/idempotency'
import type { Idempotency } from '~/core/idempotency/idempotency.types'
import type { Limiter } from '~/limiters'
import { CookieTransport } from '../../transport/cookie.transport'
import { AuthEngine } from '../engine'
import type { Engine } from '../engine.types'

/** Brandless, as a redis limiter is: `MemoryLimiter` carries `__isInProcessLimiter` and `strict()` refuses
 *  it, which would mask the one rejection each case below is about. */
const foreignLimiter: Limiter.Me = {
  consume: async () => ({ ok: true, remaining: 1, resetAt: new Date(Date.now() + 60_000) }),
  reset: async () => {},
}

/** A store that keeps nothing in this process, standing in for redis. `strict()` goes by brand, so what
 *  makes this foreign is the absence of one, exactly as a third-party store is. */
const foreignIdempotency: Idempotency.Store = {
  claim: async () => true,
  delete: async () => {},
  get: async () => ({ body: null, createdAt: new Date(), headers: {}, status: 200 }),
  put: async () => {},
}

/** The memory adapter's facets with the brand removed: this is what a drizzle or redis deploy looks like
 *  to `strict()`, and it keeps the store rejection from crowding out the one under test. */
function foreignStores() {
  const adapter = new MemoryAdapter()
  const strip = <T extends object>(facet: T): T => {
    const copy = { ...facet }
    Reflect.deleteProperty(copy, '__isMemoryStore')
    return copy
  }
  return {
    credentials: strip(adapter.credentials),
    identities: strip(adapter.identities),
    sessions: strip(adapter.sessions),
  }
}

/** A bus carrying no in-process brand, which is what a fleet-safe one looks like to `strict()`. It
 *  keeps `listenerCount`, or the `lockout` check would be skipped rather than satisfied. */
function foreignEvents(): Events.IBus & { listenerCount(event: Events.EventName): number } {
  const bus = new InMemoryEvents()
  return {
    emit: (event, payload) => bus.emit(event, payload),
    listenerCount: (event) => bus.listenerCount(event),
    on: (event, handler) => bus.on(event, handler),
  }
}
/** Production-clean but for whatever the case under test wires in. */
function makeAuth(over: Partial<Engine.Cfg> = {}) {
  const auth = new AuthEngine({
    baseUrl: 'https://app.example.com',
    events: foreignEvents(),
    idempotency: foreignIdempotency,
    limiter: foreignLimiter,
    stores: foreignStores(),
    transport: new CookieTransport({ name: 'duck-sid', secure: true }),
    ...over,
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

const rejects = (auth: AuthEngine, pattern: RegExp) =>
  expect(() => auth.strict({ env: 'production' })).toThrow(
    expect.objectContaining({
      code: 'AUTH_MISCONFIGURED',
      meta: expect.objectContaining({ detail: expect.stringMatching(pattern) }),
    }),
  )

describe('strict() rejects a dev-only implementation NODE_ENV did not catch', () => {
  it('is the only thing standing: neither constructor refused under this NODE_ENV', () => {
    // If this ever fails the suite is testing the constructors instead, and the gate below is vacuous.
    expect(process.env.NODE_ENV).not.toBe('production')
    expect(() => memoryIdempotency()).not.toThrow()
    expect(() => new AuthNullCaptchaVerifier()).not.toThrow()
  })

  it('passes a deployment with nothing dev-only in it', () => {
    expect(() => makeAuth().strict({ env: 'production' })).not.toThrow()
  })

  it('rejects an idempotency store handed over by name, not only one left out', () => {
    rejects(makeAuth({ idempotency: memoryIdempotency() }), /AuthMemoryIdempotency rejected in production/)
  })

  it('still rejects the omitted store with its own sentence', () => {
    const auth = makeAuth()
    Reflect.deleteProperty(auth.cfg, 'idempotency')
    rejects(auth, /Idempotency store required/)
  })

  it('sees through the facet wrapper, which is what the factory returns', () => {
    // `memoryIdempotency()` answers an `IdempotencyImpl`, so the brand has to be republished by the facet:
    // reading the store off it directly would be reaching into private state.
    expect(memoryIdempotency().__isInProcessIdempotency).toBe(true)
  })

  it('rejects the captcha verifier that passes every challenge', () => {
    rejects(makeAuth({ captcha: new AuthNullCaptchaVerifier() }), /AuthNullCaptchaVerifier passes every challenge/)
  })

  it('accepts the unconfigured verifier, which refuses every challenge instead', () => {
    // Fail-closed is not a footgun: it removes no protection, it only turns captcha off loudly.
    expect(() =>
      makeAuth({ captcha: new AuthUnconfiguredCaptchaVerifier() }).strict({ env: 'production' }),
    ).not.toThrow()
  })

  it('accepts a real verifier, so the check is on the brand and not on having one at all', () => {
    const real = {
      async verify() {
        return { success: true }
      },
      id: 'turnstile',
    }
    expect(() => makeAuth({ captcha: real }).strict({ env: 'production' })).not.toThrow()
  })

  it('stays a no-op outside production, where a dev-only implementation is the point', () => {
    const auth = makeAuth({ captcha: new AuthNullCaptchaVerifier(), idempotency: memoryIdempotency() })
    expect(() => auth.strict({ env: 'development' })).not.toThrow()
    expect(() => auth.strict({ env: 'test' })).not.toThrow()
  })
})

/**
 * The successor to the non-delivering-channel gate. Magic-link is the one provider whose whole flow is a
 * message: with no `deliver` it mints a token, stores it, answers `{ ok: true }` and sends nothing, and the
 * `AUTH_MISCONFIGURED` it raises instead only lands once a user has already asked for a link.
 */
describe('strict() rejects magic-link wired with no deliver', () => {
  const magic = {
    async begin() {
      return []
    },
    async complete() {
      return []
    },
    id: 'magic-link',
    kind: 'magic-link',
  } as const

  it('refuses the provider when the config carries no deliver', () => {
    const auth = makeAuth()
    auth.providers.register(magic)
    rejects(auth, /magic-link provider is registered with no `deliver`/)
  })

  it('accepts it once a deliver is wired, so the gate is on the pair and not on the provider', () => {
    const auth = makeAuth({ deliver: async () => {} })
    auth.providers.register(magic)
    expect(() => auth.strict({ env: 'production' })).not.toThrow()
  })

  it('leaves a deployment with no magic-link alone, deliver or not', () => {
    expect(() => makeAuth().strict({ env: 'production' })).not.toThrow()
  })
})
