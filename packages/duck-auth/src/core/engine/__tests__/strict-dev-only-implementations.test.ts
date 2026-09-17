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
import { AuthConsoleChannel, AuthNoopChannel, AuthTestChannel } from '~/channels/console'
import { AuthNullCaptchaVerifier, AuthUnconfiguredCaptchaVerifier } from '~/core/captcha'
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

/** Production-clean but for whatever the case under test wires in. */
function makeAuth(over: Partial<Engine.Cfg> = {}) {
  const auth = new AuthEngine({
    baseUrl: 'https://app.example.com',
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
 * The same two notions of production, for the three channels that deliver nothing. Each refuses itself in
 * its constructor on `NODE_ENV`, exactly as `MemoryIdempotency` and `AuthNullCaptchaVerifier` do, and
 * those two carry a brand as well precisely because that check does not fire where `NODE_ENV` is unset.
 */
describe('strict() rejects a channel that delivers nothing', () => {
  /** A real channel is a plain object with a `send`; nothing here goes by constructor name. */
  const realChannel = { id: 'ses', kind: 'email' as const, send: async () => ({ ok: true as const }) }

  it('is the only thing standing: no constructor refused under this NODE_ENV', () => {
    expect(process.env.NODE_ENV).not.toBe('production')
    expect(() => new AuthConsoleChannel()).not.toThrow()
    expect(() => new AuthNoopChannel()).not.toThrow()
    expect(() => new AuthTestChannel()).not.toThrow()
  })

  it.each([
    ['AuthConsoleChannel', () => new AuthConsoleChannel()],
    ['AuthNoopChannel', () => new AuthNoopChannel()],
    ['AuthTestChannel', () => new AuthTestChannel()],
  ])('rejects %s on the email slot, where the reset link goes', (_label, build) => {
    rejects(makeAuth({ channels: { email: build() } }), /the email channel .* delivers nothing/)
  })

  it('reads the bag rather than the email slot, so the sms and webpush slots are covered too', () => {
    rejects(
      makeAuth({ channels: { sms: new AuthNoopChannel({ kind: 'sms' }) } }),
      /the sms channel .* delivers nothing/,
    )
    rejects(
      makeAuth({ channels: { webpush: new AuthNoopChannel({ kind: 'webpush' }) } }),
      /the webpush channel .* delivers nothing/,
    )
  })

  it('names the channel id, so an operator knows which slot to change', () => {
    rejects(makeAuth({ channels: { email: new AuthConsoleChannel({ id: 'dev-log' }) } }), /'dev-log'/)
  })

  it('accepts a real channel, so the check is on the brand and not on having one at all', () => {
    expect(() => makeAuth({ channels: { email: realChannel } }).strict({ env: 'production' })).not.toThrow()
  })

  it('accepts a deployment wiring no channels at all', () => {
    expect(() => makeAuth({ channels: {} }).strict({ env: 'production' })).not.toThrow()
    expect(() => makeAuth().strict({ env: 'production' })).not.toThrow()
  })

  it('leaves a real channel alone while refusing the dev one beside it', () => {
    rejects(
      makeAuth({ channels: { email: realChannel, sms: new AuthTestChannel({ kind: 'sms' }) } }),
      /the sms channel .* delivers nothing/,
    )
  })

  it('stays a no-op outside production, where these channels are the point', () => {
    const auth = makeAuth({ channels: { email: new AuthConsoleChannel() } })
    expect(() => auth.strict({ env: 'development' })).not.toThrow()
    expect(() => auth.strict({ env: 'test' })).not.toThrow()
  })
})
