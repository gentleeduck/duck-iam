/**
 * Two notions of "production" ship in this package: the one an operator declares by calling
 * `strict({ env: 'production' })`, and the one `AuthNullCaptchaVerifier` reads out of `NODE_ENV` in its
 * own constructor. Where `NODE_ENV` is unset — which is the default on most runtimes — only the first
 * exists, and the constructor lets the verifier that passes every challenge through.
 */
import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import {
  AuthHCaptchaVerifier,
  AuthNullCaptchaVerifier,
  AuthRecaptchaV3Verifier,
  AuthTurnstileVerifier,
  AuthUnconfiguredCaptchaVerifier,
} from '~/core/captcha'
import { InMemoryEvents } from '~/core/events'
import type { Events } from '~/core/events/events.types'
import type { Deliver } from '~/core/flows/flows.delivery'
import type { Limiter } from '~/limiters'
import { magicLink } from '~/providers/magic-link'
import { CookieTransport } from '../../transport/cookie.transport'
import { AuthEngine } from '../engine'
import type { Engine } from '../engine.types'

/** Brandless, as a redis limiter is: `MemoryLimiter` carries `__isInProcessLimiter` and `strict()` refuses
 *  it, which would mask the one rejection each case below is about. */
const foreignLimiter: Limiter.Me = {
  consume: async () => ({ ok: true, remaining: 1, resetAt: new Date(Date.now() + 60_000) }),
  reset: async () => {},
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
function foreignEvents(): Events.IBus {
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
  it('is the only thing standing: the constructor did not refuse under this NODE_ENV', () => {
    // If this ever fails the suite is testing the constructor instead, and the gate below is vacuous.
    expect(process.env.NODE_ENV).not.toBe('production')
    expect(() => new AuthNullCaptchaVerifier()).not.toThrow()
  })

  it('passes a deployment with nothing dev-only in it', () => {
    expect(() => makeAuth().strict({ env: 'production' })).not.toThrow()
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

  it.each([
    ['turnstile', AuthTurnstileVerifier],
    ['hcaptcha', AuthHCaptchaVerifier],
    ['recaptcha', AuthRecaptchaV3Verifier],
  ])('rejects a plaintext %s endpoint however its scheme is spelled, and passes https', (_, Verifier) => {
    const make = (endpoint: string) => new Verifier({ allowInsecureEndpoint: true, endpoint, secret: 'sk' })
    for (const endpoint of ['http://captcha.test/x', 'HTTP://captcha.test/x', ' http://captcha.test/x']) {
      rejects(makeAuth({ captcha: make(endpoint) }), /siteverify endpoint is plaintext http/)
    }
    expect(() => makeAuth({ captcha: make('https://captcha.test/x') }).strict({ env: 'production' })).not.toThrow()
  })

  it('stays a no-op outside production, where a dev-only implementation is the point', () => {
    const auth = makeAuth({ captcha: new AuthNullCaptchaVerifier() })
    expect(() => auth.strict({ env: 'development' })).not.toThrow()
    expect(() => auth.strict({ env: 'test' })).not.toThrow()
  })
})

/**
 * Magic-link is the one provider whose whole flow is a message, and with no `deliver` its `begin` refuses
 * every link request. The provider sends through its own `deliver`, so that is what the gate reads:
 * `cfg.deliver` reaches it only when a thunk passes it on.
 */
describe('strict() rejects magic-link wired with no deliver', () => {
  const findIdentityByEmail = async () => null
  const sent = async () => {}

  it('refuses a provider built with no deliver, even when the config carries one', () => {
    const auth = makeAuth({ deliver: sent })
    auth.providers.register(magicLink({ findIdentityByEmail }))
    rejects(auth, /provider 'magic-link' has no `deliver`/)
  })

  it('accepts a provider built with its own deliver, with none on the config', () => {
    const auth = makeAuth()
    auth.providers.register(magicLink({ deliver: sent, findIdentityByEmail }))
    expect(() => auth.strict({ env: 'production' })).not.toThrow()
  })

  it('judges a thunk by the deliver it was handed', () => {
    const providers = [(_: unknown, deliver: Deliver | undefined) => magicLink({ deliver, findIdentityByEmail })]
    rejects(makeAuth({ providers }), /provider 'magic-link' has no `deliver`/)
    expect(() => makeAuth({ deliver: sent, providers }).strict({ env: 'production' })).not.toThrow()
  })

  it('leaves a deployment with no magic-link alone, deliver or not', () => {
    expect(() => makeAuth().strict({ env: 'production' })).not.toThrow()
  })
})
