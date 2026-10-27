/**
 * One switch: every dev-only implementation, and `strict()`, reads `NODE_ENV` through `resolveEnv`. What
 * development and test admit, production refuses, and an unset or unknown `NODE_ENV` is production.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthNullCaptchaVerifier, AuthTurnstileVerifier } from '~/core/captcha'
import { InMemoryEvents } from '~/core/events'
import type { Events } from '~/core/events/events.types'
import type { Deliver } from '~/core/flows/flows.delivery'
import { MemoryIdempotency } from '~/core/idempotency'
import { MemoryDPoPNonceStore } from '~/core/transport/dpop-nonce.memory'
import { WebhookDeliverer } from '~/core/webhooks'
import type { Limiter } from '~/limiters'
import {
  AuthMemoryAccessTokenStore,
  AuthMemoryClientStore,
  AuthMemoryCodeStore,
  AuthMemoryConsentStore,
  AuthMemoryRefreshTokenStore,
  createOidcOP,
} from '~/oidc/op'
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
    transport: new CookieTransport({ name: 'duck-sid' }),
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
  expect(() => auth.strict()).toThrow(
    expect.objectContaining({
      code: 'AUTH_MISCONFIGURED',
      meta: expect.objectContaining({ detail: expect.stringMatching(pattern) }),
    }),
  )

describe('one switch: what development admits, production refuses', () => {
  const op = { config: { issuer: 'https://op.example.com', supportedScopes: ['openid'] }, signIdToken: () => 'jwt' }

  const DEV_ONLY: Array<[string, () => unknown]> = [
    ['the always-pass captcha verifier', () => new AuthNullCaptchaVerifier()],
    [
      'a captcha endpoint on loopback over http',
      () => new AuthTurnstileVerifier({ endpoint: 'http://localhost:8080/x', secret: 'sk' }),
    ],
    [
      'a webhook receiver on loopback over http',
      () => new WebhookDeliverer({ endpoints: [{ secret: 'sk', url: 'http://localhost:3000/h' }] }),
    ],
    ['the in-process DPoP nonce store', () => new MemoryDPoPNonceStore()],
    ['the in-process idempotency store', () => new MemoryIdempotency()],
    ['the OIDC OP client store', () => new AuthMemoryClientStore()],
    ['the OIDC OP code store', () => new AuthMemoryCodeStore()],
    ['the OIDC OP access token store', () => new AuthMemoryAccessTokenStore()],
    ['the OIDC OP refresh token store', () => new AuthMemoryRefreshTokenStore()],
    ['the OIDC OP consent store', () => new AuthMemoryConsentStore()],
    ['an OIDC OP left on its default stores', () => createOidcOP({ ...op, auth: makeAuth() })],
  ]

  it.each(['development', 'test'])('builds every one with NODE_ENV=%s, and strict() passes', (env) => {
    vi.stubEnv('NODE_ENV', env)
    for (const [, build] of DEV_ONLY) expect(build).not.toThrow()
    expect(() => makeAuth({ captcha: new AuthNullCaptchaVerifier() }).strict()).not.toThrow()
  })

  it.each(['production', undefined, 'staging'])('refuses every one at construction with NODE_ENV=%o', (env) => {
    vi.stubEnv('NODE_ENV', env)
    for (const [label, build] of DEV_ONLY) {
      expect(build, label).toThrow(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
    }
  })

  it('builds an OIDC OP in production once every store is passed', () => {
    vi.stubEnv('NODE_ENV', 'production')
    const none = async () => null
    const done = async () => {}
    const stores = {
      accessTokens: { findByHash: none, insert: done, revokeByHash: done, revokeFamily: done },
      clients: { findById: none, insert: done },
      codes: { consume: none, insert: done },
      consents: { find: none, upsert: done },
      refreshTokens: { consume: none, findByHash: none, insert: done, revokeFamily: done },
    }
    expect(() => createOidcOP({ ...op, auth: makeAuth(), stores })).not.toThrow()
  })

  it('passes a production deployment with nothing dev-only in it', () => {
    vi.stubEnv('NODE_ENV', 'production')
    expect(() => makeAuth().strict()).not.toThrow()
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

  beforeEach(() => {
    vi.stubEnv('NODE_ENV', 'production')
  })

  it('refuses a provider built with no deliver, even when the config carries one', () => {
    const auth = makeAuth({ deliver: sent })
    auth.providers.register(magicLink({ findIdentityByEmail }))
    rejects(auth, /provider 'magic-link' has no `deliver`/)
  })

  it('accepts a provider built with its own deliver, with none on the config', () => {
    const auth = makeAuth()
    auth.providers.register(magicLink({ deliver: sent, findIdentityByEmail }))
    expect(() => auth.strict()).not.toThrow()
  })

  it('judges a thunk by the deliver it was handed', () => {
    const providers = [(_: unknown, deliver: Deliver | undefined) => magicLink({ deliver, findIdentityByEmail })]
    rejects(makeAuth({ providers }), /provider 'magic-link' has no `deliver`/)
    expect(() => makeAuth({ deliver: sent, providers }).strict()).not.toThrow()
  })

  it('leaves a deployment with no magic-link alone, deliver or not', () => {
    expect(() => makeAuth().strict()).not.toThrow()
  })
})
