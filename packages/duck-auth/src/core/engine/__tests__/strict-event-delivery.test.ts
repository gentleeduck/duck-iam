/** In production, `strict()` refuses an in-process bus only while it holds a `fleet` handler; a Redis bus
 *  passes whatever it holds. */
import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { FakeRedis } from '~/core/drivers/redis-like'
import { AuthError } from '~/core/errors'
import { InMemoryEvents, RedisEvents } from '~/core/events'
import type { Events } from '~/core/events/events.types'
import { WebhookDeliverer } from '~/core/webhooks'
import type { Limiter } from '~/limiters'
import { CookieTransport } from '../../transport/cookie.transport'
import { AuthEngine } from '../engine'

const ORIGIN: Events.OnOptions = { delivery: 'origin' }
const noop = () => {}
const FLEET_RULE =
  "handlers must run on every server (delivery 'fleet', the default), and the in-process bus runs them on one; pass redisEvents({ redis }) or register them with { delivery: 'origin' }"

/** Brandless, as a redis limiter is. */
const foreignLimiter: Limiter.Me = {
  consume: async () => ({ ok: true, remaining: 1, resetAt: new Date(Date.now() + 60_000) }),
  reset: async () => {},
}

/** The memory adapter's facets with the brand removed, as a drizzle or redis deploy looks to `strict()`. */
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

/** Production-clean but for the bus and its handlers. */
function makeAuth(events?: Events.IBus) {
  const auth = new AuthEngine({
    baseUrl: 'https://app.example.com',
    ...(events && { events }),
    limiter: foreignLimiter,
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
  return auth
}

/** What `strict()` refused in production, or `''` when it booted. */
function refusal(auth: AuthEngine): string {
  try {
    auth.strict({ env: 'production' })
    return ''
  } catch (err) {
    if (!(err instanceof AuthError) || err.code !== 'AUTH_MISCONFIGURED') throw err
    return String(err.meta.detail)
  }
}

const detail = (...lines: string[]) => `production strict() checks failed:\n  - ${lines.join('\n  - ')}`

describe.each([
  ['an InMemoryEvents', () => new InMemoryEvents()],
  ['no bus', () => undefined],
])('strict() over %s', (_name, bus) => {
  it('passes with only origin handlers, lockout included', () => {
    const auth = makeAuth(bus())
    auth.events.on('lockout', noop, ORIGIN)
    auth.events.on('authz.revoked', noop, ORIGIN)
    expect(refusal(auth)).toBe('')
  })

  it('refuses one handler registered with no options, naming its event', () => {
    const auth = makeAuth(bus())
    auth.events.on('lockout', noop, ORIGIN)
    auth.events.on('authz.revoked', noop)
    expect(refusal(auth)).toBe(detail(`\`authz.revoked\` ${FLEET_RULE}`))
  })

  it('refuses a default lockout handler, which satisfies the lockout check but not this one', () => {
    const auth = makeAuth(bus())
    auth.events.on('lockout', noop)
    expect(refusal(auth)).toBe(detail(`\`lockout\` ${FLEET_RULE}`))
  })

  it('names every event holding a fleet handler, and only those', () => {
    const auth = makeAuth(bus())
    auth.events.on('lockout', noop, ORIGIN)
    auth.events.on('session.created', noop, { delivery: 'fleet' })
    auth.events.on('session.created', () => {})
    auth.events.on('authz.revoked', noop)
    expect(refusal(auth)).toBe(detail(`\`session.created\`, \`authz.revoked\` ${FLEET_RULE}`))
  })

  it('passes again once the last fleet handler is removed', () => {
    const auth = makeAuth(bus())
    auth.events.on('lockout', noop, ORIGIN)
    const off = auth.events.on('authz.revoked', noop)
    expect(refusal(auth)).not.toBe('')

    off()
    expect(refusal(auth)).toBe('')
  })

  it('with no handlers refuses only the missing lockout handler', () => {
    expect(refusal(makeAuth(bus()))).toBe(
      detail('no `lockout` event handler subscribed; operators must wire one (paging, audit, etc.)'),
    )
  })

  it('sees only the handlers registered before it runs', () => {
    const auth = makeAuth(bus())
    auth.events.on('lockout', noop, ORIGIN)
    expect(refusal(auth)).toBe('')

    auth.events.on('authz.revoked', noop)
    expect(refusal(auth)).toBe(detail(`\`authz.revoked\` ${FLEET_RULE}`))
  })

  it('passes a webhook deliverer, which posts from the server that emitted', () => {
    const auth = makeAuth(bus())
    new WebhookDeliverer({
      endpoints: [{ events: '*', secret: 'shhh', url: 'https://hooks.example.com/duck' }],
      fetch: async () => new Response(),
    }).attach(auth.events)
    expect(auth.events.listenerCount?.('lockout')).toBe(1)
    expect(refusal(auth)).toBe('')
  })

  it("refuses a plugin's event handlers, which take the default", async () => {
    const auth = makeAuth(bus())
    auth.events.on('lockout', noop, ORIGIN)
    await auth.use({ events: { 'session.created': noop }, id: 'audit' })
    expect(refusal(auth)).toBe(detail(`\`session.created\` ${FLEET_RULE}`))
  })

  it('is not checked outside production', () => {
    const auth = makeAuth(bus())
    auth.events.on('authz.revoked', noop)
    expect(() => auth.strict({ env: 'development' })).not.toThrow()
    expect(() => auth.strict({ env: 'test' })).not.toThrow()
  })
})

describe('strict() over a bus that runs every handler on every server', () => {
  it('passes a Redis bus holding fleet handlers', () => {
    const auth = makeAuth(new RedisEvents({ redis: new FakeRedis() }))
    auth.events.on('lockout', noop)
    auth.events.on('authz.revoked', noop, { delivery: 'fleet' })
    expect(refusal(auth)).toBe('')
  })

  it('passes a Redis bus holding only origin handlers', () => {
    const auth = makeAuth(new RedisEvents({ redis: new FakeRedis() }))
    auth.events.on('lockout', noop, ORIGIN)
    expect(refusal(auth)).toBe('')
  })

  it('refuses an in-process bus that cannot list its fleet handlers', () => {
    const inner = new InMemoryEvents()
    const legacy: Events.IBus = Object.assign(
      {
        emit: inner.emit.bind(inner),
        listenerCount: inner.listenerCount.bind(inner),
        on: inner.on.bind(inner),
      },
      { __isInProcessBus: true },
    )
    const auth = makeAuth(legacy)
    auth.events.on('lockout', noop, ORIGIN)
    expect(refusal(auth)).toBe(
      detail('in-process event bus rejected in production; it cannot list its `fleet` handlers'),
    )
  })
})
