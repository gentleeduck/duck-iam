/**
 * Every config key should take the value a caller naturally has, in one call.
 * The reference is `limiter`, which takes `redisLimiter({ redis, max, windowMs })`
 * and nothing else. These cases hold the other keys to that shape, so a later
 * change that reintroduces a wrapper step fails here rather than in a consumer's
 * editor.
 */
import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { fakeRedis } from '~/adapters/redis/redis-like'
import { AnomalyFacet, anomalyFacet, authMemoryDeviceFingerprintStore } from '~/core/anomaly'
import { InMemoryEvents } from '~/core/events'
import { HijackFacet, hijackFacet } from '~/core/hijack'
import {
  IdempotencyImpl,
  idempotency,
  MemoryIdempotency,
  memoryIdempotency,
  RedisIdempotency,
  redisIdempotency,
  resolveIdempotency,
} from '~/core/idempotency'
import { bearerTransport } from '~/core/transport'
import { WebhookDeliverer, webhookDeliverer } from '~/core/webhooks'
import { memoryLimiter } from '~/limiters/memory'
import { AuthMemoryPasskeyChallengeStore, memoryPasskeyChallengeStore } from '~/providers/passkey'
import { createAuth } from '../config'

const stores = () => new MemoryAdapter()
const base = () => ({ baseUrl: 'https://app.test', stores: stores() })

describe('idempotency is configured the way the limiter is', () => {
  it('one call builds a ready-to-use facet, with no wrapper step', () => {
    const auth = createAuth({ ...base(), idempotency: memoryIdempotency() })
    expect(auth.idempotency).toBeInstanceOf(IdempotencyImpl)
    expect(auth.idempotency.enabled()).toBe(true)
  })

  it('the redis spelling reads like the redis limiter beside it', () => {
    const redis = fakeRedis()
    const auth = createAuth({
      ...base(),
      idempotency: redisIdempotency({ prefix: 'auth:idem', redis }),
      limiter: memoryLimiter({ max: 10, windowMs: 60_000 }),
    })
    expect(auth.idempotency.enabled()).toBe(true)
  })

  it('store knobs and facet knobs share the one object', () => {
    const redis = fakeRedis()
    const facet = redisIdempotency({ headerName: 'x-request-id', prefix: 'auth:idem', redis, ttlMs: 60_000 })
    expect(facet.headerName).toBe('x-request-id')
  })

  it('the memory factory takes the same merged shape', () => {
    expect(memoryIdempotency({ headerName: 'x-key' }).headerName).toBe('x-key')
  })

  it('a bare store is accepted too, and wrapped by the engine', () => {
    const auth = createAuth({ ...base(), idempotency: new MemoryIdempotency({ development: true }) })
    expect(auth.idempotency).toBeInstanceOf(IdempotencyImpl)
    expect(auth.idempotency.enabled()).toBe(true)
  })

  it('an explicitly wrapped store still works, for a custom implementation', () => {
    const wrapped = idempotency(new MemoryIdempotency({ development: true }), { headerName: 'x-custom' })
    const auth = createAuth({ ...base(), idempotency: wrapped })
    expect(auth.idempotency).toBe(wrapped)
    expect(auth.idempotency.headerName).toBe('x-custom')
  })

  it('wrapping something already wrapped is a no-op rather than an error', () => {
    const once = memoryIdempotency()
    expect(idempotency(once)).toBe(once)
    expect(resolveIdempotency(once)).toBe(once)
  })

  it('omitting the key still yields a working in-memory facet', () => {
    expect(createAuth(base()).idempotency.enabled()).toBe(true)
  })

  it('the redis store is still constructible on its own for custom wiring', () => {
    expect(new RedisIdempotency({ redis: fakeRedis() })).toBeInstanceOf(RedisIdempotency)
  })

  it('the facet actually dedupes through whichever spelling built it', async () => {
    const auth = createAuth({ ...base(), idempotency: redisIdempotency({ redis: fakeRedis() }) })
    let runs = 0
    const executor = async () => {
      runs++
      return { body: { ok: true }, createdAt: new Date(), status: 201 }
    }

    const first = await auth.idempotency.handle('key-1', {}, executor)
    const replay = await auth.idempotency.handle('key-1', {}, executor)

    expect(runs).toBe(1)
    expect(replay.body).toEqual(first.body)
  })
})

describe('anomaly thresholds are reachable from the config', () => {
  it('a configured reaction reaches the facet', async () => {
    const auth = createAuth({ ...base(), anomaly: { reactions: { 'new-device': 'deny' } } })
    expect(auth.anomaly.decide([{ evidence: {}, kind: 'new-device', score: 0.01 }])).toBe('deny')
  })

  it('a configured threshold reaches the facet', async () => {
    const auth = createAuth({ ...base(), anomaly: { denyAt: 0.2, stepUpAt: 0.1 } })
    expect(auth.anomaly.decide([{ evidence: {}, kind: 'off-hours', score: 0.15 }])).toBe('step-up')
    expect(auth.anomaly.decide([{ evidence: {}, kind: 'off-hours', score: 0.25 }])).toBe('deny')
  })

  it('an omitted key keeps the shipped defaults', () => {
    const auth = createAuth(base())
    expect(auth.anomaly.decide([{ evidence: {}, kind: 'off-hours', score: 0.5 }])).toBe('allow')
    expect(auth.anomaly.decide([{ evidence: {}, kind: 'off-hours', score: 0.7 }])).toBe('step-up')
  })

  it('a partial config merges over the defaults rather than replacing them', () => {
    const auth = createAuth({ ...base(), anomaly: { stepUpAt: 0.1 } })
    expect(auth.anomaly.decide([{ evidence: {}, kind: 'off-hours', score: 0.99 }])).toBe('deny')
  })
})

describe('every config-position class has a factory beside it', () => {
  const events = new InMemoryEvents()

  it('the facets the engine builds are also constructible by function', () => {
    expect(anomalyFacet(events)).toBeInstanceOf(AnomalyFacet)
    expect(hijackFacet(events, { onIpChange: 'revoke' })).toBeInstanceOf(HijackFacet)
  })

  it('the webhook deliverer has one', () => {
    const deliverer = webhookDeliverer({
      endpoints: [{ secret: 's', url: 'https://hooks.example.com/h' }],
      fetch: (async () => new Response()) as never,
    })
    expect(deliverer).toBeInstanceOf(WebhookDeliverer)
  })

  it('the reference stores a consumer passes into a detector or provider have one', () => {
    expect(authMemoryDeviceFingerprintStore()).toBeInstanceOf(Object)
    expect(memoryPasskeyChallengeStore()).toBeInstanceOf(AuthMemoryPasskeyChallengeStore)
  })

  it('the anomaly barrel exposes its detectors, not just the facet', async () => {
    const mod = await import('~/core/anomaly')
    expect(typeof mod.deviceFingerprintDetector).toBe('function')
    expect(typeof mod.authImpossibleTravelDetector).toBe('function')
  })

  it('the channels barrel exposes every channel, and imports at runtime', async () => {
    // It used to re-export only the `Channel` type namespace, and to do it as a
    // value, so importing the barrel threw before a consumer reached a channel
    // that was not there to reach.
    const mod = await import('~/channels')
    for (const name of [
      'authConsoleChannel',
      'authNoopChannel',
      'authResendChannel',
      'authSesChannel',
      'authSmtpChannel',
      'authTwilioChannel',
      'authWebPushChannel',
    ]) {
      expect(typeof (mod as Record<string, unknown>)[name], name).toBe('function')
    }
  })
})

describe('the keys that already took the natural value keep doing so', () => {
  it('stores accepts an adapter directly, without picking the triple apart', () => {
    const adapter = new MemoryAdapter()
    const auth = createAuth({ baseUrl: 'https://app.test', stores: adapter })
    expect(auth.cfg.stores.identities).toBe(adapter.identities)
    expect(auth.cfg.stores.sessions).toBe(adapter.sessions)
    expect(auth.cfg.stores.credentials).toBe(adapter.credentials)
  })

  it('an adapter carrying an org store forwards that too', () => {
    const adapter = new MemoryAdapter()
    expect(createAuth({ baseUrl: 'https://app.test', stores: adapter }).cfg.stores.orgs).toBe(adapter.orgs)
  })

  it('transport and limiter take the object their factory returned', () => {
    const transport = bearerTransport()
    const limiter = memoryLimiter({ max: 5, windowMs: 1_000 })
    const auth = createAuth({ ...base(), limiter, transport })
    expect(auth.transport).toBe(transport)
    expect(auth.cfg.limiter).toBe(limiter)
  })

  it('hijack takes a plain object, which is what anomaly now matches', () => {
    const auth = createAuth({ ...base(), anomaly: { denyAt: 0.5 }, hijack: { onIpChange: 'revoke' } })
    expect(auth.cfg.hijack).toMatchObject({ onIpChange: 'revoke' })
    expect(auth.cfg.anomaly).toMatchObject({ denyAt: 0.5 })
  })
})
