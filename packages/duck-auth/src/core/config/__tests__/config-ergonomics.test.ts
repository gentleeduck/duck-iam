/**
 * Every config key should take the value a caller naturally has, in one call.
 * The reference is `limiter`, which takes `redisLimiter({ redis, max, windowMs })`
 * and nothing else. These cases hold the other keys to that shape, so a later
 * change that reintroduces a wrapper step fails here rather than in a consumer's
 * editor.
 */
import { describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AnomalyFacet, anomalyFacet, authMemoryDeviceFingerprintStore } from '~/core/anomaly'
import { fakeRedis } from '~/core/drivers/redis-like'
import { InMemoryEvents } from '~/core/events'
import { HijackFacet, hijackFacet } from '~/core/hijack'
import { idempotency, MemoryIdempotency, memoryIdempotency, redisIdempotency } from '~/core/idempotency'
import { bearerTransport } from '~/core/transport'
import { WebhookDeliverer, webhookDeliverer } from '~/core/webhooks'
import { memoryLimiter } from '~/limiters/memory'
import { AuthMemoryPasskeyChallengeStore, memoryPasskeyChallengeStore } from '~/providers/passkey'
import { createAuth } from '../config'

const stores = () => new MemoryAdapter()
const base = () => ({ baseUrl: 'https://app.test', stores: stores() })

describe('idempotency is built the way the limiter is, and held by the host', () => {
  it('store knobs and facet knobs share the one object', () => {
    const redis = fakeRedis()
    const facet = redisIdempotency({ headerName: 'x-request-id', prefix: 'auth:idem', redis, ttlMs: 60_000 })
    expect(facet.headerName).toBe('x-request-id')
  })

  it('the memory factory takes the same merged shape', () => {
    expect(memoryIdempotency({ headerName: 'x-key' }).headerName).toBe('x-key')
  })

  it('wraps a store the host wrote', () => {
    expect(idempotency(new MemoryIdempotency(), { headerName: 'x-custom' }).headerName).toBe('x-custom')
  })

  it('dedupes on its own, with no engine behind it', async () => {
    const idem = redisIdempotency({ redis: fakeRedis() })
    let runs = 0
    const executor = async () => {
      runs++
      return { body: { ok: true }, createdAt: new Date(), status: 201 }
    }

    const first = await idem.handle('key-1', {}, executor)
    const replay = await idem.handle('key-1', {}, executor)

    expect(runs).toBe(1)
    expect(replay.body).toEqual(first.body)
  })

  it('is no longer a createAuth key, and passing one says so', () => {
    expect(() => createAuth(Object.assign(base(), { idempotency: memoryIdempotency() }))).toThrow(
      expect.objectContaining({ meta: { detail: expect.stringContaining('idempotency') } }),
    )
  })

  it('builds an engine under NODE_ENV=production without a store it never uses', () => {
    vi.stubEnv('NODE_ENV', 'production')
    try {
      expect(() => createAuth({ ...base(), strict: false })).not.toThrow()
      expect(() => memoryIdempotency()).toThrow(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
    } finally {
      vi.unstubAllEnvs()
    }
  })
})

describe('anomaly thresholds are reachable from the config', () => {
  it('a configured reaction reaches the facet', async () => {
    const auth = createAuth({ ...base(), anomaly: { reactions: { '*': { 'new-device': 'deny' } } } })
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
    expect(hijackFacet(events, createAuth(base()).sessions, { onIpChange: 'revoke' })).toBeInstanceOf(HijackFacet)
  })

  it('the webhook deliverer has one', () => {
    const deliverer = webhookDeliverer({
      endpoints: [{ secret: 's', url: 'https://hooks.example.com/h' }],
      fetch: async () => new Response(),
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
