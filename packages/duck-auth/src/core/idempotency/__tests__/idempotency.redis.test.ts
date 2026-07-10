import { beforeEach, describe, expect, it } from 'vitest'
import { FakeRedis } from '~/adapters/redis'
import { RedisIdempotency } from '../idempotency.redis'

const ctx = { tenantId: 'acme' }

describe('RedisIdempotencyStore', () => {
  let redis: FakeRedis
  let store: RedisIdempotency

  beforeEach(() => {
    redis = new FakeRedis()
    store = new RedisIdempotency({ redis, prefix: 'test:idem' })
  })

  it('claim() returns true on first call, false on second', async () => {
    expect(await store.claim('k1', 60_000, ctx)).toBe(true)
    expect(await store.claim('k1', 60_000, ctx)).toBe(false)
  })

  it('get() returns null while only the claim tombstone exists', async () => {
    await store.claim('k1', 60_000, ctx)
    expect(await store.get('k1', ctx)).toBeNull()
  })

  it('put() overwrites the tombstone with the executor response; get() reads it back', async () => {
    await store.claim('k1', 60_000, ctx)
    await store.put('k1', { status: 200, body: { ok: true }, createdAt: new Date() }, 60_000, ctx)
    const cached = await store.get('k1', ctx)
    expect(cached?.status).toBe(200)
    expect(cached?.body).toEqual({ ok: true })
  })

  it('tenant scoping: same key under two tenants does not collide', async () => {
    expect(await store.claim('k1', 60_000, { tenantId: 'a' })).toBe(true)
    expect(await store.claim('k1', 60_000, { tenantId: 'b' })).toBe(true)
  })

  it('delete() drops the entry so a fresh claim succeeds', async () => {
    await store.claim('k1', 60_000, ctx)
    await store.delete('k1', ctx)
    expect(await store.claim('k1', 60_000, ctx)).toBe(true)
  })

  it('TTL is honored; expired claim is reclaimable', async () => {
    // Real Redis TTL granularity is seconds; FakeRedis honors EX seconds too.
    await store.claim('k1', 1000, ctx)
    await new Promise((r) => setTimeout(r, 1100))
    expect(await store.claim('k1', 60_000, ctx)).toBe(true)
  })
})
