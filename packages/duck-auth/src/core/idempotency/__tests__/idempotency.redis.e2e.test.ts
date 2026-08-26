/**
 * E2E: RedisIdempotency against a REAL Redis.
 *
 * `claim` is the whole contract: exactly one caller may win a key, or a retried
 * payment runs twice. It rests on `SET NX EX` being atomic in the server, which
 * `FakeRedis` cannot demonstrate: its `set` is a `Map` write inside one JS thread,
 * so a race there is unobservable by construction.
 *
 * Skips when DUCKAUTH_E2E_REDIS_URL is unset; `globalSetup` provisions a container
 * when docker is available.
 */
import Redis from 'ioredis'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { type ValkeyClient, valkeyAdapter } from '~/adapters/valkey'
import { dropPrefix, e2ePrefix, redisUrl } from '~/test/e2e-env'
import { RedisIdempotency } from '../idempotency.redis'

const URL = redisUrl()
const suite = URL ? describe : describe.skip

suite('E2E RedisIdempotency (real Redis)', () => {
  let raw: Redis
  let prefix: string
  let store: RedisIdempotency

  beforeAll(async () => {
    raw = new Redis(URL as string, { lazyConnect: true, maxRetriesPerRequest: 2 })
    await raw.connect()
    prefix = e2ePrefix()
    store = new RedisIdempotency({ prefix, redis: valkeyAdapter(raw as unknown as ValkeyClient.Me) })
  })

  afterAll(async () => {
    if (raw) {
      await dropPrefix(raw, prefix)
      await raw.quit()
    }
  })

  const key = (label: string) => `${label}-${e2ePrefix()}`

  it('the first claim wins and the second is refused', async () => {
    const k = key('claim')
    expect(await store.claim(k, 60_000, {})).toBe(true)
    expect(await store.claim(k, 60_000, {})).toBe(false)
  })

  it('exactly one of many concurrent claims wins', async () => {
    // The reason this store exists. 25 simultaneous retries of the same request
    // must produce one executor; SET NX decides that in the server.
    const k = key('race')
    const results = await Promise.all(Array.from({ length: 25 }, () => store.claim(k, 60_000, {})))
    expect(results.filter(Boolean)).toHaveLength(1)
  })

  it('a stored response round-trips through JSON', async () => {
    const k = key('roundtrip')
    await store.put(
      k,
      { body: { id: 'order-1', nested: { ok: true } }, createdAt: new Date(), status: 201 },
      60_000,
      {},
    )
    const got = await store.get(k, {})
    expect(got?.status).toBe(201)
    expect(got?.body).toEqual({ id: 'order-1', nested: { ok: true } })
  })

  it('the claim really expires on the server', async () => {
    const k = key('ttl')
    expect(await store.claim(k, 1000, {})).toBe(true)
    expect(await store.claim(k, 1000, {})).toBe(false)
    await new Promise((r) => setTimeout(r, 1300))
    expect(await store.claim(k, 1000, {})).toBe(true)
  })

  it('two tenants may hold the same key', async () => {
    const k = key('tenant')
    expect(await store.claim(k, 60_000, { tenantId: 'alpha' })).toBe(true)
    expect(await store.claim(k, 60_000, { tenantId: 'beta' })).toBe(true)
    expect(await store.claim(k, 60_000, { tenantId: 'alpha' })).toBe(false)
  })

  it('delete releases the key for a fresh claim', async () => {
    const k = key('delete')
    expect(await store.claim(k, 60_000, {})).toBe(true)
    await store.delete(k, {})
    expect(await store.claim(k, 60_000, {})).toBe(true)
  })

  it('get returns null for a key that was only claimed, never stored', async () => {
    const k = key('claimed-only')
    await store.claim(k, 60_000, {})
    expect(await store.get(k, {})).toBeNull()
  })
})
