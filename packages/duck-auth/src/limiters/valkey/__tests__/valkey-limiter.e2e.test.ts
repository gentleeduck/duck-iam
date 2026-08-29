/**
 * E2E: `valkeyLimiter` against a REAL server.
 *
 * `redis-limiter.e2e.test.ts` covers `RedisLimiter`'s atomic counter and window
 * expiry. This proves `valkeyLimiter` wires a raw ioredis client into a working
 * limiter, on the property that matters: two instances share one counter.
 *
 * Skips when DUCKAUTH_E2E_REDIS_URL is unset; `globalSetup` provisions a container
 * when docker is available.
 */
import Redis from 'ioredis'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { valkeyLimiter } from '~/limiters/valkey'
import { dropPrefix, e2ePrefix, redisUrl } from '~/test/e2e-env'

const URL = redisUrl()
const suite = URL ? describe : describe.skip

suite('E2E valkeyLimiter (real server)', () => {
  let raw: Redis
  let prefix: string

  beforeAll(async () => {
    raw = new Redis(URL as string, { lazyConnect: true, maxRetriesPerRequest: 2 })
    await raw.connect()
    prefix = e2ePrefix()
  })

  afterAll(async () => {
    if (raw) {
      await dropPrefix(raw, prefix)
      await raw.quit()
    }
  })

  it('counts down to zero and then refuses', async () => {
    const limiter = valkeyLimiter({ max: 3, prefix, redis: raw, windowMs: 60_000 })
    const key = `count-${e2ePrefix()}`
    expect((await limiter.consume(key)).ok).toBe(true)
    await limiter.consume(key)
    const third = await limiter.consume(key)
    expect(third.ok).toBe(true)
    expect(third.remaining).toBe(0)
    expect((await limiter.consume(key)).ok).toBe(false)
  })

  it('two independent instances share one counter', async () => {
    const key = `shared-${e2ePrefix()}`
    const a = valkeyLimiter({ max: 2, prefix, redis: raw, windowMs: 60_000 })
    const b = valkeyLimiter({ max: 2, prefix, redis: raw, windowMs: 60_000 })
    expect((await a.consume(key)).ok).toBe(true)
    expect((await b.consume(key)).ok).toBe(true)
    expect((await a.consume(key)).ok).toBe(false)
  })
})
