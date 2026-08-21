/**
 * E2E: RedisLimiter against a REAL Redis.
 *
 * A rate limiter is only worth anything if the counter is atomic across processes
 * and the window actually expires. `FakeRedis` fakes both: its `incr` is a JS
 * `Map` write that cannot race, and its TTL is a timestamp checked on read rather
 * than eviction by the server. Neither property survives being faked, so both are
 * asserted here or nowhere.
 *
 * Skips when DUCKAUTH_E2E_REDIS_URL is unset; `globalSetup` provisions a container
 * when docker is available.
 */
import Redis from 'ioredis'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { dropPrefix, e2ePrefix, redisUrl } from '~/test/e2e-env'
import { toRedisLike } from '~/test/e2e-redis'
import { RedisLimiter } from '../index'

const URL = redisUrl()
const suite = URL ? describe : describe.skip

suite('E2E RedisLimiter (real Redis)', () => {
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

  function limiter(windowMs: number, max: number): RedisLimiter {
    return new RedisLimiter({ max, prefix, redis: toRedisLike(raw), windowMs })
  }

  it('counts down to zero and then refuses', async () => {
    const l = limiter(60_000, 3)
    const key = `count-${e2ePrefix()}`
    const first = await l.consume(key)
    expect(first.ok).toBe(true)
    await l.consume(key)
    const third = await l.consume(key)
    expect(third.ok).toBe(true)
    expect(third.remaining).toBe(0)
    const fourth = await l.consume(key)
    expect(fourth.ok).toBe(false)
  })

  it('two independent instances share one counter', async () => {
    // The whole point of a Redis limiter: a second app process must not get a
    // fresh allowance. An in-process limiter passes the test above and fails this.
    const a = limiter(60_000, 2)
    const b = limiter(60_000, 2)
    const key = `shared-${e2ePrefix()}`
    expect((await a.consume(key)).ok).toBe(true)
    expect((await b.consume(key)).ok).toBe(true)
    expect((await a.consume(key)).ok).toBe(false)
    expect((await b.consume(key)).ok).toBe(false)
  })

  it('concurrent consumes never over-admit', async () => {
    // 20 callers racing for 5 slots. INCR is atomic server-side; a read-then-write
    // limiter would admit more than 5 here.
    const l = limiter(60_000, 5)
    const key = `race-${e2ePrefix()}`
    const results = await Promise.all(Array.from({ length: 20 }, () => l.consume(key)))
    expect(results.filter((r) => r.ok)).toHaveLength(5)
  })

  it('the window really expires on the server', async () => {
    const l = limiter(1000, 1)
    const key = `ttl-${e2ePrefix()}`
    expect((await l.consume(key)).ok).toBe(true)
    expect((await l.consume(key)).ok).toBe(false)
    await new Promise((r) => setTimeout(r, 1300))
    expect((await l.consume(key)).ok).toBe(true)
  })

  it('reset clears the counter', async () => {
    const l = limiter(60_000, 1)
    const key = `reset-${e2ePrefix()}`
    await l.consume(key)
    expect((await l.consume(key)).ok).toBe(false)
    await l.reset(key)
    expect((await l.consume(key)).ok).toBe(true)
  })

  it('separate keys hold separate budgets', async () => {
    const l = limiter(60_000, 1)
    const a = `sep-a-${e2ePrefix()}`
    const b = `sep-b-${e2ePrefix()}`
    expect((await l.consume(a)).ok).toBe(true)
    expect((await l.consume(a)).ok).toBe(false)
    expect((await l.consume(b)).ok).toBe(true)
  })
})
