/** E2E: RedisLimiter against a REAL Redis. */
import Redis from 'ioredis'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { valkeyAdapter } from '~/adapters/valkey'
import { dropPrefix, e2ePrefix, redisUrl } from '~/test/e2e-env'
import { RedisLimiter } from '../index'

const URL = redisUrl()
const suite = URL ? describe : describe.skip

suite('E2E RedisLimiter (real Redis)', () => {
  let raw: Redis
  let prefix: string

  beforeAll(async () => {
    raw = new Redis(URL, { lazyConnect: true, maxRetriesPerRequest: 2 })
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
    return new RedisLimiter({ max, prefix, redis: valkeyAdapter(raw), windowMs })
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

  it('a counter left without a TTL gets one back, and resets with the window', async () => {
    const l = limiter(1000, 3)
    const key = `immortal-${e2ePrefix()}`
    await raw.set(`${prefix}:${key}`, '5')
    expect((await l.consume(key)).ok).toBe(false)
    const pttl = await raw.pttl(`${prefix}:${key}`)
    expect(pttl).toBeGreaterThan(0)
    expect(pttl).toBeLessThanOrEqual(1000)
    await new Promise((r) => setTimeout(r, 1300))
    expect((await l.consume(key)).ok).toBe(true)
  })

  it('resetAt is when the window ends, not a full window from now', async () => {
    const l = limiter(60_000, 1)
    const key = `reset-at-${e2ePrefix()}`
    await raw.set(`${prefix}:${key}`, '1', 'PX', 5000)
    const refused = await l.consume(key)
    expect(refused.ok).toBe(false)
    expect(refused.resetAt.getTime() - Date.now()).toBeLessThanOrEqual(5000)
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
