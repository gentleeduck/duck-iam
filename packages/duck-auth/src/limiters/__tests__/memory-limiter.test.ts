import { beforeEach, describe, expect, it } from 'vitest'
import { FakeRedis } from '~/adapters/redis'
import { RedisLimiter } from '../redis'

describe('RedisLimiter', () => {
  let redis: FakeRedis
  let limiter: RedisLimiter

  beforeEach(() => {
    redis = new FakeRedis()
    limiter = new RedisLimiter({ redis, max: 3, windowMs: 60_000, prefix: 'test:rl' })
  })

  it('allows up to max requests', async () => {
    expect((await limiter.consume('ip:1.2.3.4')).ok).toBe(true)
    expect((await limiter.consume('ip:1.2.3.4')).ok).toBe(true)
    expect((await limiter.consume('ip:1.2.3.4')).ok).toBe(true)
  })

  it('rejects once max exceeded', async () => {
    for (let i = 0; i < 3; i++) await limiter.consume('k')
    const blocked = await limiter.consume('k')
    expect(blocked.ok).toBe(false)
    expect(blocked.remaining).toBe(0)
  })

  it('separate keys do not interfere', async () => {
    for (let i = 0; i < 3; i++) await limiter.consume('a')
    expect((await limiter.consume('b')).ok).toBe(true)
  })

  it('reset clears a key so consume succeeds again', async () => {
    for (let i = 0; i < 3; i++) await limiter.consume('k')
    expect((await limiter.consume('k')).ok).toBe(false)
    await limiter.reset('k')
    expect((await limiter.consume('k')).ok).toBe(true)
  })

  it('reports remaining headroom on each call', async () => {
    const a = await limiter.consume('k')
    expect(a.remaining).toBe(2)
    const b = await limiter.consume('k')
    expect(b.remaining).toBe(1)
    const c = await limiter.consume('k')
    expect(c.remaining).toBe(0)
  })

  it('weight > 1 consumes the full amount', async () => {
    const result = await limiter.consume('k', 3)
    expect(result.ok).toBe(true)
    expect(result.remaining).toBe(0)
    const next = await limiter.consume('k')
    expect(next.ok).toBe(false)
  })
})
