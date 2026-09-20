import { afterEach, describe, expect, it, vi } from 'vitest'
import { FakeRedis } from '~/core/drivers/redis-like'

describe('FakeRedis.scan - glob MATCH', () => {
  async function withKeys(keys: string[]): Promise<FakeRedis> {
    const r = new FakeRedis()
    for (const k of keys) await r.set(k, '1')
    return r
  }

  it('matches plain prefix glob', async () => {
    const r = await withKeys(['user:1', 'user:2', 'session:1'])
    const [, matched] = await r.scan('0', { match: 'user:*' })
    expect(matched.sort()).toEqual(['user:1', 'user:2'])
  })

  it('matches plain suffix glob', async () => {
    const r = await withKeys(['a-x', 'b-x', 'b-y'])
    const [, matched] = await r.scan('0', { match: '*-x' })
    expect(matched.sort()).toEqual(['a-x', 'b-x'])
  })

  it('matches inner star glob', async () => {
    const r = await withKeys(['a-1-z', 'a-22-z', 'a-z'])
    const [, matched] = await r.scan('0', { match: 'a-*-z' })
    expect(matched.sort()).toEqual(['a-1-z', 'a-22-z'])
  })

  it('multiple stars collapse cleanly (a***b == a*b)', async () => {
    const r = await withKeys(['ab', 'aXb', 'aXYZb', 'aXc'])
    const [, matched] = await r.scan('0', { match: 'a***b' })
    expect(matched.sort()).toEqual(['aXYZb', 'aXb', 'ab'])
  })

  it('exact pattern matches only the exact key', async () => {
    const r = await withKeys(['exact', 'exacto'])
    const [, matched] = await r.scan('0', { match: 'exact' })
    expect(matched).toEqual(['exact'])
  })

  it('a pathological multi-star non-matching pattern stays linear (ReDoS defense)', async () => {
    // Pattern like `a*a*a*a*a*X` matched against `aaaaaaaaaa...Y` would
    // have driven the legacy regex into super-linear backtracking. With
    // the iterative matcher this returns false in O(n*m).
    const r = await withKeys(['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaY'])
    const start = performance.now()
    const [, matched] = await r.scan('0', { match: 'a*a*a*a*a*a*a*a*X' })
    const elapsed = performance.now() - start
    expect(matched).toEqual([])
    // Loose bound: should complete well under 100ms on any modern
    // machine. Catastrophic backtracking would push it into seconds.
    expect(elapsed).toBeLessThan(100)
  })

  it('a pattern containing `?` matches `?` literally (legacy threw SyntaxError, crashing scan)', async () => {
    const r = await withKeys(['key?1', 'key:1'])
    const [, matched] = await r.scan('0', { match: 'key?1' })
    // The legacy code: regex `^key?1$` is invalid syntax in some engines
    // because `?` after a non-quantifiable char threw. The iterative
    // matcher treats `?` as a literal char so `key?1` matches.
    expect(matched).toEqual(['key?1'])
  })

  it('a pattern containing `[` does not crash (legacy regex `^[$` was invalid)', async () => {
    const r = await withKeys(['[abc]'])
    const [, matched] = await r.scan('0', { match: '[abc]' })
    expect(matched).toEqual(['[abc]'])
  })

  it('an oversize pattern is rejected (length cap defends against an attacker-supplied huge pattern)', async () => {
    const r = await withKeys(['k'])
    const huge = `${'*'.repeat(257)}k`
    const [, matched] = await r.scan('0', { match: huge })
    expect(matched).toEqual([])
  })
})

/**
 * The gc sweep in `RedisSessionImpl` runs against this class in every unit test,
 * so a FakeRedis that ordered, bounded or paged differently from Redis would
 * make those tests agree with each other and disagree with production.
 */
describe('FakeRedis - sorted sets', () => {
  it('zadd reports an insert once, and a re-score as an update', async () => {
    const r = new FakeRedis()
    expect(await r.zadd('z', 10, 'a')).toBe(1)
    expect(await r.zadd('z', 20, 'a')).toBe(0)
    // The second call moved the member rather than adding a duplicate.
    expect(await r.zrangebyscore('z', 15, 25)).toEqual(['a'])
    expect(await r.zrangebyscore('z', 0, 14)).toEqual([])
  })

  it('zrangebyscore bounds are inclusive on both ends', async () => {
    // `gc` asks for `<= now`; an exclusive upper bound would leave a session
    // that expired on exactly this millisecond unswept until the next cycle.
    const r = new FakeRedis()
    await r.zadd('z', 100, 'a')
    expect(await r.zrangebyscore('z', 100, 100)).toEqual(['a'])
  })

  it('zrangebyscore accepts -inf and +inf', async () => {
    const r = new FakeRedis()
    await r.zadd('z', -5, 'a')
    await r.zadd('z', 5, 'b')
    expect(await r.zrangebyscore('z', '-inf', '+inf')).toEqual(['a', 'b'])
    expect(await r.zrangebyscore('z', '-inf', 0)).toEqual(['a'])
  })

  it('zrangebyscore returns members in score order', async () => {
    const r = new FakeRedis()
    await r.zadd('z', 30, 'c')
    await r.zadd('z', 10, 'a')
    await r.zadd('z', 20, 'b')
    expect(await r.zrangebyscore('z', '-inf', '+inf')).toEqual(['a', 'b', 'c'])
  })

  it('members sharing a score come back in a stable lexicographic order', async () => {
    // Sessions planted at one instant are the normal case in a test; without a
    // tiebreak the page boundary would fall in a different place each run.
    const r = new FakeRedis()
    for (const m of ['c', 'a', 'b']) await r.zadd('z', 1, m)
    expect(await r.zrangebyscore('z', '-inf', '+inf')).toEqual(['a', 'b', 'c'])
  })

  it('LIMIT pages from the offset, and a page past the end is empty', async () => {
    const r = new FakeRedis()
    for (let i = 0; i < 5; i++) await r.zadd('z', i, `m${i}`)
    expect(await r.zrangebyscore('z', '-inf', '+inf', { limit: { count: 2, offset: 0 } })).toEqual(['m0', 'm1'])
    expect(await r.zrangebyscore('z', '-inf', '+inf', { limit: { count: 2, offset: 2 } })).toEqual(['m2', 'm3'])
    expect(await r.zrangebyscore('z', '-inf', '+inf', { limit: { count: 2, offset: 9 } })).toEqual([])
  })

  it('zrem counts only what it actually removed', async () => {
    // `gc` reports this number as `deleted`, so counting absent members would
    // have a losing instance claim work the winner did.
    const r = new FakeRedis()
    await r.zadd('z', 1, 'a')
    await r.zadd('z', 2, 'b')
    expect(await r.zrem('z', 'a', 'ghost')).toBe(1)
    expect(await r.zrangebyscore('z', '-inf', '+inf')).toEqual(['b'])
  })

  it('a range or removal on an unknown key is empty, not an error', async () => {
    const r = new FakeRedis()
    expect(await r.zrangebyscore('nope', '-inf', '+inf')).toEqual([])
    expect(await r.zrem('nope', 'a')).toBe(0)
  })
})

/**
 * `EXPIRE` applies to a key of any type. `FakeRedis` held the TTL on its string entry, so it answered
 * `0` and set nothing for a set or a sorted set — and `RedisSessionImpl` keeps its per-identity session
 * index in a set, bounding it with exactly one `expire` call.
 */
describe('FakeRedis - TTL applies to every key type', () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  it('answers 1 for a set key, where a string-only TTL answered 0', async () => {
    const r = new FakeRedis()
    await r.sadd('idx:u1', 'sid-a', 'sid-b')

    expect(await r.expire('idx:u1', 60)).toBe(1)
  })

  it('drops the set once its TTL elapses, rather than keeping it for ever', async () => {
    vi.useFakeTimers()
    const r = new FakeRedis()
    await r.sadd('idx:u1', 'sid-a')
    await r.expire('idx:u1', 60)

    vi.advanceTimersByTime(61_000)

    expect(await r.smembers('idx:u1')).toEqual([])
    expect((await r.scan('0', { match: 'idx:*' }))[1]).toEqual([])
  })

  it('drops a sorted set once its TTL elapses', async () => {
    vi.useFakeTimers()
    const r = new FakeRedis()
    await r.zadd('exp:all', 100, 'sid-a')
    expect(await r.expire('exp:all', 60)).toBe(1)

    vi.advanceTimersByTime(61_000)

    expect(await r.zrangebyscore('exp:all', '-inf', '+inf')).toEqual([])
  })

  it('scans sorted-set keys too, which the docstring already claimed', async () => {
    const r = new FakeRedis()
    await r.zadd('exp:all', 1, 'm')

    expect((await r.scan('0', { match: 'exp:*' }))[1]).toEqual(['exp:all'])
  })

  it('still answers 0 for a key of no type at all', async () => {
    expect(await new FakeRedis().expire('nothing', 60)).toBe(0)
  })

  it('drops the TTL on a bare SET, as real Redis does without KEEPTTL', async () => {
    vi.useFakeTimers()
    const r = new FakeRedis()
    await r.set('k', 'v', { ex: 60 })
    await r.set('k', 'v2')

    vi.advanceTimersByTime(61_000)

    expect(await r.get('k')).toBe('v2')
  })

  it('keeps the TTL across an INCR, which is what bounds a rate-limit window', async () => {
    vi.useFakeTimers()
    const r = new FakeRedis()
    await r.set('rl:ip', '0', { ex: 60 })
    await r.incr('rl:ip')

    vi.advanceTimersByTime(61_000)

    expect(await r.get('rl:ip')).toBeNull()
  })
})
