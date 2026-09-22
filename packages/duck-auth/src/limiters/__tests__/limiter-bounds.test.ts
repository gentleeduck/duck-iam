import { describe, expect, it } from 'vitest'
import { AuthMemoryLimiter } from '..'

describe('AuthMemoryLimiter - input bounds', () => {
  describe('weight floor', () => {
    it('default weight = 1 (control case)', async () => {
      const l = new AuthMemoryLimiter({ max: 3, windowMs: 60_000 })
      expect((await l.consume('k')).ok).toBe(true)
      expect((await l.consume('k')).ok).toBe(true)
      expect((await l.consume('k')).ok).toBe(true)
      expect((await l.consume('k')).ok).toBe(false) // 4th
    })

    it('negative weight does NOT decrement the counter (limiter-bypass defense)', async () => {
      const l = new AuthMemoryLimiter({ max: 3, windowMs: 60_000 })
      // Burn the budget.
      await l.consume('k')
      await l.consume('k')
      await l.consume('k')
      expect((await l.consume('k')).ok).toBe(false) // exhausted

      // A malicious caller tries to "give back" budget.
      const r = await l.consume('k', -100)
      // The consume must NOT have decreased the counter - still exhausted.
      expect(r.ok).toBe(false)

      // Subsequent normal call still rejected.
      expect((await l.consume('k')).ok).toBe(false)
    })

    it('zero weight is floored to 1 (still consumes)', async () => {
      const l = new AuthMemoryLimiter({ max: 2, windowMs: 60_000 })
      const r1 = await l.consume('k', 0)
      expect(r1.ok).toBe(true)
      const r2 = await l.consume('k', 0)
      expect(r2.ok).toBe(true)
      const r3 = await l.consume('k', 0)
      expect(r3.ok).toBe(false)
    })

    it('NaN weight is floored to 1', async () => {
      const l = new AuthMemoryLimiter({ max: 2, windowMs: 60_000 })
      expect((await l.consume('k', NaN)).ok).toBe(true)
      expect((await l.consume('k', NaN)).ok).toBe(true)
      expect((await l.consume('k', NaN)).ok).toBe(false)
    })

    it('Infinity weight is floored to 1 (does NOT immediately exhaust)', async () => {
      const l = new AuthMemoryLimiter({ max: 5, windowMs: 60_000 })
      const r = await l.consume('k', Infinity)
      expect(r.ok).toBe(true)
      expect(r.remaining).toBe(4) // consumed 1, not Infinity
    })

    it('large positive weight is honored', async () => {
      const l = new AuthMemoryLimiter({ max: 100, windowMs: 60_000 })
      const r = await l.consume('k', 50)
      expect(r.ok).toBe(true)
      expect(r.remaining).toBe(50)
    })
  })

  describe('key bounds', () => {
    it('refuses empty key (fail-closed)', async () => {
      const l = new AuthMemoryLimiter({ max: 10, windowMs: 60_000 })
      expect((await l.consume('')).ok).toBe(false)
    })

    it('refuses oversize key (>1024 chars)', async () => {
      const l = new AuthMemoryLimiter({ max: 10, windowMs: 60_000 })
      const big = 'k'.repeat(1025)
      expect((await l.consume(big)).ok).toBe(false)
    })

    it('accepts 1024-char key at the cap (boundary)', async () => {
      const l = new AuthMemoryLimiter({ max: 10, windowMs: 60_000 })
      const sized = 'k'.repeat(1024)
      expect((await l.consume(sized)).ok).toBe(true)
    })

    it('refuses non-string key without crashing', async () => {
      const l = new AuthMemoryLimiter({ max: 10, windowMs: 60_000 })
      expect((await l.consume(null as unknown as string)).ok).toBe(false)
      expect((await l.consume(42 as unknown as string)).ok).toBe(false)
    })

    it('bogus keys do NOT consume real-key budget', async () => {
      const l = new AuthMemoryLimiter({ max: 3, windowMs: 60_000 })
      // 100 attempts on bogus keys.
      for (let i = 0; i < 100; i++) {
        await l.consume('')
        await l.consume('x'.repeat(2000))
      }
      // Real key budget is untouched.
      expect((await l.consume('k')).ok).toBe(true)
      expect((await l.consume('k')).ok).toBe(true)
      expect((await l.consume('k')).ok).toBe(true)
      expect((await l.consume('k')).ok).toBe(false)
    })
  })

  describe('reset still works for valid keys', () => {
    it('reset clears the bucket', async () => {
      const l = new AuthMemoryLimiter({ max: 1, windowMs: 60_000 })
      await l.consume('k')
      expect((await l.consume('k')).ok).toBe(false)
      await l.reset('k')
      expect((await l.consume('k')).ok).toBe(true)
    })
  })
})

describe('expired buckets do not stay resident', () => {
  // The bucket key is caller-shaped - an email for the password guard, an identity id elsewhere - so the
  // set of keys is whatever a request can name. Nothing ever removed one, so a flood of distinct
  // addresses grew this map for as long as the process lived, and `strict()` accepts this limiter in
  // production: it only refuses the noop one.
  const bucketCount = (limiter: AuthMemoryLimiter): number =>
    (limiter as unknown as { _buckets: Map<string, unknown> })._buckets.size

  it('drops them once the map has grown, rather than holding every key ever seen', async () => {
    const limiter = new AuthMemoryLimiter({ max: 5, windowMs: 10 })
    for (let i = 0; i < 2000; i++) await limiter.consume(`attacker-${i}@x.com`)
    expect(bucketCount(limiter)).toBeGreaterThan(0)

    await new Promise((resolve) => setTimeout(resolve, 30))
    await limiter.consume('someone-else@x.com')

    expect(bucketCount(limiter)).toBeLessThan(2000)
  })

  it('keeps a live bucket through the sweep, so nobody gets their budget back early', async () => {
    const limiter = new AuthMemoryLimiter({ max: 2, windowMs: 60_000 })
    await limiter.consume('victim@x.com')
    await limiter.consume('victim@x.com')
    // Enough distinct keys to cross the sweep threshold while the victim's window is still open.
    for (let i = 0; i < 2000; i++) await limiter.consume(`filler-${i}@x.com`)

    expect(await limiter.consume('victim@x.com')).toMatchObject({ ok: false })
  })

  it('still refuses over budget within one window', async () => {
    const limiter = new AuthMemoryLimiter({ max: 2, windowMs: 60_000 })
    expect(await limiter.consume('a')).toMatchObject({ ok: true })
    expect(await limiter.consume('a')).toMatchObject({ ok: true })
    expect(await limiter.consume('a')).toMatchObject({ ok: false })
  })
})
