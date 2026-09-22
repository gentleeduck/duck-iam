/** `limiter-bounds.test.ts` next door bounds `weight` and `key` exhaustively, and hard-codes
 *  `{ max, windowMs }` in every one of its cases. Those two are what decide whether the limiter limits
 *  at all, and both shipped limiters took them on trust. */

import { describe, expect, it } from 'vitest'
import { FakeRedis } from '~/core/drivers/redis-like'
import { AuthMemoryLimiter, RedisLimiter } from '~/limiters'
import type { Limiter } from '~/limiters/limiters.types'

const limiters = [
  { make: (cfg: { max?: number; windowMs?: number }) => new AuthMemoryLimiter(cfg), name: 'AuthMemoryLimiter' },
  {
    make: (cfg: { max?: number; windowMs?: number }) => new RedisLimiter({ ...cfg, redis: new FakeRedis() }),
    name: 'RedisLimiter',
  },
] as const

/** The `detail`, since `AuthError.message` is the bare code and never carries one. */
function refusal(make: () => Limiter.Me): string {
  try {
    make()
  } catch (err) {
    return err instanceof Error && 'meta' in err ? String((err.meta as { detail?: unknown }).detail) : String(err)
  }
  throw new Error('expected the limiter to refuse this config')
}

describe.each(limiters)('$name config bounds', ({ make }) => {
  // `2 ** 53` is `MAX_SAFE_INTEGER + 1` and finite, so it is the only case the ceiling alone catches:
  // both infinities are already refused by the finiteness test, and without it that clause proves nothing.
  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, 0, -1, 2 ** 53])('refuses max %p', (max) => {
    expect(refusal(() => make({ max }))).toContain('max')
  })

  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, 0, -1, 1e16])(
    'refuses windowMs %p',
    (windowMs) => {
      expect(refusal(() => make({ windowMs }))).toContain('windowMs')
    },
  )

  it('accepts the defaults, and still refuses over budget', async () => {
    expect(() => make({})).not.toThrow()
    const limiter = make({ max: 2, windowMs: 60_000 })
    expect((await limiter.consume('k')).ok).toBe(true)
    expect((await limiter.consume('k')).ok).toBe(true)
    expect((await limiter.consume('k')).ok).toBe(false)
  })

  it('answers with a resetAt a caller can build a Retry-After from', async () => {
    const { resetAt } = await make({ max: 1, windowMs: 60_000 }).consume('k')
    expect(Number.isNaN(resetAt.getTime())).toBe(false)
  })
})
