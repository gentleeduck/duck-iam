// Re-exported so a consumer can type the limiter they supply. `strict()` refuses to
// boot production without one, so the interface has to be reachable.
export type { Limiter } from '../limiters.types'

import type { RedisLike } from '~/core/drivers/redis-like'
import { AuthError } from '~/core/errors'
import type { Limiter } from '../limiters.types'

/** Past this `now + windowMs` stops being a representable `Date`, and a window this long is a ban. */
const WINDOW_MAX_MS = 8_640_000_000_000

/** Increments, restores the TTL whenever the key has none, and answers `[count, remaining ms]`. */
const INCR_WITH_TTL = `local n = redis.call('INCRBY', KEYS[1], ARGV[1])
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[2])
  ttl = tonumber(ARGV[2])
end
return {n, ttl}`

export namespace RedisLimiter {
  /** The Redis client, window size and limit. */
  export type Cfg<TRedis extends RedisLike.Client = RedisLike.Client> = {
    /** An `@upstash/redis`-shaped client or `FakeRedis`; wrap ioredis and iovalkey with `valkeyAdapter`. */
    redis: TRedis
    /** Max consumed weight per window. Default 10. */
    max?: number
    /** Window size in ms. Default 15 minutes. */
    windowMs?: number
    /** Key namespace prefix. Default `auth:rl`. */
    prefix?: string
  }
}

/**
 * Fixed-window counter: the key's TTL is the window, and `resetAt` is when it runs out.
 *
 * WARN: a client without `eval` gets `INCRBY` then `EXPIRE` as two commands. An `EXPIRE` lost between
 * them leaves a counter that never resets, locking its key out for good, and `resetAt` there is a full
 * window from now rather than the window's end.
 */
export class RedisLimiter<TRedis extends RedisLike.Client = RedisLike.Client> implements Limiter.Me {
  private readonly _redis: TRedis
  private readonly _max: number
  private readonly _windowMs: number
  private readonly _prefix: string

  constructor(cfg: RedisLimiter.Cfg<TRedis>) {
    this._redis = cfg.redis
    this._max = cfg.max ?? 10
    this._windowMs = cfg.windowMs ?? 15 * 60 * 1000
    this._prefix = cfg.prefix ?? 'auth:rl'
    // SECURITY: a NaN `max` makes `count > max` always false, and a `windowMs` that is not a positive number
    // never elapses.
    if (!Number.isFinite(this._max) || this._max < 1 || this._max > Number.MAX_SAFE_INTEGER) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `redisLimiter: max must be a number between 1 and ${Number.MAX_SAFE_INTEGER} (got ${this._max})`,
      })
    }
    if (!Number.isFinite(this._windowMs) || this._windowMs < 1 || this._windowMs > WINDOW_MAX_MS) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `redisLimiter: windowMs must be a number between 1 and ${WINDOW_MAX_MS} (got ${this._windowMs})`,
      })
    }
  }

  /** Compose the bucket key. */
  private _k(key: string): string {
    return `${this._prefix}:${key}`
  }

  /**
   * Adds `weight` to the key's count for this window.
   *
   * PERF: one command whatever the weight. Looping `weight` INCRs instead makes `consume(key, 1e6)`
   * a caller-controlled flood of a million sequential commands, and leaves the count atomic only
   * for a weight of one. A client with no INCRBY still loops, but stops once the budget is gone.
   */
  async consume(key: string, weight = 1): Promise<Limiter.Result> {
    const now0 = Date.now()
    if (typeof key !== 'string' || key.length === 0 || key.length > 1024) {
      return { ok: false, remaining: 0, resetAt: new Date(now0 + this._windowMs) }
    }
    const w = Number.isFinite(weight) ? Math.max(1, Math.floor(weight)) : 1
    const k = this._k(key)
    const ttlSec = Math.max(1, Math.ceil(this._windowMs / 1000))
    let count = 0
    let ttlMs = this._windowMs
    if (this._redis.eval) {
      const out = await this._redis.eval(INCR_WITH_TTL, [k], [w, this._windowMs])
      if (!Array.isArray(out) || !Number.isSafeInteger(out[0]) || !Number.isSafeInteger(out[1])) {
        throw new AuthError('AUTH_MISCONFIGURED', { detail: 'redisLimiter: eval did not answer [count, ttl]' })
      }
      count = out[0]
      ttlMs = out[1]
    } else if (this._redis.incrby) {
      count = await this._redis.incrby(k, w)
      if (count === w) await this._redis.expire(k, ttlSec)
    } else {
      for (let i = 0; i < w; i++) {
        count = await this._redis.incr(k)
        if (i === 0 && count === 1) await this._redis.expire(k, ttlSec)
        if (count > this._max) break
      }
    }
    const resetAt = new Date(Date.now() + ttlMs)
    if (count > this._max) {
      return { ok: false, remaining: 0, resetAt }
    }
    return { ok: true, remaining: Math.max(0, this._max - count), resetAt }
  }

  /** Drop a bucket. Used by tests + explicit unlock paths. */
  async reset(key: string): Promise<void> {
    await this._redis.del(this._k(key))
  }
}

/** Constructs a {@link RedisLimiter}. */
export function redisLimiter<TRedis extends RedisLike.Client = RedisLike.Client>(
  cfg: RedisLimiter.Cfg<TRedis>,
): RedisLimiter<TRedis> {
  return new RedisLimiter(cfg)
}
