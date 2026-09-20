// Re-exported so a consumer can type the limiter they supply. `strict()` refuses to
// boot production without one, so the interface has to be reachable.
export type { Limiter } from '../limiters.types'

import type { RedisLike } from '~/core/drivers/redis-like'
import { AuthError } from '~/core/errors'
import type { Limiter } from '../limiters.types'

/** Past this `now + windowMs` stops being a representable `Date`, and a window this long is a ban. */
const WINDOW_MAX_MS = 8_640_000_000_000

export namespace RedisLimiter {
  export type Cfg<TRedis extends RedisLike.Client = RedisLike.Client> = {
    /** RedisLike client (ioredis, @upstash/redis, or FakeRedis). */
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
 * Fixed-window counter over `INCR + EXPIRE` on the first hit of each window, which is accurate
 * against a single Redis primary. Clustered Redis needs a Lua script for cross-shard accuracy.
 *
 * WARN: `resetAt` is `now + windowMs` on every call, not the key's remaining TTL, so a refusal fourteen
 * minutes into a fifteen-minute window reports a full window left and the `Retry-After` built from it
 * over-states the wait. The budget itself resets correctly - that is the store's TTL - so this misleads
 * a client rather than locking it out, and `MemoryLimiter` reports the true window end. Reading
 * the real one means a `pttl` on `RedisLike.Client`, which every implementer would have to grow, so it
 * is left to a deliberate change rather than added here.
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
    // SECURITY: `consume` bounds the `weight` a caller passes and the `key` it names, and these two -
    // the numbers that decide whether it limits at all - arrived unchecked. `max` non-finite makes
    // `count > NaN` false on every call, so the limiter answers `ok` to an unbounded number of attempts
    // and the brute-force defence `strict()` insists on is simply off. A `windowMs` that is not a
    // positive number never elapses, so the first budget spent is the last: `resetAt` reads
    // `Invalid Date` and the key is locked out until the process restarts.
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
   * One INCRBY establishes the new count, then EXPIRE sets the TTL on the first hit of the window.
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
    if (this._redis.incrby) {
      count = await this._redis.incrby(k, w)
      if (count === w) await this._redis.expire(k, ttlSec)
    } else {
      for (let i = 0; i < w; i++) {
        count = await this._redis.incr(k)
        if (i === 0 && count === 1) await this._redis.expire(k, ttlSec)
        if (count > this._max) break
      }
    }
    const resetAt = new Date(Date.now() + this._windowMs)
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
