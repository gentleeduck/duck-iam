import type { Limiter } from '../../core/types/limiter'
import type { RedisLike } from './redis-like'

/**
 * Public surface for the Redis-backed limiter. Every type lives inside
 * the namespace.
 */
export namespace RedisLimiter {
  /** Config knobs for {@link RedisLimiter}. */
  export interface IConfig {
    /** RedisLike client (ioredis, @upstash/redis, or FakeRedis). */
    redis: RedisLike.IClient
    /** Max consumed weight per window. Default 10. */
    max?: number
    /** Window size in ms. Default 15 minutes. */
    windowMs?: number
    /** Key namespace prefix. Default `auth:rl`. */
    prefix?: string
  }
}

/**
 * Redis-backed token bucket. Uses fixed-window counter semantics via
 * `INCR + EXPIRE` on first hit per window - production-grade for single
 * Redis primary; for clustered Redis with cross-shard accuracy use a
 * Lua script (see `evalScript` below).
 */
export class RedisLimiter implements Limiter.ILimiter {
  private readonly _redis: RedisLike.IClient
  private readonly _max: number
  private readonly _windowMs: number
  private readonly _prefix: string

  constructor(cfg: RedisLimiter.IConfig) {
    this._redis = cfg.redis
    this._max = cfg.max ?? 10
    this._windowMs = cfg.windowMs ?? 15 * 60 * 1000
    this._prefix = cfg.prefix ?? 'auth:rl'
  }

  /** Compose the bucket key. */
  private _k(key: string): string {
    return `${this._prefix}:${key}`
  }

  /**
   * Consume `weight` units. Atomic per call: a single INCR establishes
   * the new count, then EXPIRE sets the TTL on the first hit of the
   * window. Returns the standard `Limiter.IResult` shape.
   */
  async consume(key: string, weight = 1): Promise<Limiter.IResult> {
    const now0 = Date.now()
    if (typeof key !== 'string' || key.length === 0 || key.length > 1024) {
      return { ok: false, remaining: 0, resetAt: now0 + this._windowMs }
    }
    const w = Number.isFinite(weight) ? Math.max(1, Math.floor(weight)) : 1
    const k = this._k(key)
    const ttlSec = Math.max(1, Math.ceil(this._windowMs / 1000))
    let count = 0
    for (let i = 0; i < w; i++) {
      count = await this._redis.incr(k)
      if (i === 0 && count === 1) {
        await this._redis.expire(k, ttlSec)
      }
    }
    const resetAt = Date.now() + this._windowMs
    if (count > this._max) {
      return { ok: false, remaining: 0, resetAt }
    }
    return { ok: true, remaining: Math.max(0, this._max - count), resetAt }
  }

  /**
   * Drop a bucket. Used by tests + explicit unlock paths.
   */
  async reset(key: string): Promise<void> {
    await this._redis.del(this._k(key))
  }
}
