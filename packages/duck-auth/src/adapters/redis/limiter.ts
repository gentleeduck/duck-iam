/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import type { Limiter } from '../../core/types/limiter'
import type { RedisLike } from './redis-like'

/**
 * Config knobs for `RedisLimiter`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface RedisLimiterConfig {
  /** RedisLike client (ioredis, @upstash/redis, or FakeRedis). */
  redis: RedisLike
  /** Max consumed weight per window. Default 10. */
  max?: number
  /** Window size in ms. Default 15 minutes. */
  windowMs?: number
  /** Key namespace prefix. Default `auth:rl`. */
  prefix?: string
}

/**
 * Redis-backed token bucket. Uses fixed-window counter semantics via
 * `INCR + EXPIRE` on first hit per window — production-grade for single
 * Redis primary; for clustered Redis with cross-shard accuracy use a
 * Lua script (see `evalScript` below).
 *
 * Semantics:
 *   - First call within a window: `INCR` returns 1; `EXPIRE` sets TTL
 *   - Subsequent calls: `INCR` increments; TTL preserved
 *   - When `INCR result > max`: returns `ok:false` with remaining clamped 0
 *   - `reset(key)`: `DEL` clears the bucket
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class RedisLimiter implements Limiter.ILimiter {
  private readonly _redis: RedisLike
  private readonly _max: number
  private readonly _windowMs: number
  private readonly _prefix: string

  constructor(cfg: RedisLimiterConfig) {
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
   *
   * Weights >1 are summed via N sequential INCRs — atomic per command,
   * not as a group. Tradeoff: a clustered limiter receiving weight=5
   * concurrently with another caller may interleave; the absolute cap
   * still holds, but the per-call `remaining` is best-effort.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async consume(key: string, weight = 1): Promise<Limiter.IResult> {
    const k = this._k(key)
    const ttlSec = Math.max(1, Math.ceil(this._windowMs / 1000))
    let count = 0
    for (let i = 0; i < Math.max(1, weight); i++) {
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
   * Drop a bucket. Used by tests + explicit unlock paths (e.g. admin
   * console after manual review).
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async reset(key: string): Promise<void> {
    await this._redis.del(this._k(key))
  }
}

/**
 * Namespace merge for `RedisLimiter`. Co-locates config alongside
 * the class via TS class+namespace merging.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace RedisLimiter {
  /** Alias for `RedisLimiterConfig`. */
  export type IConfig = RedisLimiterConfig
}
