/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import type { DPoPNonceStore } from '../../core/transport/dpop'
import type { RedisLike } from './redis-like'

/**
 * Config knobs for `RedisDPoPNonceStore`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface RedisDPoPNonceStoreConfig {
  /** RedisLike client (ioredis, @upstash/redis, or FakeRedis). */
  redis: RedisLike
  /** Key namespace prefix. Default `auth:dpop:jti`. */
  prefix?: string
}

/**
 * Redis-backed `DPoPNonceStore`. Uses `SET NX EX` for atomic
 * across-pod jti-replay protection - the property the memory store
 * cannot provide.
 *
 * Storage shape: `${prefix}:{jti}` = '1' with TTL = `ttlMs / 1000`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class RedisDPoPNonceStore implements DPoPNonceStore {
  private readonly _redis: RedisLike
  private readonly _prefix: string

  constructor(cfg: RedisDPoPNonceStoreConfig) {
    this._redis = cfg.redis
    this._prefix = cfg.prefix ?? 'auth:dpop:jti'
  }

  /** Compose the key for a jti. */
  private _k(jti: string): string {
    return `${this._prefix}:${jti}`
  }

  /**
   * Atomic SET NX EX claim. Returns true on first sight, false when a
   * prior claim is still alive in the freshness window.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async recordSeen(jti: string, ttlMs: number): Promise<boolean> {
    const ex = Math.max(1, Math.ceil(ttlMs / 1000))
    const result = await this._redis.set(this._k(jti), '1', { nx: true, ex })
    return result === 'OK'
  }
}

/**
 * Namespace merge for `RedisDPoPNonceStore`. Co-locates config alongside
 * the class.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace RedisDPoPNonceStore {
  /** Alias for `RedisDPoPNonceStoreConfig`. */
  export type IConfig = RedisDPoPNonceStoreConfig
}
