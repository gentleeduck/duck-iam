import type { DPoPVerifier } from '../../core/transport/dpop'
import type { RedisLike } from './redis-like'

/**
 * Public surface for the Redis-backed DPoP nonce store. Every type
 * lives inside the namespace.
 */
export namespace RedisDPoPNonceStore {
  /** Config knobs for {@link RedisDPoPNonceStore}. */
  export interface IConfig {
    /** RedisLike client (ioredis, @upstash/redis, or FakeRedis). */
    redis: RedisLike.IClient
    /** Key namespace prefix. Default `auth:dpop:jti`. */
    prefix?: string
  }
}

/**
 * Redis-backed `DPoPVerifier.INonceStore`. Uses `SET NX EX` for atomic
 * across-pod jti-replay protection - the property the memory store
 * cannot provide.
 *
 * Storage shape: `${prefix}:{jti}` = '1' with TTL = `ttlMs / 1000`.
 */
export class RedisDPoPNonceStore implements DPoPVerifier.INonceStore {
  private readonly _redis: RedisLike.IClient
  private readonly _prefix: string

  constructor(cfg: RedisDPoPNonceStore.IConfig) {
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
   */
  async recordSeen(jti: string, ttlMs: number): Promise<boolean> {
    const ex = Math.max(1, Math.ceil(ttlMs / 1000))
    const result = await this._redis.set(this._k(jti), '1', { nx: true, ex })
    return result === 'OK'
  }
}
