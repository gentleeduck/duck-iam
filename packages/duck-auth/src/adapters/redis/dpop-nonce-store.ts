import type { DPoPVerifier } from '~/core/transport/dpop.transport'
import type { RedisLike } from './redis-like'

export namespace RedisDPoPNonceStore {
  /** Config knobs for {@link RedisDPoPNonceStore}. */
  export type Config<TRedis extends RedisLike.Client = RedisLike.Client> = {
    /** RedisLike client (ioredis, @upstash/redis, or FakeRedis). */
    redis: TRedis
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
export class RedisDPoPNonceStore<TRedis extends RedisLike.Client = RedisLike.Client>
  implements DPoPVerifier.NonceStore
{
  private readonly _redis: TRedis
  private readonly _prefix: string

  constructor(cfg: RedisDPoPNonceStore.Config<TRedis>) {
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
