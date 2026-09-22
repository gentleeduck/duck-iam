import type { RedisLike } from '~/core/drivers/redis-like'
import type { DPoPVerifier } from './dpop.transport'

export namespace RedisDPoPNonceStore {
  export type Cfg<TRedis extends RedisLike.Client = RedisLike.Client> = {
    /** An ioredis, @upstash/redis or FakeRedis client. */
    redis: TRedis
    /** Default `auth:dpop:jti`. */
    prefix?: string
  }
}

/** `SET NX EX` makes jti-replay protection atomic across pods, which the memory store cannot do. */
export class RedisDPoPNonceStore<TRedis extends RedisLike.Client = RedisLike.Client>
  implements DPoPVerifier.NonceStore
{
  private readonly _redis: TRedis
  private readonly _prefix: string

  constructor(cfg: RedisDPoPNonceStore.Cfg<TRedis>) {
    this._redis = cfg.redis
    this._prefix = cfg.prefix ?? 'auth:dpop:jti'
  }

  private _k(jti: string): string {
    return `${this._prefix}:${jti}`
  }

  /** `true` on first sight, `false` while a prior claim is still alive in the freshness window. */
  async recordSeen(jti: string, ttlMs: number): Promise<boolean> {
    const ex = Math.max(1, Math.ceil(ttlMs / 1000))
    const result = await this._redis.set(this._k(jti), '1', { nx: true, ex })
    return result === 'OK'
  }
}

/** Redis-backed DPoP nonce store, shared across a fleet. */
export function redisDPoPNonceStore<TRedis extends RedisLike.Client = RedisLike.Client>(
  cfg: RedisDPoPNonceStore.Cfg<TRedis>,
): RedisDPoPNonceStore<TRedis> {
  return new RedisDPoPNonceStore(cfg)
}
