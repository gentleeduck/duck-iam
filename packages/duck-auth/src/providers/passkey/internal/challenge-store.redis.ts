import type { RedisLike } from '~/core/drivers/redis-like'
import { AuthError } from '~/core/errors'
import type { Passkey } from '../passkey.types'

export namespace RedisPasskeyChallengeStore {
  export type Cfg<TRedis extends RedisLike.Client = RedisLike.Client> = {
    /** An ioredis, @upstash/redis or FakeRedis client. */
    redis: TRedis
    /** Default `auth:passkey:challenge`. */
    prefix?: string
  }
}

/** Shared across a fleet, which the memory store cannot be: a challenge the memory store consumes on
 *  one node stays live on every other, which is a replay window for the whole TTL. */
export class RedisPasskeyChallengeStore<TRedis extends RedisLike.Client = RedisLike.Client>
  implements Passkey.ChallengeStore
{
  private readonly _redis: TRedis
  private readonly _prefix: string

  constructor(cfg: RedisPasskeyChallengeStore.Cfg<TRedis>) {
    this._redis = cfg.redis
    this._prefix = cfg.prefix ?? 'auth:passkey:challenge'
  }

  private _k(key: string): string {
    return `${this._prefix}:${key}`
  }

  /** Overwrites any prior entry: one challenge is live per key at a time. The TTL is what expires it,
   *  so there is no sweep to do and no non-finite `expiresAt` to slip past a comparison. */
  async put(key: string, challenge: string, ttlMs: number): Promise<void> {
    await this._redis.set(this._k(key), challenge, { ex: Math.max(1, Math.ceil(ttlMs / 1000)) })
  }

  /** SECURITY: `DEL` is the claim, not the read. Concurrent takes all see the same challenge, and only
   *  the one whose `DEL` actually removed a key may use it, so the ceremony stays single-use across the
   *  fleet rather than per node. */
  async take(key: string): Promise<string> {
    const k = this._k(key)
    const challenge = await this._redis.get(k)
    if (challenge === null) throw new AuthError('AUTH_CREDENTIAL_NOT_FOUND')
    if ((await this._redis.del(k)) === 0) throw new AuthError('AUTH_CREDENTIAL_NOT_FOUND')
    return challenge
  }
}

/** Redis-backed passkey challenge store, shared across a fleet. */
export function redisPasskeyChallengeStore<TRedis extends RedisLike.Client = RedisLike.Client>(
  cfg: RedisPasskeyChallengeStore.Cfg<TRedis>,
): RedisPasskeyChallengeStore<TRedis> {
  return new RedisPasskeyChallengeStore(cfg)
}
