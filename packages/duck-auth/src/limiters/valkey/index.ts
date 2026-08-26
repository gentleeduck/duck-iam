// Re-exported so a consumer can type the limiter they supply, same as `limiters/redis`.
export type { Limiter } from '../limiters.types'

import { type ValkeyClient, valkeyAdapter } from '~/adapters/valkey/valkey-like'
import { RedisLimiter } from '../redis'

/** {@link RedisLimiter}, driven by an ioredis/iovalkey client via {@link valkeyAdapter}. */
export function valkeyLimiter(cfg: Omit<RedisLimiter.Cfg, 'redis'> & { redis: ValkeyClient.Me }): RedisLimiter {
  return new RedisLimiter({ ...cfg, redis: valkeyAdapter(cfg.redis) })
}
