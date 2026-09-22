import { type ValkeyClient, valkeyAdapter } from '~/core/drivers/valkey-like'
import type { Idempotency } from '~/core/idempotency/idempotency.types'
import { IdempotencyImpl } from './idempotency'
import { RedisIdempotency } from './idempotency.redis'

/** `redisIdempotency`, driven by an ioredis/iovalkey client via {@link valkeyAdapter}. */
export function valkeyIdempotency(
  cfg: Omit<RedisIdempotency.Cfg, 'redis'> & { redis: ValkeyClient.Me } & Partial<Idempotency.Cfg>,
): IdempotencyImpl {
  return new IdempotencyImpl(new RedisIdempotency({ ...cfg, redis: valkeyAdapter(cfg.redis) }), cfg)
}
