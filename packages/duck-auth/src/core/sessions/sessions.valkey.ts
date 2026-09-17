import { type ValkeyClient, valkeyAdapter } from '~/core/drivers/valkey-like'
import { type RedisSession, RedisSessionImpl } from './sessions.redis'

/** `redis` never enters subscriber mode, so it can be shared with `valkeyDPoPNonceStore` or the `cmd`
 *  side of `valkeyEvents`. */
export function valkeySessionImpl(cfg: Omit<RedisSession.Cfg, 'redis'> & { redis: ValkeyClient.Me }): RedisSessionImpl {
  return new RedisSessionImpl({ ...cfg, redis: valkeyAdapter(cfg.redis) })
}
