import { type ValkeyClient, valkeyAdapter } from '~/adapters/valkey/valkey-like'
import { RedisDPoPNonceStore } from './dpop-nonce.redis'

/** {@link RedisDPoPNonceStore}, driven by an ioredis/iovalkey client via {@link valkeyAdapter}. */
export function valkeyDPoPNonceStore(
  cfg: Omit<RedisDPoPNonceStore.Cfg, 'redis'> & { redis: ValkeyClient.Me },
): RedisDPoPNonceStore {
  return new RedisDPoPNonceStore({ ...cfg, redis: valkeyAdapter(cfg.redis) })
}
