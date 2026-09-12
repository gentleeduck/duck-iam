/** The redis-backed stores - they live with their subject in `core/*` - under the public
 *  `@gentleduck/auth/adapters/redis` entry, so swapping backends is one line. */

export { FakeRedis, fakeRedis, type RedisLike } from '~/core/drivers/redis-like'
export { RedisEvents, redisEvents } from '~/core/events/events.redis'
export { type RedisSession, RedisSessionImpl, redisSessionImpl, session } from '~/core/sessions/sessions.redis'
export { RedisDPoPNonceStore, redisDPoPNonceStore } from '~/core/transport/dpop-nonce.redis'
