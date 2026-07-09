/**
 * Redis adapter bundle: stores backed by any `RedisLike.Client`
 * (ioredis, @upstash/redis, or the in-tree FakeRedis for tests). All
 * exports honor the same contracts as the memory adapter so swapping
 * is a one-line change in the `Engine` config.
 */

export { RedisDPoPNonceStore } from './dpop-nonce-store'
export { RedisEvents } from '~/core/events/events.redis'
export { RedisIdempotencyStore } from '~/core/idempotency/idempotency.redis'
export type { RedisLike } from './redis-like'
export { FakeRedis } from './redis-like'
export { RedisSessionStore } from '~/core/sessions/sessions.redis'
