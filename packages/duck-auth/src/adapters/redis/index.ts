/**
 * Redis adapter bundle: stores backed by any `RedisLike.IClient`
 * (ioredis, @upstash/redis, or the in-tree FakeRedis for tests). All
 * exports honor the same contracts as the memory adapter so swapping
 * is a one-line change in the `AuthRoot` config.
 */

export { RedisDPoPNonceStore } from './dpop-nonce-store'
export { RedisEvents } from './events'
export { RedisIdempotencyStore } from './idempotency-store'
export { RedisLimiter } from './limiter'
export type { RedisLike } from './redis-like'
export { FakeRedis } from './redis-like'
export { RedisSessionStore } from './session-store'
