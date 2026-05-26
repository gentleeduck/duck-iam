/**
 * @packageDocumentation
 * Redis adapter bundle: stores backed by any `RedisLike` client (ioredis,
 * @upstash/redis, or the in-tree FakeRedis for tests). All exports honor
 * the same contracts as the memory adapter so swapping is a one-line
 * change in the `AuthRoot` config.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

export { RedisIdempotencyStore, type RedisIdempotencyStoreConfig } from './idempotency-store'
export { RedisLimiter, type RedisLimiterConfig } from './limiter'
export type { RedisLike } from './redis-like'
export { FakeRedis } from './redis-like'
export { RedisSessionStore, type RedisSessionStoreConfig } from './session-store'
