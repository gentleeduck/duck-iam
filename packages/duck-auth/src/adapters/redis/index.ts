/**
 * Redis adapter bundle. The store implementations now live with their
 * subject in `core/*`; this barrel re-exports them under the public
 * `@gentleduck/auth/adapters/redis` entry so swapping backends stays a
 * one-line change. `RedisLike`/`FakeRedis` (the shared client contract +
 * test double) are the only impls that live here.
 */

export { RedisEvents } from '~/core/events/events.redis'
export { RedisIdempotencyStore } from '~/core/idempotency/idempotency.redis'
export { RedisSessionStore } from '~/core/sessions/sessions.redis'
export { RedisDPoPNonceStore } from '~/core/transport/dpop-nonce.redis'
export type { RedisLike } from './redis-like'
export { FakeRedis } from './redis-like'
