/**
 * Store-contract compliance for the Redis session store.
 *
 * `RedisSessionImpl` was the only shipped `Sessions.Store` never wired to the
 * shared suite, despite `FakeRedis` making it runnable in-process with no
 * infrastructure. Every divergence found in the C1 audit lived in the gap that
 * exemption created.
 */
import { describe } from 'vitest'
import { FakeRedis } from '~/adapters/redis/redis-like'
import { runSessionStoreCompliance } from '~/test/store-compliance'
import { RedisSessionImpl } from '../sessions.redis'

describe('RedisSessionImpl compliance matrix', () => {
  runSessionStoreCompliance(() => new RedisSessionImpl({ redis: new FakeRedis(), prefix: 'c' }))
})
