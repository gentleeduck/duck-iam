/** Store-contract compliance for the Redis session store. */
import { describe } from 'vitest'
import { FakeRedis } from '~/core/drivers/redis-like'
import { runSessionStoreCompliance } from '~/test/store-compliance'
import { RedisSessionImpl } from '../sessions.redis'

describe('RedisSessionImpl compliance matrix', () => {
  runSessionStoreCompliance(() => new RedisSessionImpl({ redis: new FakeRedis(), prefix: 'c' }))
})
