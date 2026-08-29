/**
 * E2E: `valkeyIdempotency` against a REAL server.
 *
 * `idempotency.redis.e2e.test.ts` covers `RedisIdempotency`'s `SET NX EX` claim
 * atomicity. This proves `valkeyIdempotency` wires a raw ioredis client into a
 * working `handle()` facet: the second caller gets the first caller's response,
 * not a fresh execution.
 *
 * Skips when DUCKAUTH_E2E_REDIS_URL is unset; `globalSetup` provisions a container
 * when docker is available.
 */
import Redis from 'ioredis'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { valkeyIdempotency } from '~/core/idempotency/idempotency.valkey'
import { dropPrefix, e2ePrefix, redisUrl } from '~/test/e2e-env'

const URL = redisUrl()
const suite = URL ? describe : describe.skip

suite('E2E valkeyIdempotency (real server)', () => {
  let raw: Redis
  let prefix: string

  beforeAll(async () => {
    raw = new Redis(URL as string, { lazyConnect: true, maxRetriesPerRequest: 2 })
    await raw.connect()
    prefix = e2ePrefix()
  })

  afterAll(async () => {
    if (raw) {
      await dropPrefix(raw, prefix)
      await raw.quit()
    }
  })

  it('the second call within the window replays the first response', async () => {
    const idem = valkeyIdempotency({ prefix, redis: raw })
    const key = `key-${e2ePrefix()}`
    const first = await idem.handle(key, {}, async () => ({ status: 200, body: 'first', createdAt: new Date() }))
    const second = await idem.handle(key, {}, async () => ({ status: 200, body: 'second', createdAt: new Date() }))
    expect(first.body).toBe('first')
    expect(second.body).toBe('first')
  })

  it('exactly one of many concurrent claims executes', async () => {
    const idem = valkeyIdempotency({ prefix, redis: raw })
    const key = `key-burst-${e2ePrefix()}`
    let executions = 0
    const results = await Promise.all(
      Array.from({ length: 20 }, () =>
        idem.handle(key, {}, async () => {
          executions++
          return { status: 200, body: 'ran', createdAt: new Date() }
        }),
      ),
    )
    expect(executions).toBe(1)
    expect(results.every((r) => r.body === 'ran')).toBe(true)
  })
})
