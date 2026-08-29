/**
 * E2E: `valkeyDPoPNonceStore` against a REAL server.
 *
 * `dpop-nonce.redis.e2e.test.ts` covers `RedisDPoPNonceStore` itself; this proves
 * `valkeyDPoPNonceStore` wires a raw ioredis client into a working store, on the
 * one property that only a real server can show: cross-connection replay rejection.
 *
 * Skips when DUCKAUTH_E2E_REDIS_URL is unset; `globalSetup` provisions a container
 * when docker is available.
 */
import Redis from 'ioredis'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { valkeyDPoPNonceStore } from '~/core/transport/dpop-nonce.valkey'
import { dropPrefix, e2ePrefix, redisUrl } from '~/test/e2e-env'

const URL = redisUrl()
const suite = URL ? describe : describe.skip

suite('E2E valkeyDPoPNonceStore (real server)', () => {
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

  const jti = (label: string) => `${label}-${e2ePrefix()}`

  it('accepts a jti once and rejects the replay', async () => {
    const store = valkeyDPoPNonceStore({ prefix, redis: raw })
    const id = jti('once')
    expect(await store.recordSeen(id, 60_000)).toBe(true)
    expect(await store.recordSeen(id, 60_000)).toBe(false)
  })

  it('rejects a replay presented to a different connection', async () => {
    const id = jti('cross')
    expect(await valkeyDPoPNonceStore({ prefix, redis: raw }).recordSeen(id, 60_000)).toBe(true)
    expect(await valkeyDPoPNonceStore({ prefix, redis: raw }).recordSeen(id, 60_000)).toBe(false)
  })
})
