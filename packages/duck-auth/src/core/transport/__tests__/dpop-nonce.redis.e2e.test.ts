/**
 * E2E: RedisDPoPNonceStore against a REAL Redis.
 *
 * Replay protection is the only thing this store does, and it is a claim about
 * two pods that never share memory. Its own docstring says so: "the property the
 * memory store cannot provide". Proving it needs a real server, because
 * `FakeRedis` gives every caller the same in-process `Map`, which makes a passing
 * test say nothing about the deployed behaviour.
 *
 * Skips when DUCKAUTH_E2E_REDIS_URL is unset; `globalSetup` provisions a container
 * when docker is available.
 */
import Redis from 'ioredis'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { type ValkeyClient, valkeyAdapter } from '~/adapters/valkey'
import { dropPrefix, e2ePrefix, redisUrl } from '~/test/e2e-env'
import { RedisDPoPNonceStore } from '../dpop-nonce.redis'

const URL = redisUrl()
const suite = URL ? describe : describe.skip

suite('E2E RedisDPoPNonceStore (real Redis)', () => {
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

  /** A store as a separate pod would construct it: same Redis, own instance. */
  function pod(): RedisDPoPNonceStore {
    return new RedisDPoPNonceStore({ prefix, redis: valkeyAdapter(raw as unknown as ValkeyClient.Me) })
  }

  const jti = (label: string) => `${label}-${e2ePrefix()}`

  it('accepts a jti once and rejects the replay', async () => {
    const store = pod()
    const id = jti('once')
    expect(await store.recordSeen(id, 60_000)).toBe(true)
    expect(await store.recordSeen(id, 60_000)).toBe(false)
  })

  it('rejects a replay presented to a different pod', async () => {
    // The load-balanced case: the attacker retries the captured proof and lands
    // on another instance. Shared state is what stops it.
    const id = jti('cross-pod')
    expect(await pod().recordSeen(id, 60_000)).toBe(true)
    expect(await pod().recordSeen(id, 60_000)).toBe(false)
  })

  it('admits exactly one of a burst of simultaneous replays', async () => {
    const store = pod()
    const id = jti('burst')
    const results = await Promise.all(Array.from({ length: 20 }, () => store.recordSeen(id, 60_000)))
    expect(results.filter(Boolean)).toHaveLength(1)
  })

  it('forgets a jti once its freshness window lapses', async () => {
    // Deliberate: the store only guards the DPoP freshness window, and the proof
    // is independently rejected on `iat` age once that window passes.
    const store = pod()
    const id = jti('lapse')
    expect(await store.recordSeen(id, 1000)).toBe(true)
    await new Promise((r) => setTimeout(r, 1300))
    expect(await store.recordSeen(id, 1000)).toBe(true)
  })

  it('distinct jtis do not collide', async () => {
    const store = pod()
    expect(await store.recordSeen(jti('a'), 60_000)).toBe(true)
    expect(await store.recordSeen(jti('b'), 60_000)).toBe(true)
  })
})
