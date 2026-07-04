import { describe, expect, it } from 'vitest'
import { RedisDPoPNonceStore } from '../dpop-nonce-store'
import { FakeRedis } from '../redis-like'

describe('RedisDPoPNonceStore', () => {
  it('first sight returns true, immediate replay returns false', async () => {
    const redis = new FakeRedis()
    const store = new RedisDPoPNonceStore({ redis, prefix: 'test:jti' })
    expect(await store.recordSeen('jti-1', 60_000)).toBe(true)
    expect(await store.recordSeen('jti-1', 60_000)).toBe(false)
  })

  it('expired entries free up the jti for reuse', async () => {
    const redis = new FakeRedis()
    const store = new RedisDPoPNonceStore({ redis, prefix: 'test:jti' })
    await store.recordSeen('jti-1', 1000)
    await new Promise((r) => setTimeout(r, 1100))
    expect(await store.recordSeen('jti-1', 60_000)).toBe(true)
  })

  it('different jtis are independent', async () => {
    const redis = new FakeRedis()
    const store = new RedisDPoPNonceStore({ redis, prefix: 'test:jti' })
    expect(await store.recordSeen('a', 60_000)).toBe(true)
    expect(await store.recordSeen('b', 60_000)).toBe(true)
    expect(await store.recordSeen('a', 60_000)).toBe(false)
  })
})
