/** E2E: `RedisPasskeyChallengeStore` against a real server. */
import Redis from 'ioredis'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { valkeyAdapter } from '~/adapters/valkey'
import { dropPrefix, e2ePrefix, redisUrl } from '~/test/e2e-env'
import { RedisPasskeyChallengeStore } from '../internal/challenge-store.redis'

const URL = redisUrl()
const suite = URL ? describe : describe.skip

suite('E2E RedisPasskeyChallengeStore (real server)', () => {
  let raw: Redis
  let prefix: string

  beforeAll(async () => {
    raw = new Redis(URL, { lazyConnect: true, maxRetriesPerRequest: 2 })
    await raw.connect()
    prefix = e2ePrefix()
  })

  afterAll(async () => {
    if (raw) {
      await dropPrefix(raw, prefix)
      await raw.quit()
    }
  })

  /** A store as another node would build it: same server, own instance. */
  const node = () => new RedisPasskeyChallengeStore({ prefix, redis: valkeyAdapter(raw) })
  const key = (label: string) => `${label}-${e2ePrefix()}`

  it('hands a challenge back once, to whichever node asks for it', async () => {
    const k = key('once')
    await node().put(k, 'c1', 60_000)
    await expect(node().take(k)).resolves.toBe('c1')
    await expect(node().take(k)).rejects.toMatchObject({ code: 'AUTH_CREDENTIAL_NOT_FOUND' })
  })

  it('admits exactly one of a burst of simultaneous takes', async () => {
    const k = key('burst')
    await node().put(k, 'c1', 60_000)
    const results = await Promise.allSettled(Array.from({ length: 20 }, () => node().take(k)))
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1)
  })

  it('replaces the live challenge on a second put', async () => {
    const k = key('overwrite')
    await node().put(k, 'c1', 60_000)
    await node().put(k, 'c2', 60_000)
    await expect(node().take(k)).resolves.toBe('c2')
  })

  it('leaves expiry to the server, rounding a sub-second lifetime up to a second', async () => {
    const k = key('ttl')
    await node().put(k, 'c1', 60_000)
    const ttl = await raw.pttl(`${prefix}:${k}`)
    expect(ttl).toBeGreaterThan(59_000)
    expect(ttl).toBeLessThanOrEqual(60_000)
    await node().put(k, 'c2', 200)
    expect(await raw.pttl(`${prefix}:${k}`)).toBeGreaterThan(200)
  })

  it('refuses a key that was never put', async () => {
    await expect(node().take(key('never'))).rejects.toMatchObject({ code: 'AUTH_CREDENTIAL_NOT_FOUND' })
  })
})
