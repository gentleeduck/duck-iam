/** E2E: `valkeyAdapter` against a REAL server. */
import Redis from 'ioredis'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { RedisSessionImpl } from '~/core/sessions/sessions.redis'
import { dropPrefix, e2ePrefix, redisUrl } from '~/test/e2e-env'
import { runSessionStoreCompliance } from '~/test/store-compliance'
import { type ValkeyClient, valkeyAdapter } from '../index'

const URL = redisUrl()
const suite = URL ? describe : describe.skip

suite('E2E valkeyAdapter (real server)', () => {
  let raw: Redis
  let prefix: string
  let client: ReturnType<typeof valkeyAdapter>

  beforeAll(async () => {
    raw = new Redis(URL as string, { lazyConnect: true, maxRetriesPerRequest: 2 })
    await raw.connect()
    prefix = e2ePrefix()
    // ioredis IS the variadic shape this adapter translates into.
    client = valkeyAdapter(raw as unknown as ValkeyClient.Me)
  })

  afterAll(async () => {
    if (raw) {
      await dropPrefix(raw, prefix)
      await raw.quit()
    }
  })

  const key = (label: string) => `${prefix}:${label}`

  describe('the translation the adapter exists for', () => {
    it('set with { ex } actually reaches the server as a TTL', async () => {
      // The headline bug: a dropped `EX` leaves an immortal key and nothing fails.
      const k = key('ex')
      await client.set(k, 'v', { ex: 60 })
      const ttl = await raw.ttl(k)
      expect(ttl).toBeGreaterThan(0)
      expect(ttl).toBeLessThanOrEqual(60)
    })

    it('a plain set leaves no TTL, so the assertion above is meaningful', async () => {
      const k = key('no-ex')
      await client.set(k, 'v')
      expect(await raw.ttl(k)).toBe(-1)
    })

    it('set with { nx } is genuinely conditional', async () => {
      // A dropped `NX` makes every caller a winner, which silently defeats both
      // the idempotency claim and DPoP replay protection.
      const k = key('nx')
      expect(await client.set(k, 'first', { nx: true })).toBe('OK')
      expect(await client.set(k, 'second', { nx: true })).toBeNull()
      expect(await raw.get(k)).toBe('first')
    })

    it('set with both { ex, nx } applies both', async () => {
      const k = key('ex-nx')
      expect(await client.set(k, 'v', { ex: 60, nx: true })).toBe('OK')
      expect(await raw.ttl(k)).toBeGreaterThan(0)
      expect(await client.set(k, 'other', { ex: 60, nx: true })).toBeNull()
    })

    it('the TTL is real: the key is gone once it lapses', async () => {
      const k = key('ex-lapse')
      await client.set(k, 'v', { ex: 1 })
      await new Promise((r) => setTimeout(r, 1300))
      expect(await client.get(k)).toBeNull()
    })
  })

  describe('the rest of the surface', () => {
    it('get returns null for a missing key', async () => {
      expect(await client.get(key('absent'))).toBeNull()
    })

    it('del reports how many keys it removed', async () => {
      await client.set(key('d1'), '1')
      await client.set(key('d2'), '1')
      expect(await client.del(key('d1'), key('d2'), key('never-existed'))).toBe(2)
    })

    it('expire sets a TTL on a live key and reports failure on a missing one', async () => {
      const k = key('expire')
      await client.set(k, 'v')
      expect(await client.expire(k, 60)).toBe(1)
      expect(await raw.ttl(k)).toBeGreaterThan(0)
      expect(await client.expire(key('expire-absent'), 60)).toBe(0)
    })

    it('incr counts up from a missing key', async () => {
      const k = key('incr')
      expect(await client.incr(k)).toBe(1)
      expect(await client.incr(k)).toBe(2)
    })

    it('sadd / srem / smembers round-trip a set', async () => {
      const k = key('set')
      expect(await client.sadd(k, 'a', 'b', 'c')).toBe(3)
      expect((await client.smembers(k)).sort()).toEqual(['a', 'b', 'c'])
      expect(await client.srem(k, 'b')).toBe(1)
      expect((await client.smembers(k)).sort()).toEqual(['a', 'c'])
      expect(await client.smembers(key('set-absent'))).toEqual([])
    })
  })

  describe('a real store driven entirely through the adapter', () => {
    // The end the translation exists to serve: if any command is mistranslated,
    // the shared session contract stops holding.
    runSessionStoreCompliance(() => new RedisSessionImpl({ prefix: `${prefix}:store:${e2ePrefix()}`, redis: client }))
  })
})
