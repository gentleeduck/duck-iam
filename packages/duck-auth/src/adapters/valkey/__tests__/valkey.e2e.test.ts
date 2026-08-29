/**
 * E2E: `valkeyAdapter` against a REAL server.
 *
 * This adapter had no tests at all, which is the worst place for that to be true.
 * Its own docblock states the failure it exists to prevent: an ioredis-style
 * client passed straight through takes `set` options variadically, so an object
 * `{ ex, nx }` is dropped on the floor. The write still succeeds, so nothing
 * throws; the key simply never expires and the conditional write is not
 * conditional. A session that outlives its TTL and an idempotency claim that
 * admits every caller both look like success.
 *
 * Only a real server can show it. An in-memory double is written against the
 * object shape, so it "passes" precisely when the translation is broken.
 *
 * Valkey speaks the Redis protocol and `iovalkey` mirrors ioredis' variadic
 * surface, so ioredis is used here as the stand-in client: what is under test is
 * the argument translation, not the driver.
 *
 * Skips when DUCKAUTH_E2E_REDIS_URL is unset; `globalSetup` provisions a
 * container when docker is available.
 */
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

    it('scan passes MATCH through rather than returning the whole keyspace', async () => {
      await client.set(key('scan:a'), '1')
      await client.set(key('scan:b'), '1')
      await client.set(key('other:c'), '1')

      const seen: string[] = []
      let cursor = '0'
      do {
        const [next, keys] = await client.scan(cursor, { count: 100, match: `${prefix}:scan:*` })
        cursor = next
        seen.push(...keys)
      } while (cursor !== '0')

      expect(seen.sort()).toEqual([key('scan:a'), key('scan:b')])
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

    it('eval hands the server the key count in the right position', async () => {
      // ioredis takes numKeys positionally; the object form does not. Getting this
      // wrong makes the server read a key as an argument, or the reverse.
      const result = await client.eval?.('return {KEYS[1], ARGV[1]}', {
        args: ['arg-value'],
        keys: [key('eval')],
      })
      expect(result).toEqual([key('eval'), 'arg-value'])
    })
  })

  describe('a real store driven entirely through the adapter', () => {
    // The end the translation exists to serve: if any command is mistranslated,
    // the shared session contract stops holding.
    runSessionStoreCompliance(() => new RedisSessionImpl({ prefix: `${prefix}:store:${e2ePrefix()}`, redis: client }))
  })
})
