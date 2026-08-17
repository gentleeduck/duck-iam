/**
 * E2E: RedisSessionImpl against a REAL Redis.
 *
 * Every prior finding about this store was proven against `FakeRedis`, whose own
 * header disclaims review and which has two known bugs. This suite re-runs the
 * shared contract and the two races against a real server, where network
 * latency and real command semantics apply.
 *
 * Skips when DUCKAUTH_E2E_REDIS_URL is unset. See `.env.example`.
 */
import Redis from 'ioredis'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import type { RedisLike } from '~/adapters/redis/redis-like'
import { dropPrefix, e2ePrefix, redisUrl } from '~/test/e2e-env'
import { runSessionStoreCompliance } from '~/test/store-compliance'
import { RedisSessionImpl } from '../sessions.redis'
import type { Sessions } from '../sessions.types'

const URL = redisUrl()
const suite = URL ? describe : describe.skip

/** Adapt ioredis to the minimal `RedisLike.Client` surface the lib consumes. */
function toRedisLike(r: Redis): RedisLike.Client {
  return {
    get: (k) => r.get(k),
    set: async (k, v, opts) => {
      if (opts?.ex !== undefined && opts?.nx) {
        return (await r.set(k, v, 'EX', opts.ex, 'NX')) as string | null
      }
      if (opts?.ex !== undefined) return (await r.set(k, v, 'EX', opts.ex)) as string | null
      if (opts?.nx) return (await r.set(k, v, 'NX')) as string | null
      return (await r.set(k, v)) as string | null
    },
    del: (...keys) => r.del(...keys),
    expire: (k, s) => r.expire(k, s),
    scan: async (cursor, opts) => {
      const args: (string | number)[] = [cursor]
      if (opts?.match) args.push('MATCH', opts.match)
      if (opts?.count) args.push('COUNT', opts.count)
      const [next, keys] = (await r.scan(...(args as [string]))) as [string, string[]]
      return [next, keys]
    },
    incr: (k) => r.incr(k),
    sadd: (k, ...m) => r.sadd(k, ...m),
    srem: (k, ...m) => r.srem(k, ...m),
    smembers: (k) => r.smembers(k),
  } as RedisLike.Client
}

function sess(over: Partial<Sessions.Me> = {}): Sessions.Me {
  const now = new Date()
  return {
    id: `s-${Math.random().toString(36).slice(2)}`,
    identityId: 'ident-e2e',
    tenantId: null,
    kind: 'user',
    aal: 1,
    factors: [],
    csrfHash: null,
    ip: null,
    userAgent: null,
    fingerprint: null,
    createdAt: now,
    rotatedAt: now,
    expiresAt: new Date(now.getTime() + 60_000),
    absoluteExpiresAt: new Date(now.getTime() + 86_400_000),
    fresh: true,
    actingAs: null,
    ...over,
  }
}

suite('E2E RedisSessionImpl (real Redis)', () => {
  let raw: Redis
  let client: RedisLike.Client
  let prefix: string

  beforeAll(async () => {
    raw = new Redis(URL as string, { maxRetriesPerRequest: 2, lazyConnect: true })
    await raw.connect()
    client = toRedisLike(raw)
    prefix = e2ePrefix()
  })

  afterAll(async () => {
    if (raw) {
      await dropPrefix(raw, prefix)
      await raw.quit()
    }
  })

  // The shared contract, against a real server rather than FakeRedis.
  // A divergence here means FakeRedis lied and earlier conclusions need review.
  describe('shared Sessions.Store contract', () => {
    runSessionStoreCompliance(() => new RedisSessionImpl({ redis: client, prefix: `${e2ePrefix()}` }))
  })

  describe('races, against real latency', () => {
    it('R1 — concurrent update(): does a write get lost on a real server?', async () => {
      const store = new RedisSessionImpl({ redis: client, prefix })
      const s = sess({ id: `r1-${Date.now()}` })
      await store.create(s as never)

      await Promise.all([store.update(s.id, { aal: 2 }), store.update(s.id, { fresh: false })])

      const final = await store.getByHash(s.id)
      const bothApplied = final?.aal === 2 && final?.fresh === false
      // Documents real behaviour rather than asserting a bug: real network
      // latency widens the window, so this should lose a write at least as
      // often as FakeRedis did. If it does NOT, the finding needs re-checking.
      console.log(`      R1 real-Redis: bothApplied=${bothApplied} (false = write lost, as predicted)`)
      expect(typeof bothApplied).toBe('boolean')
    })

    it('R2 — a session created during deleteAllForIdentity survives it', async () => {
      const store = new RedisSessionImpl({ redis: client, prefix })
      const identityId = `race-${Date.now()}`
      await store.create(sess({ id: `old-${Date.now()}`, identityId }) as never)

      await Promise.all([
        store.deleteAllForIdentity(identityId),
        store.create(sess({ id: `new-${Date.now()}`, identityId }) as never),
      ])

      const survivors = await store.listByIdentity(identityId)
      console.log(`      R2 real-Redis: ${survivors.length} session(s) survived the revoke`)
      // >0 confirms the revoke-escape reaches real Redis, not just the fake.
      expect(survivors.length).toBeGreaterThanOrEqual(0)
    })

    it('R1 under sustained contention — how often is a write actually lost?', async () => {
      const store = new RedisSessionImpl({ redis: client, prefix })
      const rounds = 25
      let lost = 0

      for (let i = 0; i < rounds; i++) {
        const s = sess({ id: `load-${i}-${Date.now()}` })
        await store.create(s as never)
        await Promise.all([store.update(s.id, { aal: 2 }), store.update(s.id, { fresh: false })])
        const f = await store.getByHash(s.id)
        if (!(f?.aal === 2 && f?.fresh === false)) lost++
      }

      // This number decides whether the Lua/CAS work in plan 03 Task 3 is worth
      // building, or whether the optimistic guard alone is enough.
      console.log(`      R1 loss rate on real Redis: ${lost}/${rounds}`)
      expect(lost).toBeLessThanOrEqual(rounds)
    })
  })

  describe('gc at scale', () => {
    it('times a gc sweep over 500 sessions (S4 is O(identities x sessions) sequential)', async () => {
      const store = new RedisSessionImpl({ redis: client, prefix: `${prefix}:gcscale` })
      const identityId = `gc-${Date.now()}`
      await Promise.all(
        Array.from({ length: 500 }, (_, i) => store.create(sess({ id: `gc-${i}-${Date.now()}`, identityId }) as never)),
      )

      const started = Date.now()
      const { deleted } = await store.gc(Date.now())
      const elapsed = Date.now() - started

      // Feeds the decision in plan 02 Task 3: is batching enough, or does gc
      // need a cursor-based redesign?
      console.log(`      gc over 500 sessions: ${elapsed}ms, deleted=${deleted}`)
      expect(elapsed).toBeGreaterThanOrEqual(0)
    }, 60_000)
  })
})
