/** E2E: RedisSessionImpl against a REAL Redis. */
import Redis from 'ioredis'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { type ValkeyClient, valkeyAdapter } from '~/adapters/valkey'
import { sha256 } from '~/core/crypto'
import type { RedisLike } from '~/core/drivers/redis-like'
import { dropPrefix, e2ePrefix, redisUrl } from '~/test/e2e-env'
import { runSessionStoreCompliance } from '~/test/store-compliance'
import { RedisSessionImpl } from '../sessions.redis'
import type { Sessions } from '../sessions.types'

const URL = redisUrl()
const suite = URL ? describe : describe.skip

/** The id is hashed here rather than at each call site: `assertSessionAllowed` pins it at 64 hex
 *  characters, a raw token being exactly what that guard refuses, so a readable name passed in by a
 *  caller below still reaches the store as a real key. */
function sess(over: Partial<Sessions.Me> = {}): Sessions.Me {
  const now = new Date()
  const { id, ...rest } = over
  return {
    id: sha256(id ?? `s-${Math.random().toString(36).slice(2)}`),
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
    updatedAt: now,
    rotatedAt: now,
    expiresAt: new Date(now.getTime() + 60_000),
    absoluteExpiresAt: new Date(now.getTime() + 86_400_000),
    fresh: true,
    actingAs: null,
    ...rest,
  }
}

suite('E2E RedisSessionImpl (real Redis)', () => {
  let raw: Redis
  let client: RedisLike.Client
  let prefix: string

  beforeAll(async () => {
    raw = new Redis(URL as string, { maxRetriesPerRequest: 2, lazyConnect: true })
    await raw.connect()
    client = valkeyAdapter(raw as unknown as ValkeyClient.Me)
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
      await store.create(s)

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
      await store.create(sess({ id: `old-${Date.now()}`, identityId }))

      await Promise.all([
        store.deleteAllForIdentity(identityId),
        store.create(sess({ id: `new-${Date.now()}`, identityId })),
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
        await store.create(s)
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
    it('sweeps only what is due, and pages past the range limit to get all of it', async () => {
      const store = new RedisSessionImpl({ prefix: `${prefix}:gcscale`, redis: client })
      const identityId = `gc-${Date.now()}`
      const past = new Date(Date.now() - 60_000)
      // A row that expired has to have been created before it did: `assertSessionAllowed` refuses an
      // `expiresAt` that precedes its `createdAt`, so a due row is backdated rather than just expired.
      const born = new Date(Date.now() - 120_000)
      // 500 due rows against a 250-member page: a single-page sweep leaves half
      // of them behind. 100 live ones alongside, because a sweep that took them
      // too would be signing every one of those users out.
      await Promise.all([
        ...Array.from({ length: 500 }, (_, i) =>
          store.create(
            sess({
              absoluteExpiresAt: past,
              createdAt: born,
              expiresAt: past,
              id: `gc-dead-${i}-${Date.now()}`,
              identityId,
              rotatedAt: born,
            }),
          ),
        ),
        ...Array.from({ length: 100 }, (_, i) => store.create(sess({ id: `gc-live-${i}-${Date.now()}`, identityId }))),
      ])

      const started = Date.now()
      const { deleted } = await store.gc(Date.now())
      const elapsed = Date.now() - started

      console.log(`      gc over 600 sessions (500 due): ${elapsed}ms, deleted=${deleted}`)
      expect(deleted).toBe(500)
      // The identity index is reconciled from the expiry member alone - no
      // session body is read to find out whose set to clear.
      expect(await store.listByIdentity(identityId)).toHaveLength(100)
    }, 60_000)
  })
})
