/**
 * E2E: what `parseStoredSession` does with a blob it did not write, against REAL
 * Redis.
 *
 * The parser's contract is that it never throws: every failure returns `null`, so
 * a corrupt or tampered row reads as "no session" rather than taking a request
 * down. That contract does not hold, and the cases below say exactly where.
 *
 * These are not new discoveries. They are S1, S1b and S6 from the C1 audit, which
 * `docs/superpowers/plans/C1-sessions/02-sessions-redis-hardening.md` describes in
 * full and nothing has yet implemented. They are pinned here because a plan is a
 * promise and a test is a fact, and because a reader who plants a bad row deserves
 * to find the behaviour written down rather than discover it in production.
 *
 * Nothing here is repaired.
 *
 * Skips when DUCKAUTH_E2E_REDIS_URL is unset; `globalSetup` provisions a container
 * when docker is available.
 */
import Redis from 'ioredis'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { RedisSessionImpl } from '~/core/sessions/sessions.redis'
import { dropPrefix, e2ePrefix, redisUrl } from '~/test/e2e-env'
import { toRedisLike } from '~/test/e2e-redis'

const URL = redisUrl()
const suite = URL ? describe : describe.skip

suite('E2E RedisSessionImpl parser under corrupt rows (real Redis)', () => {
  let raw: Redis
  let prefix: string
  let store: RedisSessionImpl

  /** A structurally valid stored session, before whatever the test breaks. */
  const wellFormed = (id: string, over: Record<string, unknown> = {}) => ({
    aal: 1,
    absoluteExpiresAt: Date.now() + 600_000,
    createdAt: Date.now(),
    expiresAt: Date.now() + 60_000,
    factors: [],
    fresh: true,
    id,
    identityId: 'identity-1',
    kind: 'user',
    rotatedAt: Date.now(),
    ...over,
  })

  /** Plant a row straight into Redis, bypassing the writer entirely. */
  async function plant(id: string, blob: unknown): Promise<void> {
    await raw.set(`${prefix}:sess:${id}`, JSON.stringify(blob))
  }

  beforeAll(async () => {
    raw = new Redis(URL as string, { lazyConnect: true, maxRetriesPerRequest: 2 })
    await raw.connect()
    prefix = e2ePrefix()
    store = new RedisSessionImpl({ prefix, redis: toRedisLike(raw) })
  })

  afterAll(async () => {
    if (raw) {
      await dropPrefix(raw, prefix)
      await raw.quit()
    }
  })

  describe('the parser is documented never to throw', () => {
    it('FINDING (audit S1): a null inside factors throws instead of returning null', async () => {
      // `Array.isArray` narrows the value to `any[]`, so `f.method` is unchecked
      // and TypeScript says nothing. The try/catch upstream wraps only JSON.parse,
      // so this escapes. One corrupt or tampered blob turns every read of that
      // session into a 500, and `getByHash` is on the path of every authed request
      // for that user.
      const id = 'parser-null-factor'
      await plant(id, wellFormed(id, { factors: [null] }))

      await expect(store.getByHash(id)).rejects.toThrow(/Cannot read properties of null/)
    })

    it('FINDING (audit S1): the same blob takes listByIdentity down with it', async () => {
      // The blast radius is wider than one lookup: anything that parses rows in a
      // loop inherits the throw, including the active-devices listing.
      const id = 'parser-null-in-list'
      await plant(id, wellFormed(id, { factors: [null] }))
      await raw.sadd(`${prefix}:idx:identity:identity-1`, id)

      await expect(store.listByIdentity('identity-1')).rejects.toThrow(/Cannot read properties of null/)
      await raw.srem(`${prefix}:idx:identity:identity-1`, id)
    })

    it('FINDING (audit S1b): a string in factors is dropped silently', async () => {
      // Quieter than the throw and worse for it: the session comes back with
      // `factors: []` while `aal` is untouched, so a row claiming two factors
      // presents no evidence of any. Step-up logic reads that list as authoritative.
      const id = 'parser-string-factor'
      await plant(id, wellFormed(id, { aal: 2, factors: ['password'] }))

      const got = await store.getByHash(id)
      expect(got).not.toBeNull()
      expect(got?.aal).toBe(2)
      expect(got?.factors).toEqual([])
    })

    it('FINDING (audit S1b): a number in factors is dropped silently', async () => {
      const id = 'parser-number-factor'
      await plant(id, wellFormed(id, { factors: [7] }))
      expect((await store.getByHash(id))?.factors).toEqual([])
    })

    it('FINDING (audit S1b): an empty object in factors is dropped silently', async () => {
      const id = 'parser-empty-factor'
      await plant(id, wellFormed(id, { factors: [{}] }))
      expect((await store.getByHash(id))?.factors).toEqual([])
    })

    it('FINDING (audit S6): the sixteen-factor cap is not enforced on read', async () => {
      // `sessions.create` refuses more than sixteen and `parseJwtPayload` caps at
      // the same number. This reader accepts as many as the blob carries.
      const id = 'parser-many-factors'
      const factors = Array.from({ length: 17 }, () => ({ completedAt: Date.now(), method: 'password' }))
      await plant(id, wellFormed(id, { factors }))

      expect((await store.getByHash(id))?.factors).toHaveLength(17)
    })

    it('FINDING: a partial actingAs envelope is dropped rather than refused', async () => {
      // Losing the envelope loses both halves of what it is for: the audit trail
      // saying who the real actor was, and the expiry that bounds the session. The
      // row then reads as an ordinary session belonging to the impersonated user.
      const id = 'parser-partial-acting'
      await plant(id, wellFormed(id, { actingAs: { realIdentityId: 'admin-1' } }))

      const got = await store.getByHash(id)
      expect(got).not.toBeNull()
      expect(got?.actingAs).toBeNull()
    })
  })

  describe('where the parser does hold its contract', () => {
    it('returns null for a blob that is not JSON at all', async () => {
      await raw.set(`${prefix}:sess:not-json`, 'definitely-not-json{{{')
      expect(await store.getByHash('not-json')).toBeNull()
    })

    it('returns null for a top-level array', async () => {
      await plant('an-array', ['nope'])
      expect(await store.getByHash('an-array')).toBeNull()
    })

    it('returns null for a top-level number', async () => {
      await plant('a-number', 42)
      expect(await store.getByHash('a-number')).toBeNull()
    })

    it('returns null for an out-of-range aal', async () => {
      const id = 'bad-aal'
      await plant(id, wellFormed(id, { aal: 99 }))
      expect(await store.getByHash(id)).toBeNull()
    })

    it('returns null for an unrecognised kind', async () => {
      const id = 'bad-kind'
      await plant(id, wellFormed(id, { kind: 'browser' }))
      expect(await store.getByHash(id)).toBeNull()
    })

    it('returns null when expiresAt is unparseable', async () => {
      const id = 'bad-expiry'
      await plant(id, wellFormed(id, { expiresAt: 'never' }))
      expect(await store.getByHash(id)).toBeNull()
    })

    it('returns null when the id is missing', async () => {
      await plant('no-id', { ...wellFormed('no-id'), id: undefined })
      expect(await store.getByHash('no-id')).toBeNull()
    })

    it('returns null for an empty object', async () => {
      await plant('empty-object', {})
      expect(await store.getByHash('empty-object')).toBeNull()
    })

    it('drops an unrecognised factor method while keeping the row', async () => {
      // Deliberate and correct: a newer writer adding a method must not make the
      // row unreadable by an older reader.
      const id = 'unknown-method'
      await plant(id, wellFormed(id, { factors: [{ completedAt: Date.now(), method: 'telepathy' }] }))

      const got = await store.getByHash(id)
      expect(got).not.toBeNull()
      expect(got?.factors).toEqual([])
    })

    it('revives dates that arrive as ISO strings', async () => {
      const id = 'iso-dates'
      const now = new Date()
      await plant(id, {
        ...wellFormed(id),
        createdAt: now.toISOString(),
        expiresAt: new Date(now.getTime() + 60_000).toISOString(),
        factors: [{ completedAt: now.toISOString(), method: 'password' }],
      })

      const got = await store.getByHash(id)
      expect(got?.createdAt).toBeInstanceOf(Date)
      expect(got?.factors[0]?.completedAt).toBeInstanceOf(Date)
    })
  })
})
