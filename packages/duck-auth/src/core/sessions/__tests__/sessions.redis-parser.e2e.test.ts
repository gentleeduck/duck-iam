/**
 * E2E: what `parseStoredSession` does with a blob it did not write, against REAL
 * Redis.
 *
 * The parser's contract is that it never throws: every failure returns `null`, so
 * a corrupt or tampered row reads as "no session" rather than taking a request
 * down. It did not hold, and the first block below is the set of blobs that broke
 * it - S1, S1b and S6 from the C1 audit, now that
 * `docs/superpowers/plans/C1-sessions/02-sessions-redis-hardening.md` has been
 * applied. The blobs are unchanged; only what they are expected to produce is.
 *
 * The unit suite covers the same shapes through `FakeRedis`. This file exists to
 * prove the real client agrees, since the row a real deployment has to survive is
 * one Redis handed back, not one a fake did.
 *
 * Skips when DUCKAUTH_E2E_REDIS_URL is unset; `globalSetup` provisions a container
 * when docker is available.
 */
import Redis from 'ioredis'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { type ValkeyClient, valkeyAdapter } from '~/adapters/valkey'
import { RedisSessionImpl } from '~/core/sessions/sessions.redis'
import { dropPrefix, e2ePrefix, redisUrl } from '~/test/e2e-env'

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
    store = new RedisSessionImpl({ prefix, redis: valkeyAdapter(raw as unknown as ValkeyClient.Me) })
  })

  afterAll(async () => {
    if (raw) {
      await dropPrefix(raw, prefix)
      await raw.quit()
    }
  })

  describe('the parser never throws, and never quietly loses a factor', () => {
    it('returns null rather than throwing on a null inside factors (audit S1)', async () => {
      // `Array.isArray` narrows the value to `any[]`, so `f.method` was unchecked
      // and TypeScript said nothing. The try/catch upstream wraps only JSON.parse,
      // so the throw escaped - and `getByHash` is on the path of every authed
      // request for that user, so one tampered blob was a permanent 500.
      const id = 'parser-null-factor'
      await plant(id, wellFormed(id, { factors: [null] }))

      expect(await store.getByHash(id)).toBeNull()
    })

    it('no longer takes listByIdentity down with it (audit S1)', async () => {
      // The blast radius was wider than one lookup: anything parsing rows in a
      // loop inherited the throw, the active-devices listing included.
      const id = 'parser-null-in-list'
      await plant(id, wellFormed(id, { factors: [null] }))
      await raw.sadd(`${prefix}:idx:identity:identity-1`, id)

      expect(await store.listByIdentity('identity-1')).toEqual([])
      await raw.srem(`${prefix}:idx:identity:identity-1`, id)
    })

    it('refuses the row when factors holds a string (audit S1b)', async () => {
      // Quieter than the throw and worse for it. The session used to come back
      // with `factors: []` and `aal` untouched, so a row claiming two factors
      // presented evidence of none - and step-up logic reads that list as
      // authoritative.
      const id = 'parser-string-factor'
      await plant(id, wellFormed(id, { aal: 2, factors: ['password'] }))

      expect(await store.getByHash(id)).toBeNull()
    })

    it('refuses the row when factors holds a number (audit S1b)', async () => {
      const id = 'parser-number-factor'
      await plant(id, wellFormed(id, { factors: [7] }))
      expect(await store.getByHash(id)).toBeNull()
    })

    it('refuses the row when a factor entry carries no method (audit S1b)', async () => {
      const id = 'parser-empty-factor'
      await plant(id, wellFormed(id, { factors: [{}] }))
      expect(await store.getByHash(id)).toBeNull()
    })

    it('enforces the sixteen-factor cap on read (audit S6)', async () => {
      // `sessions.create` refuses more than sixteen and `parseJwtPayload` caps at
      // the same number. This reader was the one door in that did not.
      const id = 'parser-many-factors'
      const factors = Array.from({ length: 17 }, () => ({ completedAt: Date.now(), method: 'password' }))
      await plant(id, wellFormed(id, { factors }))

      expect(await store.getByHash(id)).toBeNull()
    })

    it('keeps a row sitting exactly on the cap', async () => {
      const id = 'parser-cap-factors'
      const factors = Array.from({ length: 16 }, () => ({ completedAt: Date.now(), method: 'password' }))
      await plant(id, wellFormed(id, { factors }))

      expect((await store.getByHash(id))?.factors).toHaveLength(16)
    })

    it('refuses a partial actingAs envelope rather than dropping it', async () => {
      // Dropping it lost both halves of what the envelope is for: the audit trail
      // naming the real actor, and the expiry bounding the window. The row then
      // read as an ordinary session belonging to the impersonated user.
      const id = 'parser-partial-acting'
      await plant(id, wellFormed(id, { actingAs: { realIdentityId: 'admin-1' } }))

      expect(await store.getByHash(id)).toBeNull()
    })

    it('keeps a complete actingAs envelope intact', async () => {
      // The other half of the contract: refusing broken envelopes must not cost
      // the good ones.
      const id = 'parser-whole-acting'
      const startedAt = Date.now()
      await plant(
        id,
        wellFormed(id, {
          actingAs: { expiresAt: startedAt + 300_000, realIdentityId: 'admin-1', reason: 'support', startedAt },
        }),
      )

      expect((await store.getByHash(id))?.actingAs).toMatchObject({ realIdentityId: 'admin-1', reason: 'support' })
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
