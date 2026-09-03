/**
 * Integrity of what comes back out of Redis.
 *
 * `parseStoredSession` already refuses a row whose `id`, `kind`, `aal` or
 * `expiresAt` is unusable. These cases cover the fields where a corrupt or
 * partially-written value was instead coerced into something that *weakens* a
 * defence - a future `rotatedAt` that always looks fresh, a `csrfHash` nulled
 * into "double-submit off", an `identityId` nulled out of every index - plus
 * the write paths that let the index and the record drift apart.
 */
import { beforeEach, describe, expect, it } from 'vitest'
import { FakeRedis } from '~/adapters/redis/redis-like'
import type { Sessions } from '~/core/sessions/sessions.types'
import { RedisSessionImpl } from '../sessions.redis'

const PREFIX = 'itg'

function buildSession(overrides: Partial<Sessions.Me> = {}): Sessions.Me {
  const now = new Date()
  const exp = new Date(now.getTime() + 60_000)
  return {
    absoluteExpiresAt: exp,
    actingAs: null,
    aal: 2,
    createdAt: now,
    csrfHash: null,
    expiresAt: exp,
    factors: [{ completedAt: now, method: 'password' }],
    fingerprint: null,
    fresh: true,
    id: 'sess-1',
    identityId: 'ident-A',
    ip: null,
    kind: 'user',
    rotatedAt: now,
    tenantId: null,
    userAgent: null,
    ...overrides,
  }
}

/** A stored row as JSON, with the named fields overwritten by raw (possibly hostile) values. */
function plant(redis: FakeRedis, id: string, corrupt: Record<string, unknown>): Promise<'OK' | null> {
  const base = buildSession({ id })
  return redis.set(`${PREFIX}:sess:${id}`, JSON.stringify({ ...base, ...corrupt }), {})
}

describe('RedisSessionImpl row integrity', () => {
  let redis: FakeRedis
  let store: RedisSessionImpl

  beforeEach(() => {
    redis = new FakeRedis()
    store = new RedisSessionImpl({ prefix: PREFIX, redis })
  })

  describe('rotatedAt / createdAt fail closed', () => {
    it('rejects a row whose rotatedAt is missing rather than dating it in the future', async () => {
      await plant(redis, 'no-rotated', { rotatedAt: undefined })
      expect(await store.getByHash('no-rotated')).toBeNull()
    })

    it('rejects a row whose rotatedAt is unparseable', async () => {
      await plant(redis, 'bad-rotated', { rotatedAt: 'whenever' })
      expect(await store.getByHash('bad-rotated')).toBeNull()
    })

    it('never revives a rotatedAt later than now, which would satisfy every freshness gate', async () => {
      // The old fallback was `expiresAt`, which is by construction in the
      // future: `now - rotatedAt` went negative and `fresh` was unconditional.
      await plant(redis, 'future-rotated', { rotatedAt: null })
      const got = await store.getByHash('future-rotated')
      expect(got).toBeNull()
    })

    it('rejects a row whose createdAt is unparseable', async () => {
      await plant(redis, 'bad-created', { createdAt: {} })
      expect(await store.getByHash('bad-created')).toBeNull()
    })
  })

  describe('fields whose coercion switched a defence off', () => {
    it('rejects a row whose csrfHash is present but not a string', async () => {
      // A caller reads `csrfHash` and skips the double-submit check when it is
      // null, so coercing a corrupt value to null did not weaken CSRF for this
      // session - it disabled it.
      await plant(redis, 'bad-csrf', { csrfHash: 12345 })
      expect(await store.getByHash('bad-csrf')).toBeNull()
    })

    it('still accepts a row whose csrfHash is legitimately null', async () => {
      // Without this the guard above could pass by rejecting every session.
      await plant(redis, 'no-csrf', { csrfHash: null })
      expect(await store.getByHash('no-csrf')).not.toBeNull()
    })

    it('rejects a row whose identityId is present but not a string', async () => {
      // Coerced to null, the session became a guest session: owned by nobody,
      // in no index, and unreachable by `deleteAllForIdentity`.
      await plant(redis, 'bad-ident', { identityId: 42 })
      expect(await store.getByHash('bad-ident')).toBeNull()
    })

    it('still accepts a genuine guest session, which has no identityId', async () => {
      await plant(redis, 'guest', { identityId: null })
      const got = await store.getByHash('guest')
      expect(got?.identityId).toBeNull()
    })
  })

  describe('the row must agree with the key it lives under', () => {
    it('refuses a row whose body id is not the key it was read from', async () => {
      // The body's id is what a caller revokes by; the key is where the row
      // lives. When they disagree, revoking deletes some other key and leaves
      // this session alive - so the row does not resolve at all.
      await plant(redis, 'key-a', { id: 'key-b' })
      expect(await store.getByHash('key-a')).toBeNull()
    })

    it('update cannot move a session to a different key by patching its id', async () => {
      await store.create(buildSession({ id: 'pin-me' }))
      const next = await store.update('pin-me', { id: 'somewhere-else', fresh: false })
      expect(next.id).toBe('pin-me')
      // The row it would have escaped to was never written.
      expect(await store.getByHash('somewhere-else')).toBeNull()
      expect((await store.getByHash('pin-me'))?.fresh).toBe(false)
    })

    it('update leaves a field alone when the patch carries an explicit undefined', async () => {
      await store.create(buildSession({ csrfHash: 'csrf-token', id: 'keep' }))
      await store.update('keep', { csrfHash: undefined })
      expect((await store.getByHash('keep'))?.csrfHash).toBe('csrf-token')
    })
  })

  describe('the identity index tracks the record', () => {
    it('moves the session between indexes when a patch repoints identityId', async () => {
      await store.create(buildSession({ id: 'moves', identityId: 'ident-A' }))
      expect((await store.listByIdentity('ident-A')).map((x) => x.id)).toEqual(['moves'])

      await store.update('moves', { identityId: 'ident-B' })

      // Left behind in the old set, the session was invisible to its new owner
      // and - the part that matters - unreachable by "sign out everywhere".
      expect(await store.listByIdentity('ident-A')).toEqual([])
      expect((await store.listByIdentity('ident-B')).map((x) => x.id)).toEqual(['moves'])
      await store.deleteAllForIdentity('ident-B')
      expect(await store.getByHash('moves')).toBeNull()
    })
  })

  describe('create is an insert, not an upsert', () => {
    it('refuses to overwrite a live session at the same id', async () => {
      await store.create(buildSession({ id: 'dup', ip: '1.1.1.1' }))
      await expect(store.create(buildSession({ id: 'dup', ip: '2.2.2.2' }))).rejects.toMatchObject({
        code: 'AUTH_SESSION_REVOKED',
      })
      // Every SQL dialect raises a unique violation here; a plain SET reported
      // success while destroying the session that was already there.
      expect((await store.getByHash('dup'))?.ip).toBe('1.1.1.1')
    })
  })
})
