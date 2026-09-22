import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { sha256 } from '~/core/crypto'
import { FakeRedis } from '~/core/drivers/redis-like'
import type { Sessions } from '~/core/sessions/sessions.types'
import { RedisSessionImpl } from '../sessions.redis'

/** Created a day ago, so the gc cases that push a deadline into the past still describe a session that
 *  existed before it expired — `expires_at >= created_at` is a constraint every dialect carries. */
function buildSession(overrides: Partial<Sessions.Me> = {}): Sessions.Me {
  const sid = 'sid-' + Math.random().toString(36).slice(2)
  const now = new Date()
  const born = new Date(now.getTime() - 86_400_000)
  const exp = new Date(now.getTime() + 60_000)
  return {
    id: sha256(sid),
    identityId: 'ident-1',
    tenantId: null,
    kind: 'user',
    aal: 2,
    factors: [{ method: 'password', completedAt: now }],
    csrfHash: null,
    ip: null,
    userAgent: null,
    fingerprint: null,
    createdAt: born,
    updatedAt: now,
    rotatedAt: now,
    expiresAt: exp,
    absoluteExpiresAt: exp,
    fresh: true,
    actingAs: null,
    ...overrides,
  }
}

/**
 * A stored row as JSON, so a test can plant a shape TypeScript would refuse to
 * build. Every field is valid unless the case overrides it.
 */
function storedRow(id: string, overrides: Record<string, unknown> = {}): string {
  const now = Date.now()
  return JSON.stringify({
    id,
    identityId: 'i1',
    kind: 'user',
    aal: 1,
    factors: [],
    createdAt: now,
    updatedAt: now,
    rotatedAt: now,
    expiresAt: now + 60_000,
    absoluteExpiresAt: now + 60_000,
    fresh: true,
    ...overrides,
  })
}

describe('RedisSessionStore', () => {
  let redis: FakeRedis
  let store: RedisSessionImpl

  beforeEach(() => {
    redis = new FakeRedis()
    store = new RedisSessionImpl({ redis, prefix: 'test' })
  })

  it('create + getByHash round-trips the session', async () => {
    const s = buildSession()
    await store.create(s)
    const got = await store.getByHash(s.id)
    expect(got).toEqual(s)
  })

  it('getByHash returns null on miss', async () => {
    await expect(store.getByHash('not-real')).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
  })

  it('update merges patch + bumps absoluteExpiresAt to recompute TTL', async () => {
    const s = buildSession()
    await store.create(s)
    const newExp = new Date(Date.now() + 120_000)
    const patched = await store.update(s.id, { aal: 3, absoluteExpiresAt: newExp })
    expect(patched.aal).toBe(3)
    expect(patched.absoluteExpiresAt.getTime()).toBeGreaterThan(s.absoluteExpiresAt.getTime())
  })

  it('update rejects unknown session id', async () => {
    await expect(store.update('not-real', { aal: 3 })).rejects.toMatchObject({
      code: 'AUTH_SESSION_REVOKED',
    })
  })

  it('delete drops both primary record + identity index entry', async () => {
    const s = buildSession()
    await store.create(s)
    await store.delete(s.id)
    await expect(store.getByHash(s.id)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    expect(await store.listByIdentity(s.identityId!)).toEqual([])
  })

  it('listByIdentity returns every live session and skips ones whose record is gone', async () => {
    const a = buildSession()
    const b = buildSession()
    await store.create(a)
    await store.create(b)
    const list = await store.listByIdentity('ident-1')
    expect(list).toHaveLength(2)

    // Simulate primary record TTL eviction by directly deleting:
    await redis.del(`test:sess:${a.id}`)
    const after = await store.listByIdentity('ident-1')
    expect(after).toHaveLength(1)
    expect(after[0]!.id).toBe(b.id)
    // The entry itself stays: `create` writes the index first, so an id with no
    // record may be a write still in flight. Removing it here would orphan that
    // session permanently. `gc` is the only reconciler.
    expect((await redis.smembers('test:idx:identity:ident-1')).sort()).toEqual([a.id, b.id].sort())
  })

  it('deleteAllForIdentity wipes every session + index Set', async () => {
    const a = buildSession()
    const b = buildSession()
    await store.create(a)
    await store.create(b)
    await store.deleteAllForIdentity('ident-1')
    expect(await store.listByIdentity('ident-1')).toEqual([])
    await expect(store.getByHash(a.id)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    await expect(store.getByHash(b.id)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
  })

  it('gc sweeps a session past its deadline and leaves a live one alone', async () => {
    const past = new Date(Date.now() - 1000)
    const dead = buildSession({ absoluteExpiresAt: past, expiresAt: past })
    const live = buildSession()
    await store.create(dead)
    await store.create(live)

    const { deleted } = await store.gc(Date.now())

    expect(deleted).toBe(1)
    // Record, identity index and expiry index all clear together.
    expect(await redis.get(`test:sess:${dead.id}`)).toBeNull()
    expect(await redis.smembers('test:idx:identity:ident-1')).toEqual([live.id])
    expect(await redis.zrangebyscore('test:exp', '-inf', '+inf')).toEqual([`${live.id}:ident-1`])
    await expect(store.getByHash(live.id)).resolves.toBeTruthy()
  })

  it('gc sweeps on the sliding expiresAt, not just the absolute one', async () => {
    // The key TTL is derived from `absoluteExpiresAt` alone, so an idle-timed-out
    // session with hours left on its absolute deadline has no other enforcer.
    const s = buildSession({
      absoluteExpiresAt: new Date(Date.now() + 3_600_000),
      expiresAt: new Date(Date.now() - 1000),
    })
    await store.create(s)

    expect(await store.gc(Date.now())).toEqual({ deleted: 1 })
    await expect(store.getByHash(s.id)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
  })

  it('gc sweeps guest sessions, which sit in no identity index', async () => {
    const past = new Date(Date.now() - 1000)
    const guest = buildSession({ absoluteExpiresAt: past, expiresAt: past, identityId: null })
    await store.create(guest)

    expect(await store.gc(Date.now())).toEqual({ deleted: 1 })
    await expect(store.getByHash(guest.id)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    expect(await redis.zrangebyscore('test:exp', '-inf', '+inf')).toEqual([])
  })

  it('gc reads no session bodies at all', async () => {
    // The point of the expiry index: the member carries the identity, so the
    // sweep never has to open a row to learn whose index to clear. A `get` per
    // member is the O(all sessions) walk this replaced.
    const past = new Date(Date.now() - 1000)
    await store.create(buildSession({ absoluteExpiresAt: past, expiresAt: past }))
    await store.create(buildSession())
    const realGet = redis.get.bind(redis)
    const read: string[] = []
    redis.get = async (k: string) => {
      read.push(k)
      return realGet(k)
    }

    await store.gc(Date.now())

    expect(read.filter((k) => k.startsWith('test:sess:'))).toEqual([])
  })

  it('gc pages through more expired sessions than one range query returns', async () => {
    const past = new Date(Date.now() - 1000)
    const ids: string[] = []
    for (let i = 0; i < 260; i++) {
      const s = buildSession({ absoluteExpiresAt: past, expiresAt: past })
      ids.push(s.id)
      await store.create(s)
    }

    // 260 > the 250-member page, so a single-page sweep would leave 10 behind.
    expect(await store.gc(Date.now())).toEqual({ deleted: 260 })
    expect(await redis.zrangebyscore('test:exp', '-inf', '+inf')).toEqual([])
    expect(await redis.smembers('test:idx:identity:ident-1')).toEqual([])
  })

  it('delete retires the expiry entry rather than leaving it for gc', async () => {
    const s = buildSession()
    await store.create(s)
    await store.delete(s.id)
    expect(await redis.zrangebyscore('test:exp', '-inf', '+inf')).toEqual([])
  })

  it('deleteAllForIdentity retires every expiry entry it revoked', async () => {
    await store.create(buildSession())
    await store.create(buildSession())
    await store.deleteAllForIdentity('ident-1')
    expect(await redis.zrangebyscore('test:exp', '-inf', '+inf')).toEqual([])
  })

  it('update reschedules the sweep, so a renewal is not swept on its old deadline', async () => {
    const past = new Date(Date.now() - 1000)
    const s = buildSession({ absoluteExpiresAt: past, expiresAt: past })
    await store.create(s)
    const future = new Date(Date.now() + 60_000)
    await store.update(s.id, { absoluteExpiresAt: future, expiresAt: future })

    expect(await store.gc(Date.now())).toEqual({ deleted: 0 })
    await expect(store.getByHash(s.id)).resolves.toBeTruthy()
  })

  it('update moves the expiry entry when the session changes identity', async () => {
    // The member carries the identity, so a stale one would have gc srem from
    // the wrong set and leave the new owner's entry behind forever.
    const s = buildSession()
    await store.create(s)
    await store.update(s.id, { identityId: 'ident-2' })

    expect(await redis.zrangebyscore('test:exp', '-inf', '+inf')).toEqual([`${s.id}:ident-2`])
  })

  it('create refuses a session id containing the expiry member separator', async () => {
    // `gc` splits the member at the first `:`; an id carrying one would be
    // truncated and its tail read as somebody else's identity.
    await expect(store.create(buildSession({ id: 'abc:def' }))).rejects.toMatchObject({
      code: 'AUTH_MISCONFIGURED',
    })
  })

  it('rejects sessions with missing id', async () => {
    const broken = buildSession({ id: '' })
    await expect(store.create(broken)).rejects.toMatchObject({
      code: 'AUTH_MISCONFIGURED',
    })
  })

  it('guest sessions (no identityId) skip the identity index', async () => {
    const guest = buildSession({ identityId: null, kind: 'guest' })
    await store.create(guest)
    await expect(store.getByHash(guest.id)).resolves.toBeTruthy()
    expect(await redis.smembers('test:idx:identity:ident-1')).toEqual([])
  })

  it('getByHash returns null on a corrupted JSON entry (parser fail-closed)', async () => {
    // Plant raw garbage as if Redis was tampered with.
    await redis.set('test:sess:corrupt-id', 'not-valid-json-{{}}}', {})
    await expect(store.getByHash('corrupt-id')).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
  })

  it('getByHash returns null when expiresAt is a string (parser rejects non-finite-number)', async () => {
    // The legacy cast would have accepted this; downstream `expiresAt <
    // Date.now()` becomes a NaN comparison and silently treats the session as
    // live. parseStoredSession rejects.
    await redis.set(
      'test:sess:bad-expires',
      JSON.stringify({
        id: 'bad-expires',
        identityId: 'i1',
        kind: 'user',
        aal: 1,
        factors: [],
        createdAt: 1,
        updatedAt: 1,
        rotatedAt: 1,
        expiresAt: 'never', // <- wrong type
        absoluteExpiresAt: 2,
        fresh: true,
      }),
      {},
    )
    await expect(store.getByHash('bad-expires')).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
  })

  it('getByHash returns null when the entry is a top-level array (not an object)', async () => {
    await redis.set('test:sess:array-row', JSON.stringify(['unexpected']), {})
    await expect(store.getByHash('array-row')).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
  })

  it('getByHash returns null on an unrecognised session kind', async () => {
    await redis.set('test:sess:bad-kind', storedRow('bad-kind', { kind: 'web' }), {})
    await expect(store.getByHash('bad-kind')).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
  })

  it('getByHash returns null when factors contains null (parser must not throw)', async () => {
    // The old `.filter((f) => ...includes(f.method))` read `.method` off `null`
    // and threw, outside the try/catch that guards JSON.parse - so a single
    // tampered blob turned every read of that session into a 500 rather than the
    // `null` this parser exists to return.
    await redis.set('test:sess:bad-factors', storedRow('bad-factors', { factors: [null] }), {})
    await expect(store.getByHash('bad-factors')).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
  })

  it('getByHash returns null when factors contains a primitive', async () => {
    // Accepted silently before, with the entry dropped: the row came back as an
    // `aal` session carrying no factors at all.
    await redis.set('test:sess:prim-factors', storedRow('prim-factors', { aal: 2, factors: ['password'] }), {})
    await expect(store.getByHash('prim-factors')).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
  })

  it('getByHash returns null when a factor entry has no method', async () => {
    await redis.set('test:sess:no-method', storedRow('no-method', { factors: [{ completedAt: Date.now() }] }), {})
    await expect(store.getByHash('no-method')).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
  })

  it('getByHash drops unrecognised factor methods rather than rejecting the row', async () => {
    // The one malformed-looking case that is not corruption: a newer writer that
    // knows a factor method this version does not.
    await redis.set(
      'test:sess:unknown-factor',
      storedRow('unknown-factor', { factors: [{ completedAt: Date.now(), method: 'telepathy' }] }),
      {},
    )
    const got = await store.getByHash('unknown-factor')
    expect(got).not.toBeNull()
    expect(got?.factors).toEqual([])
  })

  it('getByHash returns null when factors exceeds the 16-element cap', async () => {
    await redis.set(
      'test:sess:many-factors',
      storedRow('many-factors', {
        factors: Array.from({ length: 17 }, () => ({ completedAt: Date.now(), method: 'password' })),
      }),
      {},
    )
    await expect(store.getByHash('many-factors')).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
  })

  it('getByHash accepts exactly 16 factors', async () => {
    await redis.set(
      'test:sess:cap-factors',
      storedRow('cap-factors', {
        factors: Array.from({ length: 16 }, () => ({ completedAt: Date.now(), method: 'password' })),
      }),
      {},
    )
    expect((await store.getByHash('cap-factors'))?.factors).toHaveLength(16)
  })

  it('getByHash returns null when factors is not an array', async () => {
    await redis.set('test:sess:obj-factors', storedRow('obj-factors', { factors: { method: 'password' } }), {})
    await expect(store.getByHash('obj-factors')).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
  })

  it('getByHash returns null on a malformed actingAs envelope', async () => {
    // Degrading this to `actingAs: null` handed back what reads as an ordinary
    // session belonging to the person being impersonated: no audit trail, and no
    // impersonation expiry either.
    await redis.set('test:sess:bad-acting', storedRow('bad-acting', { actingAs: { realIdentityId: 'admin' } }), {})
    await expect(store.getByHash('bad-acting')).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
  })

  it('getByHash round-trips a well-formed actingAs envelope', async () => {
    const startedAt = Date.now()
    await redis.set(
      'test:sess:good-acting',
      storedRow('good-acting', {
        actingAs: { expiresAt: startedAt + 60_000, realIdentityId: 'admin', reason: 'support', startedAt },
      }),
      {},
    )
    expect((await store.getByHash('good-acting'))?.actingAs).toEqual({
      expiresAt: new Date(startedAt + 60_000),
      realIdentityId: 'admin',
      reason: 'support',
      startedAt: new Date(startedAt),
    })
  })

  it('_ttlFor never hands the client a non-finite TTL', async () => {
    const realSet = redis.set.bind(redis)
    const ttls: (number | undefined)[] = []
    redis.set = async (k: string, v: string, o: { ex?: number; nx?: boolean } = {}) => {
      ttls.push(o.ex)
      return realSet(k, v, o)
    }
    // An adapter handing back a serialised date instead of a Date. The old branch
    // assumed a number, so `ex` arrived as NaN - and FakeRedis's eviction check
    // (`expiresAt < Date.now()`) is false for NaN, so the key never expired.
    const broken = buildSession()
    Object.assign(broken, { absoluteExpiresAt: new Date(Date.now() + 60_000).toISOString() })

    await store.create(broken)

    expect(ttls.every((t) => t === undefined || Number.isFinite(t))).toBe(true)
    // Parsed rather than capped: a serialised date still yields the real TTL.
    expect(ttls.some((t) => t !== undefined && t <= 60)).toBe(true)
    await expect(store.getByHash(broken.id)).resolves.toBeTruthy()
  })

  it('create does not leave an index entry behind when the record write fails', async () => {
    const s = buildSession()
    redis.set = async () => {
      throw new Error('connection lost')
    }

    await expect(store.create(s)).rejects.toThrow('connection lost')
    expect(await redis.smembers('test:idx:identity:ident-1')).toEqual([])
  })

  it('create never writes a readable session that is missing from the identity index', async () => {
    const s = buildSession()
    redis.sadd = async () => {
      throw new Error('connection lost')
    }

    await expect(store.create(s)).rejects.toThrow('connection lost')
    // A readable-but-unindexed row would authenticate while surviving
    // deleteAllForIdentity forever, and gc scans the indexes so nothing could
    // reach it. Better that it never exists.
    await expect(store.getByHash(s.id)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
  })

  it('create compensates when the index TTL write fails, not just the record write', async () => {
    // `expire` sits between the two writes, so it needs the same compensation:
    // otherwise a failure there leaves an entry naming a record that was never
    // written, and the call still reports an error to the caller.
    const s = buildSession()
    redis.expire = async () => {
      throw new Error('connection lost')
    }

    await expect(store.create(s)).rejects.toThrow('connection lost')
    expect(await redis.smembers('test:idx:identity:ident-1')).toEqual([])
    await expect(store.getByHash(s.id)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
  })

  it('a create colliding with a live record leaves the index naming it', async () => {
    const s = buildSession()
    await store.create(s)
    // Strip the entry to reproduce the orphan this whole reordering exists to
    // prevent: a readable record no index names, which gc scans right past.
    await redis.srem('test:idx:identity:ident-1', s.id)

    await expect(store.create(s)).rejects.toMatchObject({ code: 'AUTH_ALREADY_EXISTS' })

    // The id is taken, so the entry this call added names a live record - it
    // repaired the orphan on the way in. Compensating on this branch would tear
    // that back out, and on the ordinary collision it would unindex whichever
    // session won the race.
    expect(await redis.smembers('test:idx:identity:ident-1')).toEqual([s.id])
    await expect(store.getByHash(s.id)).resolves.toBeTruthy()
  })

  it('a read landing inside create does not orphan the session', async () => {
    // Index-first is unsafe on its own: listByIdentity used to srem an id whose
    // record had not been written yet, and gc cannot heal that direction.
    const s = buildSession()
    const realSet = redis.set.bind(redis)
    redis.set = async (k: string, v: string, o: { ex?: number; nx?: boolean } = {}) => {
      if (k === `test:sess:${s.id}`) await store.listByIdentity('ident-1')
      return realSet(k, v, o)
    }

    await store.create(s)

    await expect(store.getByHash(s.id)).resolves.toBeTruthy()
    expect(await redis.smembers('test:idx:identity:ident-1')).toEqual([s.id])
    expect(await store.listByIdentity('ident-1')).toHaveLength(1)
  })

  it('listByIdentity reads every record in one round trip', async () => {
    for (let i = 0; i < 5; i++) await store.create(buildSession())
    const realMget = redis.mget.bind(redis)
    let mgets = 0
    let gets = 0
    redis.mget = async (...keys: string[]) => {
      mgets++
      return realMget(...keys)
    }
    const realGet = redis.get.bind(redis)
    redis.get = async (k: string) => {
      gets++
      return realGet(k)
    }

    expect(await store.listByIdentity('ident-1')).toHaveLength(5)
    expect(mgets).toBe(1)
    expect(gets).toBe(0)
  })

  it('listByIdentity falls back to concurrent gets when the client has no mget', async () => {
    for (let i = 0; i < 5; i++) await store.create(buildSession())
    const realGet = redis.get.bind(redis)
    let inFlight = 0
    let maxInFlight = 0
    // On the prototype, so `delete` would leave it reachable; the store only checks truthiness.
    ;(redis as { mget?: unknown }).mget = undefined
    redis.get = async (k: string) => {
      inFlight++
      maxInFlight = Math.max(maxInFlight, inFlight)
      await new Promise((r) => setTimeout(r, 5))
      inFlight--
      return realGet(k)
    }

    expect(await store.listByIdentity('ident-1')).toHaveLength(5)
    // Sequential round-trips would pin this at 1, and this path backs both the
    // active-devices request and revokeAllForIdentity.
    expect(maxInFlight).toBeGreaterThan(1)
  })

  it('deleteAllForIdentities clears each identity index, not just the records', async () => {
    const a = buildSession()
    const b = buildSession({ id: sha256('other'), identityId: 'ident-2' })
    await store.create(a)
    await store.create(b)

    const gone = await store.deleteAllForIdentities(['ident-1', 'ident-2', 'ident-absent'])

    expect(gone.map((s) => s.id).sort()).toEqual([a.id, b.id].sort())
    expect(gone.map((s) => s.identityId).sort()).toEqual(['ident-1', 'ident-2'])
    // A record-only sweep leaves members naming nothing: invisible to listByIdentity, which drops
    // what it cannot read, and a wasted read on every later call until the key's own TTL.
    expect(await redis.smembers('test:idx:identity:ident-1')).toEqual([])
    expect(await redis.smembers('test:idx:identity:ident-2')).toEqual([])
    expect(await redis.zrangebyscore('test:exp', '-inf', '+inf')).toEqual([])
  })

  it('deleteMany takes each session out of its own identity index', async () => {
    const a = buildSession()
    const b = buildSession({ id: sha256('b'), identityId: 'ident-2' })
    const keep = buildSession({ id: sha256('keep') })
    await store.create(a)
    await store.create(b)
    await store.create(keep)

    const gone = await store.deleteMany([a.id, b.id, sha256('absent')])

    expect(gone.map((s) => s.id).sort()).toEqual([a.id, b.id].sort())
    // Grouped per identity, so the session left behind keeps its entry and the two taken lose theirs.
    expect(await redis.smembers('test:idx:identity:ident-1')).toEqual([keep.id])
    expect(await redis.smembers('test:idx:identity:ident-2')).toEqual([])
  })

  it('deleteMany removes a record it cannot parse', async () => {
    const s = buildSession()
    await store.create(s)
    await redis.set(`test:sess:${s.id}`, '{"not":"a session"}')

    const gone = await store.deleteMany([s.id])

    // Presence is the key existing. Parsing first would make this the one delete that cannot clear
    // a corrupted row, so the row would sit there until its TTL with every read skipping past it.
    expect(gone.map((r) => r.id)).toEqual([s.id])
    expect(await redis.get(`test:sess:${s.id}`)).toBeNull()
  })

  it('gc does not run concurrently across instances sharing a redis', async () => {
    // Same prefix, so both contend for the same `test:gc:lease`.
    const other = new RedisSessionImpl({ prefix: 'test', redis })
    const past = new Date(Date.now() - 1000)
    await store.create(buildSession({ absoluteExpiresAt: past, expiresAt: past }))
    // `deleted` alone cannot tell the two apart: without a lease both instances
    // sweep, and whichever loses the zrem race reports 0 anyway. Count the range
    // queries - the loser must not even ask what is due.
    const realRange = redis.zrangebyscore.bind(redis)
    let ranges = 0
    redis.zrangebyscore = async (
      key: string,
      min: number | string,
      max: number | string,
      opts: { limit?: { count: number; offset: number } } = {},
    ) => {
      ranges++
      return realRange(key, min, max, opts)
    }

    const [ra, rb] = await Promise.all([store.gc(Date.now()), other.gc(Date.now())])

    // One instance does the work; the other no-ops on the lease before sweeping.
    // A short page ends the winner's loop, so the whole sweep is one query.
    expect(ranges).toBe(1)
    expect([ra.deleted, rb.deleted].sort()).toEqual([0, 1])
  })

  it('gc cannot see a create still in flight', async () => {
    // The hazard index-first `create` introduces: between the index write and the
    // record write, the entry names a record that is not there yet. The old
    // index-walking gc met that entry and had to guess whether it was an orphan;
    // this one never meets it, because a session earns an expiry member only
    // after its record lands.
    const s = buildSession()
    await redis.sadd('test:idx:identity:ident-1', s.id)

    const { deleted } = await store.gc(Date.now())

    expect(deleted).toBe(0)
    expect(await redis.smembers('test:idx:identity:ident-1')).toEqual([s.id])
  })

  it('gc leaves its lease to expire rather than releasing it', async () => {
    // Releasing in a `finally` is the unsafe unlock: a sweep that outruns the
    // lease would delete a lease another instance already holds.
    await store.gc(Date.now())
    expect(await redis.get('test:gc:lease')).toBe('1')
    expect(await store.gc(Date.now())).toEqual({ deleted: 0 })
  })
})

/**
 * `create` and `repoint` each bound the per-identity index with one `expire` call, and the fake every
 * test here runs against answered `0` to it and set nothing, because it held TTLs on string entries
 * only. So the index — one key per identity, growing for the life of the process — was unbounded, and
 * dropping either call broke no test.
 */
describe('RedisSessionImpl - the identity index is bounded', () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  it('expires the index set, rather than keeping one key per identity for ever', async () => {
    vi.useFakeTimers()
    const redis = new FakeRedis()
    const store = new RedisSessionImpl({ redis, maxTtlSec: 60 })
    const session = buildSession()
    await store.create(session)
    expect(await redis.smembers(`auth:idx:identity:${session.identityId}`)).toEqual([session.id])

    vi.advanceTimersByTime(61_000)

    expect(await redis.smembers(`auth:idx:identity:${session.identityId}`)).toEqual([])
  })
})
