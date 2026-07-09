import { beforeEach, describe, expect, it } from 'vitest'
import { FakeRedis } from '~/adapters/redis/redis-like'
import { sha256 } from '~/core/crypto'
import type { Session } from '~/core/sessions/sessions.types'
import { RedisSessionStore } from '../sessions.redis'

function buildSession(overrides: Partial<Session.Me> = {}): Session.Me {
  const sid = 'sid-' + Math.random().toString(36).slice(2)
  const now = new Date()
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
    createdAt: now,
    rotatedAt: now,
    expiresAt: exp,
    absoluteExpiresAt: exp,
    fresh: true,
    actingAs: null,
    ...overrides,
  }
}

describe('RedisSessionStore', () => {
  let redis: FakeRedis
  let store: RedisSessionStore

  beforeEach(() => {
    redis = new FakeRedis()
    store = new RedisSessionStore({ redis, prefix: 'test' })
  })

  it('create + getByHash round-trips the session', async () => {
    const s = buildSession()
    await store.create(s)
    const got = await store.getByHash(s.id)
    expect(got).toEqual(s)
  })

  it('getByHash returns null on miss', async () => {
    expect(await store.getByHash('not-real')).toBeNull()
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
    expect(await store.getByHash(s.id)).toBeNull()
    expect(await store.listByIdentity(s.identityId!)).toEqual([])
  })

  it('listByIdentity returns every live session + prunes stale entries', async () => {
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
  })

  it('deleteAllForIdentity wipes every session + index Set', async () => {
    const a = buildSession()
    const b = buildSession()
    await store.create(a)
    await store.create(b)
    await store.deleteAllForIdentity('ident-1')
    expect(await store.listByIdentity('ident-1')).toEqual([])
    expect(await store.getByHash(a.id)).toBeNull()
    expect(await store.getByHash(b.id)).toBeNull()
  })

  it('gc reconciles index Sets that point at TTL-evicted records', async () => {
    const a = buildSession()
    const b = buildSession()
    await store.create(a)
    await store.create(b)
    await redis.del(`test:sess:${a.id}`)
    const { deleted } = await store.gc(Date.now())
    expect(deleted).toBe(1)
    const remaining = await redis.smembers('test:idx:identity:ident-1')
    expect(remaining).toEqual([b.id])
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
    expect(await store.getByHash(guest.id)).not.toBeNull()
    expect(await redis.smembers('test:idx:identity:ident-1')).toEqual([])
  })

  it('getByHash returns null on a corrupted JSON entry (parser fail-closed)', async () => {
    // Plant raw garbage as if Redis was tampered with.
    await redis.set('test:sess:corrupt-id', 'not-valid-json-{{}}}', {})
    expect(await store.getByHash('corrupt-id')).toBeNull()
  })

  it('getByHash returns null when expiresAt is a string (parser rejects non-finite-number)', async () => {
    // The legacy cast would have accepted this; downstream
    // `expiresAt < Date.now()` becomes a NaN comparison and silently
    // treats the session as live. parseStoredSession rejects.
    await redis.set(
      'test:sess:bad-expires',
      JSON.stringify({
        id: 'bad-expires',
        identityId: 'i1',
        kind: 'web',
        aal: 1,
        factors: [],
        createdAt: 1,
        rotatedAt: 1,
        expiresAt: 'never', // <- wrong type
        absoluteExpiresAt: 2,
        fresh: true,
      }),
      {},
    )
    expect(await store.getByHash('bad-expires')).toBeNull()
  })

  it('getByHash returns null when the entry is a top-level array (not an object)', async () => {
    await redis.set('test:sess:array-row', JSON.stringify(['unexpected']), {})
    expect(await store.getByHash('array-row')).toBeNull()
  })
})
