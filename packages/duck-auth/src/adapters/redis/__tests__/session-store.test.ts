/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { beforeEach, describe, expect, it } from 'vitest'
import { sha256 } from '../../../core/crypto'
import type { Session } from '../../../core/types/session'
import { FakeRedis } from '../redis-like'
import { RedisSessionStore } from '../session-store'

function buildSession(overrides: Partial<Session.ISession> = {}): Session.ISession {
  const sid = 'sid-' + Math.random().toString(36).slice(2)
  const now = Date.now()
  return {
    id: sha256(sid),
    identityId: 'ident-1',
    kind: 'user',
    aal: 2,
    factors: [{ method: 'password', completedAt: now }],
    createdAt: now,
    rotatedAt: now,
    expiresAt: now + 60_000,
    absoluteExpiresAt: now + 60_000,
    fresh: true,
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
    const patched = await store.update(s.id, { aal: 3, absoluteExpiresAt: Date.now() + 120_000 })
    expect(patched.aal).toBe(3)
    expect(patched.absoluteExpiresAt).toBeGreaterThan(s.absoluteExpiresAt)
  })

  it('update rejects unknown session id', async () => {
    await expect(store.update('not-real', { aal: 3 })).rejects.toMatchObject({
      code: 'AUTH/SESSION_REVOKED',
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
      code: 'AUTH/MISCONFIGURED',
    })
  })

  it('guest sessions (no identityId) skip the identity index', async () => {
    const guest = buildSession({ identityId: null, kind: 'guest' })
    await store.create(guest)
    expect(await store.getByHash(guest.id)).not.toBeNull()
    expect(await redis.smembers('test:idx:identity:ident-1')).toEqual([])
  })
})
