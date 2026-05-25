import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAuthAdapter } from '../../../adapters/memory'
import { sha256 } from '../../crypto'
import { InMemoryEvents } from '../../events'
import { DEFAULT_SESSION_CONFIG, resolveBySid, SessionsFacet } from '../sessions'

describe('SessionsFacet', () => {
  let adapter: MemoryAuthAdapter
  let events: InMemoryEvents
  let facet: SessionsFacet

  beforeEach(() => {
    adapter = new MemoryAuthAdapter()
    events = new InMemoryEvents()
    facet = new SessionsFacet(adapter.sessions, events, DEFAULT_SESSION_CONFIG)
  })

  describe('create()', () => {
    it('issues an opaque SID, stores by sha256 hash, returns the plaintext on the returned session', async () => {
      const fresh = await facet.create({
        identityId: 'user-1',
        kind: 'user',
        aal: 2,
        factors: [{ method: 'password', completedAt: Date.now() }],
      })
      expect(fresh.id).toMatch(/^[A-Za-z0-9_-]+$/) // base64url
      // Lookup must use the hash, not the plaintext.
      expect(await adapter.sessions.getByHash(fresh.id)).toBeNull()
      expect(await adapter.sessions.getByHash(sha256(fresh.id))).not.toBeNull()
    })

    it('emits session.created', async () => {
      const handler = vi.fn()
      events.on('session.created', handler)
      await facet.create({
        identityId: 'user-1',
        kind: 'user',
        aal: 1,
        factors: [],
      })
      expect(handler).toHaveBeenCalledOnce()
      expect(handler.mock.calls[0]?.[0].session.identityId).toBe('user-1')
    })

    it('marks the session fresh and within ttlMs / absoluteTtlMs', async () => {
      const s = await facet.create({ identityId: 'u', kind: 'user', aal: 1, factors: [] })
      expect(s.fresh).toBe(true)
      const now = Date.now()
      expect(s.expiresAt).toBeGreaterThan(now)
      expect(s.expiresAt - now).toBeLessThanOrEqual(DEFAULT_SESSION_CONFIG.ttlMs)
      expect(s.absoluteExpiresAt - now).toBeLessThanOrEqual(DEFAULT_SESSION_CONFIG.absoluteTtlMs)
    })

    it('respects guest sessions (identityId=null, kind="guest", aal=1, factors=[])', async () => {
      const g = await facet.createGuest()
      expect(g.identityId).toBeNull()
      expect(g.kind).toBe('guest')
      expect(g.aal).toBe(1)
      expect(g.factors).toEqual([])
    })
  })

  describe('rotateOrCreate() — DESIGN §37 rotation matrix', () => {
    it('signin purpose revokes the previous SID', async () => {
      const guest = await facet.createGuest()
      const handler = vi.fn()
      events.on('session.revoked', handler)
      const next = await facet.rotateOrCreate({
        purpose: 'signin',
        previousSid: guest.id,
        identityId: 'user-1',
        kind: 'user',
        aal: 1,
        factors: [{ method: 'password', completedAt: Date.now() }],
      })
      expect(next.id).not.toBe(guest.id)
      expect(await adapter.sessions.getByHash(sha256(guest.id))).toBeNull()
      expect(handler).toHaveBeenCalledOnce()
    })

    it('step-up purpose downgrades the previous SID instead of deleting it', async () => {
      const prev = await facet.create({
        identityId: 'user-1',
        kind: 'user',
        aal: 1,
        factors: [{ method: 'password', completedAt: Date.now() }],
      })
      await facet.rotateOrCreate({
        purpose: 'step-up',
        previousSid: prev.id,
        identityId: 'user-1',
        kind: 'user',
        aal: 2,
        factors: [
          { method: 'password', completedAt: Date.now() },
          { method: 'totp', completedAt: Date.now() },
        ],
      })
      const old = await adapter.sessions.getByHash(sha256(prev.id))
      expect(old).not.toBeNull()
      expect(old?.fresh).toBe(false)
    })

    it('credential-change purpose revokes every OTHER session for the identity', async () => {
      const a = await facet.create({ identityId: 'user-1', kind: 'user', aal: 1, factors: [] })
      const b = await facet.create({ identityId: 'user-1', kind: 'user', aal: 1, factors: [] })
      const c = await facet.create({ identityId: 'other', kind: 'user', aal: 1, factors: [] })
      await facet.rotateOrCreate({
        purpose: 'credential-change',
        previousSid: a.id,
        identityId: 'user-1',
        kind: 'user',
        aal: 1,
        factors: [],
      })
      expect(await adapter.sessions.getByHash(sha256(a.id))).toBeNull()
      expect(await adapter.sessions.getByHash(sha256(b.id))).toBeNull()
      // Other identity's session must survive.
      expect(await adapter.sessions.getByHash(sha256(c.id))).not.toBeNull()
    })

    it('impersonate-start preserves the real session alongside the actingAs session', async () => {
      const real = await facet.create({
        identityId: 'admin',
        kind: 'user',
        aal: 2,
        factors: [{ method: 'password', completedAt: Date.now() }],
      })
      const impersonation = await facet.rotateOrCreate({
        purpose: 'impersonate-start',
        previousSid: real.id,
        identityId: 'target-user',
        kind: 'user',
        aal: 2,
        factors: [{ method: 'password', completedAt: Date.now() }],
        actingAs: {
          realIdentityId: 'admin',
          startedAt: Date.now(),
          reason: 'support-ticket-1234',
          expiresAt: Date.now() + 60 * 60 * 1000,
        },
      })
      expect(impersonation.actingAs?.realIdentityId).toBe('admin')
      // Both sessions live.
      expect(await adapter.sessions.getByHash(sha256(real.id))).not.toBeNull()
      expect(await adapter.sessions.getByHash(sha256(impersonation.id))).not.toBeNull()
    })

    it('promoteGuest swaps a guest session for a user session under the same rotation rules', async () => {
      const guest = await facet.createGuest()
      const user = await facet.promoteGuest({
        guestSid: guest.id,
        identityId: 'new-user',
        aal: 1,
        factors: [{ method: 'magic-link', completedAt: Date.now() }],
      })
      expect(user.identityId).toBe('new-user')
      expect(user.kind).toBe('user')
      expect(await adapter.sessions.getByHash(sha256(guest.id))).toBeNull()
    })
  })

  describe('revoke / revokeAllForIdentity', () => {
    it('revoke deletes one session and emits session.revoked', async () => {
      const s = await facet.create({ identityId: 'u', kind: 'user', aal: 1, factors: [] })
      const handler = vi.fn()
      events.on('session.revoked', handler)
      await facet.revoke(s.id)
      expect(await adapter.sessions.getByHash(sha256(s.id))).toBeNull()
      expect(handler).toHaveBeenCalledOnce()
    })

    it('revokeAllForIdentity drops every session for that identity and emits per-session events', async () => {
      const a = await facet.create({ identityId: 'u1', kind: 'user', aal: 1, factors: [] })
      const b = await facet.create({ identityId: 'u1', kind: 'user', aal: 1, factors: [] })
      const c = await facet.create({ identityId: 'u2', kind: 'user', aal: 1, factors: [] })
      const handler = vi.fn()
      events.on('session.revoked', handler)
      await facet.revokeAllForIdentity('u1')
      expect(await adapter.sessions.getByHash(sha256(a.id))).toBeNull()
      expect(await adapter.sessions.getByHash(sha256(b.id))).toBeNull()
      expect(await adapter.sessions.getByHash(sha256(c.id))).not.toBeNull()
      expect(handler.mock.calls.length).toBe(2)
    })
  })

  describe('touch()', () => {
    it('extends expiresAt within absoluteTtlMs cap', async () => {
      const s = await facet.create({ identityId: 'u', kind: 'user', aal: 1, factors: [] })
      const refreshed = await facet.touch(s.id)
      expect(refreshed).not.toBeNull()
      expect(refreshed?.expiresAt).toBeGreaterThanOrEqual(s.expiresAt - 100)
    })

    it('returns null for unknown SID', async () => {
      expect(await facet.touch('does-not-exist')).toBeNull()
    })

    it('hard-deletes a session past its absoluteExpiresAt and returns null', async () => {
      const s = await facet.create({ identityId: 'u', kind: 'user', aal: 1, factors: [] })
      // Manually backdate absoluteExpiresAt.
      await adapter.sessions.update(sha256(s.id), { absoluteExpiresAt: Date.now() - 1 })
      expect(await facet.touch(s.id)).toBeNull()
      expect(await adapter.sessions.getByHash(sha256(s.id))).toBeNull()
    })
  })

  describe('gc()', () => {
    it('purges expired sessions', async () => {
      const a = await facet.create({ identityId: 'u', kind: 'user', aal: 1, factors: [] })
      const b = await facet.create({ identityId: 'u', kind: 'user', aal: 1, factors: [] })
      await adapter.sessions.update(sha256(a.id), { expiresAt: Date.now() - 1 })
      const result = await facet.gc()
      expect(result.deleted).toBe(1)
      expect(await adapter.sessions.getByHash(sha256(a.id))).toBeNull()
      expect(await adapter.sessions.getByHash(sha256(b.id))).not.toBeNull()
    })
  })
})

describe('resolveBySid()', () => {
  it('returns null for unknown SID', async () => {
    const adapter = new MemoryAuthAdapter()
    expect(await resolveBySid('nope', adapter.sessions, adapter.identities, {})).toBeNull()
  })

  it('returns (session, identity) for a live SID with linked identity', async () => {
    const adapter = new MemoryAuthAdapter<{ email: string }>()
    const events = new InMemoryEvents()
    const facet = new SessionsFacet(adapter.sessions, events, DEFAULT_SESSION_CONFIG)
    const identity = await adapter.identities.create({ profile: { email: 'x@y.com' }, providers: [] }, {})
    const session = await facet.create({
      identityId: identity.id,
      kind: 'user',
      aal: 1,
      factors: [],
    })
    const resolved = await resolveBySid(session.id, adapter.sessions, adapter.identities, {})
    expect(resolved?.session.identityId).toBe(identity.id)
    expect(resolved?.identity?.profile?.email).toBe('x@y.com')
  })

  it('returns null and deletes an expired session', async () => {
    const adapter = new MemoryAuthAdapter()
    const events = new InMemoryEvents()
    const facet = new SessionsFacet(adapter.sessions, events, DEFAULT_SESSION_CONFIG)
    const s = await facet.create({ identityId: 'u', kind: 'user', aal: 1, factors: [] })
    await adapter.sessions.update(sha256(s.id), { expiresAt: Date.now() - 1 })
    expect(await resolveBySid(s.id, adapter.sessions, adapter.identities, {})).toBeNull()
    expect(await adapter.sessions.getByHash(sha256(s.id))).toBeNull()
  })

  it('returns null for a session whose identity was erased mid-life', async () => {
    const adapter = new MemoryAuthAdapter()
    const events = new InMemoryEvents()
    const facet = new SessionsFacet(adapter.sessions, events, DEFAULT_SESSION_CONFIG)
    const identity = await adapter.identities.create({ providers: [] }, {})
    const session = await facet.create({
      identityId: identity.id,
      kind: 'user',
      aal: 1,
      factors: [],
    })
    await adapter.identities.erase(identity.id, {})
    await expect(resolveBySid(session.id, adapter.sessions, adapter.identities, {})).rejects.toMatchObject({
      code: 'AUTH/SESSION_REVOKED',
    })
  })
})
