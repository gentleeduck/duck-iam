import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '../../../adapters/memory'
import { sha256 } from '../../crypto'
import { InMemoryEvents } from '../../events'
import { DEFAULT_SESSION_CONFIG, resolveBySid, SessionsFacet } from '../sessions'

describe('SessionsFacet', () => {
  let adapter: MemoryAdapter
  let events: InMemoryEvents
  let facet: SessionsFacet

  beforeEach(() => {
    adapter = new MemoryAdapter()
    events = new InMemoryEvents()
    facet = new SessionsFacet(adapter.sessions, events, DEFAULT_SESSION_CONFIG)
  })

  describe('create()', () => {
    it('returns { session, sid } where session.id is the authSha256 of sid', async () => {
      const { session, sid } = await facet.create({
        identityId: 'user-1',
        kind: 'user',
        aal: 2,
        factors: [{ method: 'password', completedAt: new Date() }],
      })
      expect(sid).toMatch(/^[A-Za-z0-9_-]+$/)
      expect(session.id).toBe(sha256(sid))
      // Lookup uses the hashed row key (session.id), not the plaintext sid.
      expect(await adapter.sessions.getByHash(session.id)).not.toBeNull()
      expect(await adapter.sessions.getByHash(sid)).toBeNull()
    })

    it('emits session.created', async () => {
      const handler = vi.fn()
      events.on('session.created', handler)
      await facet.create({ identityId: 'user-1', kind: 'user', aal: 1, factors: [] })
      expect(handler).toHaveBeenCalledOnce()
      expect(handler.mock.calls[0]?.[0].session.identityId).toBe('user-1')
    })

    it('marks the session fresh and within ttlMs / absoluteTtlMs', async () => {
      const { session } = await facet.create({ identityId: 'u', kind: 'user', aal: 1, factors: [] })
      expect(session.fresh).toBe(true)
      const now = Date.now()
      expect(session.expiresAt.getTime() - now).toBeLessThanOrEqual(DEFAULT_SESSION_CONFIG.ttlMs)
      expect(session.absoluteExpiresAt.getTime() - now).toBeLessThanOrEqual(DEFAULT_SESSION_CONFIG.absoluteTtlMs)
    })

    it('createGuest sets identityId=null, kind="guest", aal=1, factors=[]', async () => {
      const { session } = await facet.createGuest()
      expect(session.identityId).toBeNull()
      expect(session.kind).toBe('guest')
      expect(session.aal).toBe(1)
      expect(session.factors).toEqual([])
    })
  })

  describe('rotateOrCreate() - DESIGN section 37 rotation matrix', () => {
    it('signin purpose revokes the previous SID', async () => {
      const { sid: guestSid } = await facet.createGuest()
      const handler = vi.fn()
      events.on('session.revoked', handler)
      const { sid: nextSid } = await facet.rotateOrCreate({
        purpose: 'signin',
        previousSid: guestSid,
        identityId: 'user-1',
        kind: 'user',
        aal: 1,
        factors: [{ method: 'password', completedAt: new Date() }],
      })
      expect(nextSid).not.toBe(guestSid)
      expect(await adapter.sessions.getByHash(sha256(guestSid))).toBeNull()
      expect(handler).toHaveBeenCalledOnce()
    })

    it('step-up purpose downgrades the previous SID instead of deleting it', async () => {
      const { sid: prevSid } = await facet.create({
        identityId: 'user-1',
        kind: 'user',
        aal: 1,
        factors: [{ method: 'password', completedAt: new Date() }],
      })
      await facet.rotateOrCreate({
        purpose: 'step-up',
        previousSid: prevSid,
        identityId: 'user-1',
        kind: 'user',
        aal: 2,
        factors: [
          { method: 'password', completedAt: new Date() },
          { method: 'totp', completedAt: new Date() },
        ],
      })
      const old = await adapter.sessions.getByHash(sha256(prevSid))
      expect(old).not.toBeNull()
      expect(old?.fresh).toBe(false)
    })

    it('credential-change purpose revokes every OTHER session for the identity', async () => {
      const { sid: aSid } = await facet.create({ identityId: 'user-1', kind: 'user', aal: 1, factors: [] })
      const { sid: bSid } = await facet.create({ identityId: 'user-1', kind: 'user', aal: 1, factors: [] })
      const { sid: cSid } = await facet.create({ identityId: 'other', kind: 'user', aal: 1, factors: [] })
      await facet.rotateOrCreate({
        purpose: 'credential-change',
        previousSid: aSid,
        identityId: 'user-1',
        kind: 'user',
        aal: 1,
        factors: [],
      })
      expect(await adapter.sessions.getByHash(sha256(aSid))).toBeNull()
      expect(await adapter.sessions.getByHash(sha256(bSid))).toBeNull()
      expect(await adapter.sessions.getByHash(sha256(cSid))).not.toBeNull()
    })

    it('impersonate-start preserves the real session alongside the actingAs session', async () => {
      const { sid: realSid } = await facet.create({
        identityId: 'admin',
        kind: 'user',
        aal: 2,
        factors: [{ method: 'password', completedAt: new Date() }],
      })
      const { session: impersonation, sid: impersonationSid } = await facet.rotateOrCreate({
        purpose: 'impersonate-start',
        previousSid: realSid,
        identityId: 'target-user',
        kind: 'user',
        aal: 2,
        factors: [{ method: 'password', completedAt: new Date() }],
        actingAs: {
          realIdentityId: 'admin',
          startedAt: new Date(),
          reason: 'support-ticket-1234',
          expiresAt: new Date(Date.now() + 60 * 60 * 1000),
        },
      })
      expect(impersonation.actingAs?.realIdentityId).toBe('admin')
      expect(await adapter.sessions.getByHash(sha256(realSid))).not.toBeNull()
      expect(await adapter.sessions.getByHash(sha256(impersonationSid))).not.toBeNull()
    })

    it('promoteGuest swaps a guest session for a user session under signin-class rotation', async () => {
      const { sid: guestSid } = await facet.createGuest()
      const { session: user, sid: userSid } = await facet.promoteGuest({
        guestSid,
        identityId: 'new-user',
        aal: 1,
        factors: [{ method: 'magic-link', completedAt: new Date() }],
      })
      expect(user.identityId).toBe('new-user')
      expect(user.kind).toBe('user')
      expect(userSid).not.toBe(guestSid)
      expect(await adapter.sessions.getByHash(sha256(guestSid))).toBeNull()
    })
  })

  describe('revoke / revokeAllForIdentity', () => {
    it('revoke deletes one session and emits session.revoked', async () => {
      const { sid } = await facet.create({ identityId: 'u', kind: 'user', aal: 1, factors: [] })
      const handler = vi.fn()
      events.on('session.revoked', handler)
      await facet.revoke(sid)
      expect(await adapter.sessions.getByHash(sha256(sid))).toBeNull()
      expect(handler).toHaveBeenCalledOnce()
    })

    it('revokeAllForIdentity drops every session for that identity', async () => {
      const { sid: aSid } = await facet.create({ identityId: 'u1', kind: 'user', aal: 1, factors: [] })
      const { sid: bSid } = await facet.create({ identityId: 'u1', kind: 'user', aal: 1, factors: [] })
      const { sid: cSid } = await facet.create({ identityId: 'u2', kind: 'user', aal: 1, factors: [] })
      const handler = vi.fn()
      events.on('session.revoked', handler)
      await facet.revokeAllForIdentity('u1')
      expect(await adapter.sessions.getByHash(sha256(aSid))).toBeNull()
      expect(await adapter.sessions.getByHash(sha256(bSid))).toBeNull()
      expect(await adapter.sessions.getByHash(sha256(cSid))).not.toBeNull()
      expect(handler.mock.calls.length).toBe(2)
    })
  })

  describe('touch()', () => {
    it('extends expiresAt within absoluteTtlMs cap', async () => {
      const { session, sid } = await facet.create({ identityId: 'u', kind: 'user', aal: 1, factors: [] })
      const refreshed = await facet.touch(sid)
      expect(refreshed).not.toBeNull()
      expect(refreshed?.expiresAt.getTime()).toBeGreaterThanOrEqual(session.expiresAt.getTime() - 100)
    })

    it('returns null for unknown SID', async () => {
      expect(await facet.touch('does-not-exist')).toBeNull()
    })

    it('hard-deletes a session past its absoluteExpiresAt and returns null', async () => {
      const { sid } = await facet.create({ identityId: 'u', kind: 'user', aal: 1, factors: [] })
      await adapter.sessions.update(sha256(sid), { absoluteExpiresAt: new Date(Date.now() - 1) })
      expect(await facet.touch(sid)).toBeNull()
      expect(await adapter.sessions.getByHash(sha256(sid))).toBeNull()
    })
  })

  describe('gc()', () => {
    it('purges expired sessions', async () => {
      const { sid: aSid } = await facet.create({ identityId: 'u', kind: 'user', aal: 1, factors: [] })
      const { sid: bSid } = await facet.create({ identityId: 'u', kind: 'user', aal: 1, factors: [] })
      await adapter.sessions.update(sha256(aSid), { expiresAt: new Date(Date.now() - 1) })
      const result = await facet.gc()
      expect(result.deleted).toBe(1)
      expect(await adapter.sessions.getByHash(sha256(aSid))).toBeNull()
      expect(await adapter.sessions.getByHash(sha256(bSid))).not.toBeNull()
    })
  })
})

describe('resolveBySid()', () => {
  it('returns null for unknown SID', async () => {
    const adapter = new MemoryAdapter()
    expect(await resolveBySid('nope', adapter.sessions, adapter.identities, {})).toBeNull()
  })

  it('returns (session, identity) for a live SID with linked identity', async () => {
    const adapter = new MemoryAdapter<{ email: string }>()
    const events = new InMemoryEvents()
    const facet = new SessionsFacet(adapter.sessions, events, DEFAULT_SESSION_CONFIG)
    const identity = await adapter.identities.create({ profile: { email: 'x@y.com' }, providers: [] }, {})
    const { sid } = await facet.create({ identityId: identity.id, kind: 'user', aal: 1, factors: [] })
    const resolved = await resolveBySid(sid, adapter.sessions, adapter.identities, {})
    expect(resolved?.session.identityId).toBe(identity.id)
    expect(resolved?.identity?.profile?.email).toBe('x@y.com')
  })

  it('returns null and deletes an expired session', async () => {
    const adapter = new MemoryAdapter()
    const events = new InMemoryEvents()
    const facet = new SessionsFacet(adapter.sessions, events, DEFAULT_SESSION_CONFIG)
    const { sid } = await facet.create({ identityId: 'u', kind: 'user', aal: 1, factors: [] })
    await adapter.sessions.update(sha256(sid), { expiresAt: new Date(Date.now() - 1) })
    expect(await resolveBySid(sid, adapter.sessions, adapter.identities, {})).toBeNull()
    expect(await adapter.sessions.getByHash(sha256(sid))).toBeNull()
  })

  it('throws AUTH/SESSION_REVOKED for a session whose identity was erased mid-life', async () => {
    const adapter = new MemoryAdapter()
    const events = new InMemoryEvents()
    const facet = new SessionsFacet(adapter.sessions, events, DEFAULT_SESSION_CONFIG)
    const identity = await adapter.identities.create({ providers: [] }, {})
    const { sid } = await facet.create({ identityId: identity.id, kind: 'user', aal: 1, factors: [] })
    await adapter.identities.erase(identity.id, {})
    await expect(resolveBySid(sid, adapter.sessions, adapter.identities, {})).rejects.toMatchObject({
      code: 'AUTH_SESSION_REVOKED',
    })
  })

  describe('NaN-bypass defenses against malformed adapter rows', () => {
    async function setupLiveSession(): Promise<{
      adapter: MemoryAdapter
      facet: SessionsFacet
      sid: string
      hash: string
    }> {
      const adapter = new MemoryAdapter()
      const events = new InMemoryEvents()
      const facet = new SessionsFacet(adapter.sessions, events, DEFAULT_SESSION_CONFIG)
      const { sid } = await facet.create({ identityId: 'u', kind: 'user', aal: 1, factors: [] })
      return { adapter, facet, sid, hash: sha256(sid) }
    }

    it('resolveBySid treats NaN expiresAt as expired (central gate fail-closed)', async () => {
      const { adapter, hash, sid } = await setupLiveSession()
      await adapter.sessions.update(hash, { expiresAt: new Date(Number.NaN) })
      expect(await resolveBySid(sid, adapter.sessions, adapter.identities, {})).toBeNull()
      expect(await adapter.sessions.getByHash(hash)).toBeNull()
    })

    it('resolveBySid treats non-numeric expiresAt as expired', async () => {
      const { adapter, hash, sid } = await setupLiveSession()
      // @ts-expect-error: SEC test intentionally violates the typed shape
      await adapter.sessions.update(hash, { expiresAt: 'forever' })
      expect(await resolveBySid(sid, adapter.sessions, adapter.identities, {})).toBeNull()
      expect(await adapter.sessions.getByHash(hash)).toBeNull()
    })

    it('resolveBySid treats NaN absoluteExpiresAt as expired', async () => {
      const { adapter, hash, sid } = await setupLiveSession()
      await adapter.sessions.update(hash, { absoluteExpiresAt: new Date(Number.NaN) })
      expect(await resolveBySid(sid, adapter.sessions, adapter.identities, {})).toBeNull()
      expect(await adapter.sessions.getByHash(hash)).toBeNull()
    })

    it('resolveBySid treats non-finite actingAs.expiresAt as past cap (impersonation TTL defense)', async () => {
      const { adapter, hash, sid } = await setupLiveSession()
      await adapter.sessions.update(hash, {
        actingAs: {
          realIdentityId: 'admin',
          startedAt: new Date(),
          reason: 'support',
          // @ts-expect-error: SEC test intentionally violates the typed shape
          expiresAt: 'unbounded',
        },
      })
      expect(await resolveBySid(sid, adapter.sessions, adapter.identities, {})).toBeNull()
      expect(await adapter.sessions.getByHash(hash)).toBeNull()
    })

    it('touch() treats NaN absoluteExpiresAt as expired and hard-deletes', async () => {
      const { adapter, facet, hash, sid } = await setupLiveSession()
      await adapter.sessions.update(hash, { absoluteExpiresAt: new Date(Number.NaN) })
      expect(await facet.touch(sid)).toBeNull()
      expect(await adapter.sessions.getByHash(hash)).toBeNull()
    })
  })
})
