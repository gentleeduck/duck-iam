import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Adapter } from '~/adapters/adapter'
import { MemoryAdapter } from '~/adapters/memory'
import { orNull } from '~/core/answer'
import { sha256 } from '~/core/crypto'
import { InMemoryEvents } from '~/core/events'
import { identityInput, makeIdentity } from '~/test/store-inputs'
import { resolveBySid, SessionsImpl } from '../sessions'
import { DEFAULT_SESSION_CONFIG } from '../sessions.constants'
import { Sessions } from '../sessions.types'

describe('SessionsFacet', () => {
  let adapter: MemoryAdapter
  let events: InMemoryEvents
  let facet: SessionsImpl

  beforeEach(() => {
    adapter = new MemoryAdapter()
    events = new InMemoryEvents()
    facet = new SessionsImpl(adapter.sessions, events, DEFAULT_SESSION_CONFIG)
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
      await expect(adapter.sessions.getByHash(session.id)).resolves.toBeTruthy()
      await expect(adapter.sessions.getByHash(sid)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
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

    it('session.created carries the identity when the caller supplies one', async () => {
      const handler = vi.fn()
      events.on('session.created', handler)
      const identity = makeIdentity({ id: 'user-1' })

      await facet.create({ aal: 1, factors: [], identity, identityId: identity.id, kind: 'user' })

      expect(handler.mock.calls[0]?.[0].identity).toBe(identity)
    })

    it('session.created emits identity: null when the caller supplies none', async () => {
      const handler = vi.fn()
      events.on('session.created', handler)

      await facet.create({ aal: 1, factors: [], identityId: 'user-1', kind: 'user' })

      expect(handler.mock.calls[0]?.[0].identity).toBeNull()
    })

    it('truncates fingerprint like ip and userAgent', async () => {
      const { session } = await facet.create({
        aal: 1,
        factors: [],
        fingerprint: 'x'.repeat(1000),
        identityId: 'u',
        ip: 'x'.repeat(1000),
        kind: 'user',
        userAgent: 'x'.repeat(1000),
      })
      expect(session.ip?.length).toBe(64)
      expect(session.userAgent?.length).toBe(512)
      expect(session.fingerprint?.length).toBe(256)
    })
  })

  describe('create() validates the impersonation window', () => {
    const window = (over: Partial<Sessions.ActingAs>): Sessions.MintInput => ({
      actingAs: {
        expiresAt: new Date(Date.now() + 60_000),
        realIdentityId: 'operator-1',
        reason: 'support',
        startedAt: new Date(),
        ...over,
      },
      aal: 1,
      factors: [],
      identityId: 'user-1',
      kind: 'user',
    })

    it('refuses a window that has already closed', async () => {
      // It used to be written and then refused by every read of the row, so the caller learned
      // nothing at the one point that could have told them.
      await expect(facet.create(window({ expiresAt: new Date(Date.now() - 1) }))).rejects.toMatchObject({
        code: 'AUTH_INVALID_PARAMETERS',
      })
    })

    it('refuses a window that closes before it opens', async () => {
      await expect(
        facet.create(window({ expiresAt: new Date(Date.now() + 1_000), startedAt: new Date(Date.now() + 2_000) })),
      ).rejects.toMatchObject({ code: 'AUTH_INVALID_PARAMETERS' })
    })

    it('accepts one that is still open', async () => {
      const { session } = await facet.create(window({}))
      expect(session.actingAs?.realIdentityId).toBe('operator-1')
    })
  })

  describe('create() validates factor contents', () => {
    it('rejects an unrecognised factor method', async () => {
      await expect(
        facet.create({
          aal: 1,
          // @ts-expect-error: SEC test intentionally violates the typed shape
          factors: [{ completedAt: new Date(), method: 'telepathy' }],
          identityId: 'u',
          kind: 'user',
        }),
      ).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
    })

    it('rejects a non-Date completedAt', async () => {
      await expect(
        facet.create({
          aal: 1,
          // @ts-expect-error: SEC test intentionally violates the typed shape
          factors: [{ completedAt: 'nope', method: 'password' }],
          identityId: 'u',
          kind: 'user',
        }),
      ).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
    })

    it('still accepts a well-formed factor', async () => {
      const { session } = await facet.create({
        aal: 1,
        factors: [{ completedAt: new Date(), method: 'password' }],
        identityId: 'u',
        kind: 'user',
      })
      expect(session.factors).toHaveLength(1)
    })
  })

  describe('guest sessions expose their CSRF token', () => {
    it('createGuest returns csrfToken and it matches the hash on the row', async () => {
      const { session, csrfToken } = await facet.createGuest()
      const token: string = csrfToken
      expect(token.length).toBeGreaterThan(0)
      expect(session.csrfHash).toBe(sha256(token))
    })

    it('promoteGuest returns csrfToken', async () => {
      const guest = await facet.createGuest()
      const { csrfToken } = await facet.promoteGuest({
        aal: 1,
        factors: [],
        guestSid: guest.sid,
        identityId: 'user-1',
      })
      const token: string = csrfToken
      expect(token.length).toBeGreaterThan(0)
    })

    it('promoteGuest carries fingerprint through to the promoted session', async () => {
      const guest = await facet.createGuest()
      const { session } = await facet.promoteGuest({
        aal: 1,
        factors: [],
        fingerprint: 'fp-1',
        guestSid: guest.sid,
        identityId: 'user-1',
      })
      expect(session.fingerprint).toBe('fp-1')
    })
  })

  describe('rotateOrCreate() - rotation matrix', () => {
    it('credential-change revokes all other sessions even when previousSid is omitted', async () => {
      const { sid: aSid } = await facet.create({ aal: 1, factors: [], identityId: 'user-1', kind: 'user' })
      const { sid: bSid } = await facet.create({ aal: 1, factors: [], identityId: 'user-1', kind: 'user' })
      const { sid: keepSid } = await facet.create({ aal: 1, factors: [], identityId: 'other', kind: 'user' })

      await facet.rotateOrCreate({
        aal: 1,
        factors: [],
        identityId: 'user-1',
        kind: 'user',
        purpose: 'credential-change',
      })

      expect(await orNull(adapter.sessions.getByHash(sha256(aSid)))).toBeNull()
      expect(await orNull(adapter.sessions.getByHash(sha256(bSid)))).toBeNull()
      await expect(adapter.sessions.getByHash(sha256(keepSid))).resolves.toBeTruthy()
    })

    it('credential-change revokes BEFORE minting the replacement session', async () => {
      const order: string[] = []
      const base = adapter.sessions
      // Delegating by hand, not spreading: the store is a class, so its methods sit on the prototype
      // and `{ ...base }` would copy none of them.
      const recording: Sessions.Store = {
        create: (session) => {
          order.push('create')
          return base.create(session)
        },
        delete: (id) => base.delete(id),
        deleteAllForIdentities: (ids) => base.deleteAllForIdentities(ids),
        deleteAllForIdentity: (id) => {
          order.push('revoke')
          return base.deleteAllForIdentity(id)
        },
        deleteMany: (ids) => base.deleteMany(ids),
        gc: (now) => base.gc(now),
        getByHash: (hash) => base.getByHash(hash),
        listByIdentity: (id, ctx) => base.listByIdentity(id, ctx),
        update: (id, patch) => base.update(id, patch),
      }
      const impl = new SessionsImpl(recording, events, DEFAULT_SESSION_CONFIG)

      await impl.rotateOrCreate({
        aal: 1,
        factors: [],
        identityId: 'user-1',
        kind: 'user',
        purpose: 'credential-change',
      })

      expect(order).toEqual(['revoke', 'create'])
    })

    it('credential-change uses deleteAllForIdentity, not an N-delete loop', async () => {
      await facet.create({ aal: 1, factors: [], identityId: 'user-1', kind: 'user' })
      await facet.create({ aal: 1, factors: [], identityId: 'user-1', kind: 'user' })
      await facet.create({ aal: 1, factors: [], identityId: 'user-1', kind: 'user' })
      const sweep = vi.spyOn(adapter.sessions, 'deleteAllForIdentity')
      const single = vi.spyOn(adapter.sessions, 'delete')

      await facet.rotateOrCreate({
        aal: 1,
        factors: [],
        identityId: 'user-1',
        kind: 'user',
        purpose: 'credential-change',
      })

      expect(sweep).toHaveBeenCalledTimes(1)
      expect(single).not.toHaveBeenCalled()
    })

    it('credential-change emits session.revoked once per previously-live session', async () => {
      await facet.create({ aal: 1, factors: [], identityId: 'user-1', kind: 'user' })
      await facet.create({ aal: 1, factors: [], identityId: 'user-1', kind: 'user' })
      const handler = vi.fn()
      events.on('session.revoked', handler)

      await facet.rotateOrCreate({
        aal: 1,
        factors: [],
        identityId: 'user-1',
        kind: 'user',
        purpose: 'credential-change',
      })

      expect(handler).toHaveBeenCalledTimes(2)
    })

    it('credential-change is a no-op revocation when identityId is null (guest)', async () => {
      const sweep = vi.spyOn(adapter.sessions, 'deleteAllForIdentity')

      await facet.rotateOrCreate({
        aal: 1,
        factors: [],
        identityId: null,
        kind: 'guest',
        purpose: 'credential-change',
      })

      expect(sweep).not.toHaveBeenCalled()
    })

    it('session.rotated carries previousSessionId when previousSid was supplied', async () => {
      const { sid: prevSid } = await facet.create({ aal: 1, factors: [], identityId: 'user-1', kind: 'user' })
      const handler = vi.fn()
      events.on('session.rotated', handler)

      await facet.rotateOrCreate({
        aal: 1,
        factors: [],
        identityId: 'user-1',
        kind: 'user',
        previousSid: prevSid,
        purpose: 'signin',
      })

      expect(handler.mock.calls[0]?.[0].previousSessionId).toBe(sha256(prevSid))
    })

    it('session.rotated omits previousSessionId when there was no previous session', async () => {
      const handler = vi.fn()
      events.on('session.rotated', handler)

      await facet.rotateOrCreate({ aal: 1, factors: [], identityId: 'user-1', kind: 'user', purpose: 'signin' })

      expect(handler.mock.calls[0]?.[0].previousSessionId).toBeUndefined()
    })

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
      await expect(adapter.sessions.getByHash(sha256(guestSid))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
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
      expect(await orNull(adapter.sessions.getByHash(sha256(aSid)))).toBeNull()
      expect(await orNull(adapter.sessions.getByHash(sha256(bSid)))).toBeNull()
      await expect(adapter.sessions.getByHash(sha256(cSid))).resolves.toBeTruthy()
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
      await expect(adapter.sessions.getByHash(sha256(realSid))).resolves.toBeTruthy()
      await expect(adapter.sessions.getByHash(sha256(impersonationSid))).resolves.toBeTruthy()
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
      await expect(adapter.sessions.getByHash(sha256(guestSid))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    })
  })

  describe('revoke / revokeAllForIdentity', () => {
    it('revoke deletes one session and emits session.revoked', async () => {
      const { sid } = await facet.create({ identityId: 'u', kind: 'user', aal: 1, factors: [] })
      const handler = vi.fn()
      events.on('session.revoked', handler)
      const revoked = await facet.revoke(sid)
      // The session that went, so a caller can name the device without a read
      // that would now find nothing.
      expect(revoked?.identityId).toBe('u')
      await expect(adapter.sessions.getByHash(sha256(sid))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
      expect(handler).toHaveBeenCalledOnce()
    })

    it('rejects a sid that matches nothing, revoking nothing, and a malformed one loudly', async () => {
      const { sid } = await facet.create({ identityId: 'u', kind: 'user', aal: 1, factors: [] })
      const handler = vi.fn()
      events.on('session.revoked', handler)

      // The rejection is what distinguishes a real revocation from a no-op - the difference between
      // "signed out" and "that token was already dead". A malformed sid is neither.
      await expect(facet.revoke('not-a-real-sid')).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
      await expect(facet.revoke('')).rejects.toMatchObject({ code: 'AUTH_INVALID_PARAMETERS' })
      await expect(facet.revokeByHash(sha256('nope'))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })

      expect(handler).not.toHaveBeenCalled()
      await expect(adapter.sessions.getByHash(sha256(sid))).resolves.toBeTruthy()
    })

    it('revokeByHash answers with the session it revoked', async () => {
      const { sid, session } = await facet.create({ identityId: 'u', kind: 'user', aal: 1, factors: [] })

      const revoked = await facet.revokeByHash(session.id)

      expect(revoked?.id).toBe(session.id)
      await expect(adapter.sessions.getByHash(sha256(sid))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    })

    it('revokeAllForIdentity drops every session for that identity', async () => {
      const { sid: aSid } = await facet.create({ identityId: 'u1', kind: 'user', aal: 1, factors: [] })
      const { sid: bSid } = await facet.create({ identityId: 'u1', kind: 'user', aal: 1, factors: [] })
      const { sid: cSid } = await facet.create({ identityId: 'u2', kind: 'user', aal: 1, factors: [] })
      const handler = vi.fn()
      events.on('session.revoked', handler)
      const revoked = await facet.revokeAllForIdentity('u1')
      // The sessions that went - "you were signed out of 2 devices" needs no
      // second query, and the list is already read to emit the events.
      expect(revoked).toHaveLength(2)
      expect(revoked.every((s) => s.identityId === 'u1')).toBe(true)
      expect(await facet.revokeAllForIdentity('nobody')).toEqual([])
      expect(await orNull(adapter.sessions.getByHash(sha256(aSid)))).toBeNull()
      expect(await orNull(adapter.sessions.getByHash(sha256(bSid)))).toBeNull()
      await expect(adapter.sessions.getByHash(sha256(cSid))).resolves.toBeTruthy()
      expect(handler.mock.calls.length).toBe(2)
    })
  })

  describe('getBySid()', () => {
    it('returns a live session', async () => {
      const { session, sid } = await facet.create({ aal: 1, factors: [], identityId: 'u', kind: 'user' })
      expect((await facet.getBySid(sid)).id).toBe(session.id)
    })

    it('rejects an unknown SID', async () => {
      await expect(facet.getBySid('does-not-exist')).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    })

    it('refuses a session past its sliding expiresAt, and hard-deletes it', async () => {
      // The root cause behind four separate exploit paths: this method reads like
      // `resolveBySid` and used to hand back whatever the store had.
      const { sid } = await facet.create({ aal: 1, factors: [], identityId: 'u', kind: 'user' })
      await adapter.sessions.update(sha256(sid), {
        createdAt: new Date(Date.now() - 86_400_000),
        absoluteExpiresAt: new Date(Date.now() + 86_400_000),
        expiresAt: new Date(Date.now() - 1000),
      })
      await expect(facet.getBySid(sid)).rejects.toMatchObject({ code: 'AUTH_SESSION_EXPIRED' })
      await expect(adapter.sessions.getByHash(sha256(sid))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    })

    it('refuses a session past its absoluteExpiresAt, and hard-deletes it', async () => {
      const { sid } = await facet.create({ aal: 1, factors: [], identityId: 'u', kind: 'user' })
      await adapter.sessions.update(sha256(sid), {
        absoluteExpiresAt: new Date(Date.now() - 1),
        createdAt: new Date(Date.now() - 86_400_000),
        // Every dialect CHECKs `absolute_expires_at >= expires_at`, so a row past its absolute cap is past
        // its sliding one too; leaving `expiresAt` in the future planted a row none of them can hold.
        expiresAt: new Date(Date.now() - 1),
      })
      await expect(facet.getBySid(sid)).rejects.toMatchObject({ code: 'AUTH_SESSION_EXPIRED' })
      await expect(adapter.sessions.getByHash(sha256(sid))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    })

    it('fails closed on a non-finite expiresAt rather than treating it as no deadline', async () => {
      // `NaN < now` is false, so a lenient read keeps a should-be-dead session
      // alive forever. Only an adapter bug produces one.
      const { sid } = await facet.create({ aal: 1, factors: [], identityId: 'u', kind: 'user' })
      await adapter.sessions.update(sha256(sid), {
        createdAt: new Date(Date.now() - 86_400_000),
        expiresAt: new Date(Number.NaN),
      })
      await expect(facet.getBySid(sid)).rejects.toMatchObject({ code: 'AUTH_SESSION_EXPIRED' })
    })

    it('recomputes fresh from rotatedAt instead of trusting the stored flag', async () => {
      // Only `touch` ever refreshed the stored boolean, so a session written
      // `fresh: true` and never touched still claimed freshness weeks later - and
      // the password-reset MFA gate reads exactly that field.
      const { sid } = await facet.create({ aal: 2, factors: [], identityId: 'u', kind: 'user' })
      await adapter.sessions.update(sha256(sid), {
        createdAt: new Date(Date.now() - 86_400_000),
        fresh: true,
        rotatedAt: new Date(Date.now() - DEFAULT_SESSION_CONFIG.freshnessMs - 1000),
      })
      expect((await facet.getBySid(sid)).fresh).toBe(false)
    })

    it('still reports fresh inside the freshness window', async () => {
      const { sid } = await facet.create({ aal: 2, factors: [], identityId: 'u', kind: 'user' })
      expect((await facet.getBySid(sid)).fresh).toBe(true)
    })

    it('keeps a stored fresh:false even when the clock says otherwise', async () => {
      // `fresh` is two claims in one column. The clock half decays; the stored
      // half revokes - a step-up demotes the session it stepped up from by
      // writing `fresh: false` onto a row whose `rotatedAt` is seconds old.
      const { sid } = await facet.create({ aal: 1, factors: [], identityId: 'u', kind: 'user' })
      await adapter.sessions.update(sha256(sid), {
        createdAt: new Date(Date.now() - 86_400_000),
        fresh: false,
        rotatedAt: new Date(),
      })
      expect((await facet.getBySid(sid)).fresh).toBe(false)
    })
  })

  describe('touch()', () => {
    it('extends expiresAt within absoluteTtlMs cap', async () => {
      const { session, sid } = await facet.create({ identityId: 'u', kind: 'user', aal: 1, factors: [] })
      const refreshed = await facet.touch(sid)
      expect(refreshed).not.toBeNull()
      expect(refreshed?.expiresAt.getTime()).toBeGreaterThanOrEqual(session.expiresAt.getTime() - 100)
    })

    it('rejects an unknown SID', async () => {
      await expect(facet.touch('does-not-exist')).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    })

    it('hard-deletes a session past its sliding expiresAt and rejects', async () => {
      const { sid } = await facet.create({ aal: 1, factors: [], identityId: 'u', kind: 'user' })
      await adapter.sessions.update(sha256(sid), {
        createdAt: new Date(Date.now() - 86_400_000),
        absoluteExpiresAt: new Date(Date.now() + 86_400_000),
        expiresAt: new Date(Date.now() - 1000),
      })
      await expect(facet.touch(sid)).rejects.toMatchObject({ code: 'AUTH_SESSION_EXPIRED' })
      await expect(adapter.sessions.getByHash(sha256(sid))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    })

    it('still slides a session that is within its expiresAt window', async () => {
      const { sid } = await facet.create({ aal: 1, factors: [], identityId: 'u', kind: 'user' })
      await expect(facet.touch(sid)).resolves.toBeDefined()
    })

    it('hard-deletes a session past its absoluteExpiresAt and rejects', async () => {
      const { sid } = await facet.create({ identityId: 'u', kind: 'user', aal: 1, factors: [] })
      await adapter.sessions.update(sha256(sid), {
        absoluteExpiresAt: new Date(Date.now() - 1),
        createdAt: new Date(Date.now() - 86_400_000),
        // Every dialect CHECKs `absolute_expires_at >= expires_at`, so a row past its absolute cap is past
        // its sliding one too; leaving `expiresAt` in the future planted a row none of them can hold.
        expiresAt: new Date(Date.now() - 1),
      })
      await expect(facet.touch(sid)).rejects.toMatchObject({ code: 'AUTH_SESSION_EXPIRED' })
      await expect(adapter.sessions.getByHash(sha256(sid))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    })
  })

  describe('gc()', () => {
    it('purges expired sessions', async () => {
      const { sid: aSid } = await facet.create({ identityId: 'u', kind: 'user', aal: 1, factors: [] })
      const { sid: bSid } = await facet.create({ identityId: 'u', kind: 'user', aal: 1, factors: [] })
      await adapter.sessions.update(sha256(aSid), {
        createdAt: new Date(Date.now() - 86_400_000),
        expiresAt: new Date(Date.now() - 1),
      })
      const result = await facet.gc()
      expect(result.deleted).toBe(1)
      expect(await orNull(adapter.sessions.getByHash(sha256(aSid)))).toBeNull()
      await expect(adapter.sessions.getByHash(sha256(bSid))).resolves.toBeTruthy()
    })
  })

  describe('the facet answers with the session or rejects', () => {
    const input = () => ({ identityId: 'user-1', kind: 'user' as const, aal: 1 as const, factors: [] })

    it('rejects a repeat revoke, which orNull reads as the no-op it is', async () => {
      const { sid } = await facet.create(input())
      await expect(facet.revoke(sid)).resolves.toMatchObject({ identityId: 'user-1' })
      await expect(facet.revoke(sid)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
      await expect(facet.revoke(sid).orNull()).resolves.toBeNull()
    })

    it('refuses a malformed sid loudly, even through orNull', async () => {
      for (const bad of ['', 'x'.repeat(4097)]) {
        for (const call of [() => facet.getBySid(bad), () => facet.touch(bad), () => facet.revoke(bad)]) {
          await expect(call()).rejects.toMatchObject({ code: 'AUTH_INVALID_PARAMETERS' })
          await expect(call().orNull()).rejects.toMatchObject({ code: 'AUTH_INVALID_PARAMETERS' })
        }
      }
    })

    it('rejects an expired session and still deletes the row', async () => {
      const { sid, session } = await facet.create(input())
      await adapter.sessions.update(session.id, {
        createdAt: new Date(Date.now() - 86_400_000),
        expiresAt: new Date(Date.now() - 1),
      })
      await expect(facet.getBySid(sid)).rejects.toMatchObject({ code: 'AUTH_SESSION_EXPIRED' })
      // Deleted on read rather than left for `gc`, which is the behaviour this preserves.
      await expect(adapter.sessions.getByHash(session.id)).rejects.toMatchObject({
        code: 'AUTH_SESSION_REVOKED',
      })
    })
  })
})

describe('resolveBySid()', () => {
  it('rejects an unknown SID, naming which of the four refusals it was', async () => {
    const adapter = new MemoryAdapter()
    await expect(resolveBySid('nope', adapter.sessions, adapter.identities)).rejects.toMatchObject({
      code: 'AUTH_SESSION_REVOKED',
      meta: { reason: 'no session for that sid' },
    })
  })

  it('returns (session, identity) for a live SID with linked identity', async () => {
    const adapter = new MemoryAdapter()
    const events = new InMemoryEvents()
    const facet = new SessionsImpl(adapter.sessions, events, DEFAULT_SESSION_CONFIG)
    const identity = await adapter.identities.create(
      identityInput({ profile: { username: 'x@y.com', email: 'x@y.com' }, providers: [] }),
    )
    const { sid } = await facet.create({ identityId: identity.id, kind: 'user', aal: 1, factors: [] })
    const resolved = await resolveBySid(sid, adapter.sessions, adapter.identities)
    expect(resolved.session.identityId).toBe(identity.id)
    expect(resolved.identity?.profile?.email).toBe('x@y.com')
  })

  it('recomputes fresh from rotatedAt instead of handing back the stored flag', async () => {
    // The other half of the `getBySid` fix. `fresh` is a persisted column that
    // only `touch` ever refreshed, and this is the function the engine calls on
    // every cookie-borne request - so a session written `fresh: true` and left
    // alone claimed freshness for as long as it lived, and every re-auth gate
    // reading `session.fresh` believed it.
    const adapter = new MemoryAdapter()
    const facet = new SessionsImpl(adapter.sessions, new InMemoryEvents(), DEFAULT_SESSION_CONFIG)
    const { sid } = await facet.create({ aal: 2, factors: [], identityId: null, kind: 'guest' })
    await adapter.sessions.update(sha256(sid), {
      createdAt: new Date(Date.now() - 86_400_000),
      fresh: true,
      rotatedAt: new Date(Date.now() - DEFAULT_SESSION_CONFIG.freshnessMs - 1000),
    })
    expect((await resolveBySid(sid, adapter.sessions, adapter.identities)).session.fresh).toBe(false)
  })

  it('keeps a step-up demotion rather than reviving it from rotatedAt', async () => {
    const adapter = new MemoryAdapter()
    const facet = new SessionsImpl(adapter.sessions, new InMemoryEvents(), DEFAULT_SESSION_CONFIG)
    const first = await facet.create({ aal: 1, factors: [], identityId: null, kind: 'guest' })
    // Exactly what `rotateOrCreate({ purpose: 'step-up' })` writes to the session
    // being stepped up from: same AAL, no longer fresh, `rotatedAt` untouched.
    await facet.rotateOrCreate({
      aal: 2,
      factors: [],
      identityId: null,
      kind: 'guest',
      previousSid: first.sid,
      purpose: 'step-up',
    })
    expect((await resolveBySid(first.sid, adapter.sessions, adapter.identities)).session.fresh).toBe(false)
  })

  it('honours a caller-supplied freshness window over the default', async () => {
    const adapter = new MemoryAdapter()
    const facet = new SessionsImpl(adapter.sessions, new InMemoryEvents(), DEFAULT_SESSION_CONFIG)
    const { sid } = await facet.create({ aal: 2, factors: [], identityId: null, kind: 'guest' })
    await adapter.sessions.update(sha256(sid), {
      createdAt: new Date(Date.now() - 86_400_000),
      fresh: true,
      rotatedAt: new Date(Date.now() - 10_000),
    })
    const stores = [adapter.sessions, adapter.identities] as const
    expect((await resolveBySid(sid, ...stores, { freshnessMs: 1_000 })).session.fresh).toBe(false)
    expect((await resolveBySid(sid, ...stores, { freshnessMs: 60_000 })).session.fresh).toBe(true)
  })

  it('rejects and deletes an expired session', async () => {
    const adapter = new MemoryAdapter()
    const events = new InMemoryEvents()
    const facet = new SessionsImpl(adapter.sessions, events, DEFAULT_SESSION_CONFIG)
    const { sid } = await facet.create({ identityId: 'u', kind: 'user', aal: 1, factors: [] })
    await adapter.sessions.update(sha256(sid), {
      createdAt: new Date(Date.now() - 86_400_000),
      expiresAt: new Date(Date.now() - 1),
    })
    await expect(resolveBySid(sid, adapter.sessions, adapter.identities)).rejects.toMatchObject({
      code: 'AUTH_SESSION_EXPIRED',
      meta: { expiredAt: expect.any(Number) },
    })
    await expect(adapter.sessions.getByHash(sha256(sid))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
  })

  it('throws AUTH_SESSION_IDENTITY_ERASED for a session whose identity was erased mid-life', async () => {
    const adapter = new MemoryAdapter()
    const events = new InMemoryEvents()
    const facet = new SessionsImpl(adapter.sessions, events, DEFAULT_SESSION_CONFIG)
    const identity = await adapter.identities.create(
      identityInput({ profile: { username: 'u', email: 'u@x.com' }, providers: [] }),
    )
    const { sid } = await facet.create({ identityId: identity.id, kind: 'user', aal: 1, factors: [] })
    // The identity row is dropped on its own, leaving the session behind. That
    // is the case this guard exists for: a schema without the cascade, or the
    // window between the identity delete and the session cleanup.
    adapter.raw.identities.delete(identity.id)
    // SECURITY: outside the absent set on purpose, so a caller reading this through `orNull()` sees the
    // integrity violation rather than the plain sign-out that every other refusal here collapses to.
    await expect(resolveBySid(sid, adapter.sessions, adapter.identities)).rejects.toMatchObject({
      code: 'AUTH_SESSION_IDENTITY_ERASED',
    })
  })

  it('erasing an identity takes its sessions with it, so nothing is left to resolve', async () => {
    const adapter = new MemoryAdapter()
    const events = new InMemoryEvents()
    const facet = new SessionsImpl(adapter.sessions, events, DEFAULT_SESSION_CONFIG)
    const identity = await adapter.identities.create(
      identityInput({ profile: { username: 'u', email: 'u@x.com' }, providers: [] }),
    )
    const { sid } = await facet.create({ identityId: identity.id, kind: 'user', aal: 1, factors: [] })

    await adapter.identities.erase(identity.id)

    // `on delete cascade` on `auth_sessions.identity_id` is what every dialect
    // declares, so the row is gone rather than orphaned - `resolveBySid` finds
    // nothing at all, which is the absent refusal and not the erasure one.
    expect(await adapter.sessions.listByIdentity(identity.id)).toEqual([])
    await expect(resolveBySid(sid, adapter.sessions, adapter.identities)).rejects.toMatchObject({
      code: 'AUTH_SESSION_REVOKED',
      meta: { reason: 'no session for that sid' },
    })
  })

  describe('NaN-bypass defenses against malformed adapter rows', () => {
    async function setupLiveSession(): Promise<{
      adapter: MemoryAdapter
      facet: SessionsImpl
      sid: string
      hash: string
    }> {
      const adapter = new MemoryAdapter()
      const events = new InMemoryEvents()
      const facet = new SessionsImpl(adapter.sessions, events, DEFAULT_SESSION_CONFIG)
      const { sid } = await facet.create({ identityId: 'u', kind: 'user', aal: 1, factors: [] })
      return { adapter, facet, sid, hash: sha256(sid) }
    }

    it('resolveBySid treats NaN expiresAt as expired (central gate fail-closed)', async () => {
      const { adapter, hash, sid } = await setupLiveSession()
      await adapter.sessions.update(hash, {
        createdAt: new Date(Date.now() - 86_400_000),
        expiresAt: new Date(Number.NaN),
      })
      await expect(resolveBySid(sid, adapter.sessions, adapter.identities)).rejects.toMatchObject({
        code: 'AUTH_SESSION_EXPIRED',
        meta: { expiredAt: expect.any(Number) },
      })
      await expect(adapter.sessions.getByHash(hash)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    })

    it('resolveBySid treats non-numeric expiresAt as expired', async () => {
      const { adapter, hash, sid } = await setupLiveSession()
      await adapter.sessions.update(hash, {
        createdAt: new Date(Date.now() - 86_400_000),
        // @ts-expect-error: SEC test intentionally violates the typed shape
        expiresAt: 'forever',
      })
      await expect(resolveBySid(sid, adapter.sessions, adapter.identities)).rejects.toMatchObject({
        code: 'AUTH_SESSION_EXPIRED',
        meta: { expiredAt: expect.any(Number) },
      })
      await expect(adapter.sessions.getByHash(hash)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    })

    it('resolveBySid treats NaN absoluteExpiresAt as expired', async () => {
      const { adapter, hash, sid } = await setupLiveSession()
      await adapter.sessions.update(hash, { absoluteExpiresAt: new Date(Number.NaN) })
      await expect(resolveBySid(sid, adapter.sessions, adapter.identities)).rejects.toMatchObject({
        code: 'AUTH_SESSION_EXPIRED',
        meta: { expiredAt: expect.any(Number) },
      })
      await expect(adapter.sessions.getByHash(hash)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    })

    it('resolveBySid treats non-finite actingAs.expiresAt as past cap (impersonation TTL defense)', async () => {
      const { adapter, hash, sid } = await setupLiveSession()
      await adapter.sessions.update(hash, {
        createdAt: new Date(Date.now() - 86_400_000),
        actingAs: {
          realIdentityId: 'admin',
          startedAt: new Date(),
          reason: 'support',
          // @ts-expect-error: SEC test intentionally violates the typed shape
          expiresAt: 'unbounded',
        },
      })
      await expect(resolveBySid(sid, adapter.sessions, adapter.identities)).rejects.toMatchObject({
        code: 'AUTH_IMPERSONATE_WINDOW_CLOSED',
      })
      await expect(adapter.sessions.getByHash(hash)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    })

    it('touch() treats NaN absoluteExpiresAt as expired and hard-deletes', async () => {
      const { adapter, facet, hash, sid } = await setupLiveSession()
      await adapter.sessions.update(hash, { absoluteExpiresAt: new Date(Number.NaN) })
      await expect(facet.touch(sid)).rejects.toMatchObject({ code: 'AUTH_SESSION_EXPIRED' })
      await expect(adapter.sessions.getByHash(hash)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    })

    it('touch() treats NaN expiresAt as expired and hard-deletes', async () => {
      const { adapter, facet, hash, sid } = await setupLiveSession()
      await adapter.sessions.update(hash, {
        createdAt: new Date(Date.now() - 86_400_000),
        expiresAt: new Date(Number.NaN),
      })
      await expect(facet.touch(sid)).rejects.toMatchObject({ code: 'AUTH_SESSION_EXPIRED' })
      await expect(adapter.sessions.getByHash(hash)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    })
  })
})
