/**
 * The batch forms of the facet writes. Each answers the rows it touched and nothing else: a row the store
 * refused is simply absent, so a caller diffs its input against the answer rather than reading an outcome.
 */
import { describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthError, asAuthError } from '~/core/errors'
import { InMemoryEvents } from '~/core/events'
import { IdentitiesImpl } from '~/core/identities'
import { DEFAULT_IDENTITIES_CONFIG } from '~/core/identities/identities.constants'
import type { Identities } from '~/core/identities/identities.types'
import { SessionsImpl } from '~/core/sessions'
import { DEFAULT_SESSION_CONFIG } from '~/core/sessions/sessions.constants'

type P = Identities.ProfileMetadataBase

function makeIdentities() {
  const adapter = new MemoryAdapter<P>()
  return {
    adapter,
    identities: new IdentitiesImpl<P>(adapter.identities, new InMemoryEvents(), DEFAULT_IDENTITIES_CONFIG),
  }
}

function makeSessions() {
  const adapter = new MemoryAdapter<P>()
  const bus = new InMemoryEvents()
  const revoked = vi.fn(async () => {})
  bus.on('session.revoked', revoked)

  return { adapter, revoked, sessions: new SessionsImpl(adapter.sessions, bus, DEFAULT_SESSION_CONFIG) }
}

describe('batch operations', () => {
  it('softDeleteMany answers the rows it hid, leaving a miss out', async () => {
    const { identities } = makeIdentities()
    const a = await identities.create({ profile: { email: 'a@x', username: 'a' } })
    const b = await identities.create({ profile: { email: 'b@x', username: 'b' } })

    const hidden = await identities.softDeleteMany([a.id, 'missing-id', b.id])

    expect(hidden.map((row) => row.id)).toEqual([a.id, b.id])
    // The row as the write left it: the caller reads the new window off the answer.
    expect(hidden[0]?.deletedAt?.getTime()).toBeGreaterThan(Date.now())
  })

  it('updateProfileMany leaves a stale row out instead of throwing on the first', async () => {
    const { identities } = makeIdentities()
    const a = await identities.create({ profile: { email: 'a@x', username: 'a' } })
    const b = await identities.create({ profile: { email: 'b@x', username: 'b' } })

    const written = await identities.updateProfileMany([
      { expectedVersion: 999, id: a.id, patch: { username: 'a2' } },
      { expectedVersion: b.version, id: b.id, patch: { username: 'b2' } },
    ])

    expect(written.map((row) => row.id)).toEqual([b.id])
    // The winner really landed; the loser really did not.
    expect((await identities.getById(b.id)).profile.username).toBe('b2')
    expect((await identities.getById(a.id)).profile.username).toBe('a')
  })

  it('updateProfileMany leaves out a clash its own read found', async () => {
    const { identities } = makeIdentities()
    const holder = await identities.create({ profile: { email: 'held@x', username: 'held' } })
    const mover = await identities.create({ profile: { email: 'mover@x', username: 'mover' } })

    const written = await identities.updateProfileMany([
      { expectedVersion: mover.version, id: mover.id, patch: { email: 'held@x' } },
    ])

    expect(written).toEqual([])
    expect((await identities.getById(holder.id)).profile.email).toBe('held@x')
  })

  /**
   * The same code from a driver is the opposite case. The statement has already run and failed, which on
   * postgres leaves the caller's transaction aborted: COMMIT turns into a silent ROLLBACK and every row the
   * batch answered with is gone. Carrying the driver error is what tells the two apart.
   */
  it('updateProfileMany rethrows the same code when a driver refused the write', async () => {
    const { adapter, identities } = makeIdentities()
    const a = await identities.create({ profile: { email: 'd@x', username: 'd' } })
    const refused = new AuthError('AUTH_EMAIL_TAKEN')
    refused.cause = new Error('duplicate key value violates unique constraint "uq_auth_identities_email"')
    adapter.identities.update = () => Promise.reject(refused)

    await expect(
      identities.updateProfileMany([{ expectedVersion: a.version, id: a.id, patch: { username: 'd2' } }]),
    ).rejects.toMatchObject({ code: 'AUTH_EMAIL_TAKEN' })
  })

  it('revokeAllForIdentities answers every session it removed, one event each', async () => {
    const { adapter, revoked, sessions } = makeSessions()
    await sessions.create({ aal: 1, factors: [], identityId: 'i1', kind: 'user' })
    await sessions.create({ aal: 1, factors: [], identityId: 'i1', kind: 'user' })
    await sessions.create({ aal: 1, factors: [], identityId: 'i2', kind: 'user' })

    const gone = await sessions.revokeAllForIdentities(['i1', 'i2', 'i3-none'])

    // Per session, not per identity named: the one with none is simply absent.
    expect(gone).toHaveLength(3)
    expect(gone.filter((s) => s.identityId === 'i1')).toHaveLength(2)
    expect(revoked).toHaveBeenCalledTimes(3)
    expect(await adapter.sessions.listByIdentity('i1')).toEqual([])
  })

  it('a batch over an empty list is a no-op, not an error', async () => {
    const { identities } = makeIdentities()

    expect(await identities.softDeleteMany([])).toEqual([])
    expect(await identities.eraseMany([], { reason: 'test' })).toEqual([])
    expect(await identities.restoreMany([])).toEqual([])
  })

  it('a hard failure propagates rather than being swallowed as a refusal', async () => {
    const { adapter, identities } = makeIdentities()
    const a = await identities.create({ profile: { email: 'h@x', username: 'h' } })
    vi.spyOn(adapter.identities, 'softDeleteMany').mockRejectedValue(new Error('connection lost'))

    await expect(identities.softDeleteMany([a.id])).rejects.toThrow('connection lost')
  })

  it('linkMany answers each identity as the link left it', async () => {
    const { identities } = makeIdentities()
    const a = await identities.create({ profile: { email: 'l@x', username: 'l' } })

    const linked = await identities.linkMany([
      { identityId: a.id, link: { providerId: 'github', providerSub: 'gh-1' } },
      { identityId: a.id, link: { providerId: 'google', providerSub: 'go-1' } },
      // No such row to link to, so this one is refused and left out rather than taking the others with it.
      { identityId: 'missing-id', link: { providerId: 'gitlab', providerSub: 'gl-1' } },
    ])

    expect(linked).toHaveLength(2)
    expect(linked[1]?.providers.map((p) => p.providerId).sort()).toEqual(['github', 'google'])
    expect((await identities.getById(a.id)).providers.map((p) => p.providerId).sort()).toEqual(['github', 'google'])
  })

  it('unlinkMany removes each named link', async () => {
    const { identities } = makeIdentities()
    const a = await identities.create({ profile: { email: 'u@x', username: 'u' } })
    await identities.link(a.id, { providerId: 'github', providerSub: 'gh-1' })
    await identities.link(a.id, { providerId: 'google', providerSub: 'go-1' })

    const unlinked = await identities.unlinkMany([{ identityId: a.id, providerId: 'github' }])

    expect(unlinked.map((row) => row.id)).toEqual([a.id])
    expect((await identities.getById(a.id)).providers.map((p) => p.providerId)).toEqual(['google'])
  })

  it('restoreMany brings back soft-deleted identities, leaving a miss out', async () => {
    const { identities } = makeIdentities()
    const a = await identities.create({ profile: { email: 'r@x', username: 'r' } })
    await identities.softDelete(a.id)

    const restored = await identities.restoreMany([a.id, 'missing-id'])

    expect(restored.map((row) => row.id)).toEqual([a.id])
    await expect(identities.getById(a.id)).resolves.toBeDefined()
  })

  it('restoreMany leaves out a row whose grace window has already shut', async () => {
    const { adapter, identities } = makeIdentities()
    const ok = await identities.create({ profile: { email: 'rr-ok@x', username: 'rrok' } })
    const expired = await identities.create({ profile: { email: 'rr-exp@x', username: 'rrexp' } })
    await identities.softDelete(ok.id)
    await identities.softDelete(expired.id)

    // Wind this one's window shut. `softDelete` always stamps a deadline in the
    // future, so nothing in the public API can produce an expired row directly.
    const hidden = adapter.raw.identities.get(expired.id)
    if (hidden) hidden.deletedAt = new Date(Date.now() - 1000)

    // No clash case: a hidden row keeps its address and its logins until it is erased, so there is
    // nothing a restore can come back to find taken.
    const restored = await identities.restoreMany([ok.id, expired.id, 'missing-id'])

    expect(restored.map((row) => row.id)).toEqual([ok.id])
    await expect(identities.getById(expired.id)).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
  })

  it('a hard failure in restoreMany still aborts the batch', async () => {
    const { adapter, identities } = makeIdentities()
    const a = await identities.create({ profile: { email: 'hard@x', username: 'hard' } })
    await identities.softDelete(a.id)
    // Dropping the blanket catch means an unexpected error propagates again.
    // That is the documented hard/soft split - a driver fault is not a per-row
    // refusal - so pin it rather than let a future catch-all creep back in.
    adapter.identities.restore = () => Promise.reject(asAuthError(new Error('connection reset'), 'AUTH_ADAPTER_FAILED'))

    await expect(identities.restoreMany([a.id])).rejects.toMatchObject({
      cause: { message: 'connection reset' },
      code: 'AUTH_ADAPTER_FAILED',
    })
  })

  it('eraseMany answers each row as it stood just before it went', async () => {
    const { identities } = makeIdentities()
    const a = await identities.create({ profile: { email: 'e@x', username: 'e' } })

    const gone = await identities.eraseMany([a.id, 'missing-id'], { reason: 'test' })

    expect(gone).toEqual([a])
    await expect(identities.getById(a.id)).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
  })

  it('revokeByHashes answers the rows it removed, one event each', async () => {
    const { revoked, sessions } = makeSessions()
    const s1 = await sessions.create({ aal: 1, factors: [], identityId: 'i1', kind: 'user' })

    const gone = await sessions.revokeByHashes([s1.session.id, 'no-such-session'])

    expect(gone.map((s) => s.id)).toEqual([s1.session.id])
    expect(revoked).toHaveBeenCalledTimes(1)
  })
})
