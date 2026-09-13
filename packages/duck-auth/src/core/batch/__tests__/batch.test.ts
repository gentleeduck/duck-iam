import { describe, expect, it, vi } from 'vitest'
import { AdapterStore } from '~/adapters/adapter'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthError } from '~/core/errors'
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

describe('batch operations', () => {
  it('softDeleteMany reports one outcome per input id, in input order', async () => {
    const { identities } = makeIdentities()
    const a = await identities.create({ profile: { email: 'a@x', username: 'a' } })
    const b = await identities.create({ profile: { email: 'b@x', username: 'b' } })

    const result = await identities.softDeleteMany([a.id, 'missing-id', b.id])

    expect(result.outcomes).toHaveLength(3)
    expect(result.outcomes.map((o) => o.id)).toEqual([a.id, 'missing-id', b.id])
    expect(result.outcomes[0]?.ok).toBe(true)
    expect(result.outcomes[1]).toMatchObject({ ok: false, reason: 'not-found' })
    expect(result.applied).toBe(2)
    expect(result.failed).toBe(1)
  })

  it('updateProfileMany reports stale-write per row instead of throwing on the first', async () => {
    const { identities } = makeIdentities()
    const a = await identities.create({ profile: { email: 'a@x', username: 'a' } })
    const b = await identities.create({ profile: { email: 'b@x', username: 'b' } })

    const result = await identities.updateProfileMany([
      { expectedVersion: 999, id: a.id, patch: { username: 'a2' } },
      { expectedVersion: b.version, id: b.id, patch: { username: 'b2' } },
    ])

    expect(result.outcomes[0]).toMatchObject({ ok: false, reason: 'stale-write' })
    expect(result.outcomes[1]?.ok).toBe(true)
    expect(result.applied).toBe(1)
    expect(result.failed).toBe(1)
    // The winner really landed; the loser really did not.
    expect((await identities.getById(b.id))?.profile.username).toBe('b2')
    expect((await identities.getById(a.id))?.profile.username).toBe('a')
  })

  it('updateProfileMany reports a clash its own read found as a per-row outcome', async () => {
    const { identities } = makeIdentities()
    const holder = await identities.create({ profile: { email: 'held@x', username: 'held' } })
    const mover = await identities.create({ profile: { email: 'mover@x', username: 'mover' } })

    const result = await identities.updateProfileMany([
      { expectedVersion: mover.version, id: mover.id, patch: { email: 'held@x' } },
    ])

    expect(result.outcomes[0]).toMatchObject({ ok: false, reason: 'email-taken' })
    expect((await identities.getById(holder.id))?.profile.email).toBe('held@x')
  })

  /**
   * The same code from a driver is the opposite case. The statement has already run and failed, which on
   * postgres leaves the caller's transaction aborted: COMMIT turns into a silent ROLLBACK and every row the
   * batch reported as applied is gone. Carrying the driver error is what tells the two apart.
   */
  it('updateProfileMany rethrows the same code when a driver refused the write', async () => {
    const { adapter, identities } = makeIdentities()
    const a = await identities.create({ profile: { email: 'd@x', username: 'd' } })
    const refused = new AuthError('AUTH_EMAIL_TAKEN')
    refused.cause = new Error('duplicate key value violates unique constraint "uq_auth_identities_email"')
    adapter.identities.update = () => AdapterStore.answer(Promise.reject(refused))

    await expect(
      identities.updateProfileMany([{ expectedVersion: a.version, id: a.id, patch: { username: 'd2' } }]),
    ).rejects.toMatchObject({ code: 'AUTH_EMAIL_TAKEN' })
  })

  it('revokeAllForIdentities emits one session.revoked per actually-revoked session', async () => {
    const adapter = new MemoryAdapter<P>()
    const bus = new InMemoryEvents()
    const revoked = vi.fn(async () => {})
    bus.on('session.revoked', revoked)
    const sessions = new SessionsImpl(adapter.sessions, bus, DEFAULT_SESSION_CONFIG)

    await sessions.create({ aal: 1, factors: [], identityId: 'i1', kind: 'user' })
    await sessions.create({ aal: 1, factors: [], identityId: 'i1', kind: 'user' })
    await sessions.create({ aal: 1, factors: [], identityId: 'i2', kind: 'user' })

    const result = await sessions.revokeAllForIdentities(['i1', 'i2', 'i3-none'])

    expect(revoked).toHaveBeenCalledTimes(3)
    expect(result.outcomes).toHaveLength(3)
    expect(result.applied).toBe(2)
    expect(result.outcomes[2]).toMatchObject({ ok: false, reason: 'not-found' })
    expect(await adapter.sessions.listByIdentity('i1')).toEqual([])
  })

  it('a batch over an empty list is a no-op, not an error', async () => {
    const { identities } = makeIdentities()

    const result = await identities.softDeleteMany([])

    expect(result.outcomes).toEqual([])
    expect(result.applied).toBe(0)
  })

  it('a hard failure propagates rather than being reported as an outcome', async () => {
    const { adapter, identities } = makeIdentities()
    const a = await identities.create({ profile: { email: 'h@x', username: 'h' } })
    vi.spyOn(adapter.identities, 'softDelete').mockRejectedValue(new Error('connection lost'))

    await expect(identities.softDeleteMany([a.id])).rejects.toThrow('connection lost')
  })

  it('linkMany keeps outcomes distinct when one identity gains several links', async () => {
    const { identities } = makeIdentities()
    const a = await identities.create({ profile: { email: 'l@x', username: 'l' } })

    const result = await identities.linkMany([
      { identityId: a.id, link: { providerId: 'github', providerSub: 'gh-1' } },
      { identityId: a.id, link: { providerId: 'google', providerSub: 'go-1' } },
    ])

    expect(result.outcomes).toHaveLength(2)
    expect(result.applied).toBe(2)
    expect((await identities.getById(a.id))?.providers.map((p) => p.providerId).sort()).toEqual(['github', 'google'])
  })

  it('unlinkMany removes each named link', async () => {
    const { identities } = makeIdentities()
    const a = await identities.create({ profile: { email: 'u@x', username: 'u' } })
    await identities.link(a.id, { providerId: 'github', providerSub: 'gh-1' })
    await identities.link(a.id, { providerId: 'google', providerSub: 'go-1' })

    const result = await identities.unlinkMany([{ identityId: a.id, providerId: 'github' }])

    expect(result.applied).toBe(1)
    expect((await identities.getById(a.id))?.providers.map((p) => p.providerId)).toEqual(['google'])
  })

  it('restoreMany brings back soft-deleted identities and reports misses', async () => {
    const { identities } = makeIdentities()
    const a = await identities.create({ profile: { email: 'r@x', username: 'r' } })
    await identities.softDelete(a.id)

    const result = await identities.restoreMany([a.id, 'missing-id'])

    expect(result.applied).toBe(1)
    expect(result.outcomes[1]).toMatchObject({ ok: false, reason: 'not-found' })
    expect(await identities.getById(a.id)).not.toBeNull()
  })

  /**
   * The loop used to catch both of `restore`'s refusals and call them `not-found`. Only one of them
   * is absent; an expired row is still there, and a caller told `not-found` has no way to learn that.
   */
  it('restoreMany names the reason each row was refused', async () => {
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
    const result = await identities.restoreMany([ok.id, expired.id, 'missing-id'])

    expect(result.applied).toBe(1)
    expect(result.outcomes[0]?.ok).toBe(true)
    expect(result.outcomes[1]).toMatchObject({ ok: false, reason: 'grace-expired' })
    expect(result.outcomes[2]).toMatchObject({ ok: false, reason: 'not-found' })
    expect(await identities.getById(expired.id)).toBeNull()
  })

  it('a hard failure in restoreMany still aborts the batch', async () => {
    const { adapter, identities } = makeIdentities()
    const a = await identities.create({ profile: { email: 'hard@x', username: 'hard' } })
    await identities.softDelete(a.id)
    // Dropping the blanket catch means an unexpected error propagates again.
    // That is the documented hard/soft split - a driver fault is not a per-row
    // outcome - so pin it rather than let a future catch-all creep back in.
    adapter.identities.restore = () => AdapterStore.answer(Promise.reject(new Error('connection reset')))

    await expect(identities.restoreMany([a.id])).rejects.toMatchObject({
      cause: { message: 'connection reset' },
      code: 'AUTH_ADAPTER_FAILED',
    })
  })

  it('eraseMany hard-deletes each identity', async () => {
    const { identities } = makeIdentities()
    const a = await identities.create({ profile: { email: 'e@x', username: 'e' } })

    const result = await identities.eraseMany([a.id])

    expect(result.applied).toBe(1)
    expect(await identities.getById(a.id)).toBeNull()
  })

  it('revokeByHashes emits one session.revoked per row removed', async () => {
    const adapter = new MemoryAdapter<P>()
    const bus = new InMemoryEvents()
    const revoked = vi.fn(async () => {})
    bus.on('session.revoked', revoked)
    const sessions = new SessionsImpl(adapter.sessions, bus, DEFAULT_SESSION_CONFIG)
    const s1 = await sessions.create({ aal: 1, factors: [], identityId: 'i1', kind: 'user' })

    const result = await sessions.revokeByHashes([s1.session.id, 'no-such-session'])

    expect(result.applied).toBe(1)
    expect(result.outcomes[1]).toMatchObject({ ok: false, reason: 'not-found' })
    expect(revoked).toHaveBeenCalledTimes(1)
  })
})
