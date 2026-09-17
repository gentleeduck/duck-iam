import { afterEach, describe, expect, it } from 'vitest'
import { setDefaultActorResolver, withActor } from '~/core/actor'
import type { Events } from '~/core/events'
import { InMemoryEvents, withAuditStamping } from '~/core/events'

afterEach(() => setDefaultActorResolver(undefined))

/**
 * A payload's `identityId` is the subject. Without an operator on the envelope
 * "admin X revoked user Y's session" and "user Y revoked their own" are the
 * same event, which is the one question a consumer's audit log exists to answer.
 */
describe('audited events carry the operator', () => {
  function capture() {
    const target = new InMemoryEvents()
    const seen: Events.Envelope[] = []
    target.on('session.revoked', async (p) => {
      if (p.audit) seen.push(p.audit)
    })
    return { bus: withAuditStamping(target), seen }
  }

  it('stamps the ambient actor onto an audited event', async () => {
    const { bus, seen } = capture()
    await withActor('admin-1', () => bus.emit('session.revoked', { identityId: 'user-9', sessionId: 's1' }))
    expect(seen[0]?.actorId).toBe('admin-1')
  })

  it('falls back to the configured resolver', async () => {
    setDefaultActorResolver(() => 'svc-cleanup')
    const { bus, seen } = capture()
    await bus.emit('session.revoked', { identityId: 'user-9', sessionId: 's1' })
    expect(seen[0]?.actorId).toBe('svc-cleanup')
  })

  it('adds no envelope at all when nothing is bound', async () => {
    const { bus, seen } = capture()
    await bus.emit('session.revoked', { identityId: 'user-9', sessionId: 's1' })
    // The hot path stays allocation-free when there is nothing to say.
    expect(seen).toEqual([])
  })

  it('an envelope the caller already set is never overwritten', async () => {
    const { bus, seen } = capture()
    await withActor('ambient', () =>
      bus.emit('session.revoked', { audit: { actorId: 'explicit' }, identityId: 'u', sessionId: 's' }),
    )
    expect(seen[0]?.actorId).toBe('explicit')
  })
})
