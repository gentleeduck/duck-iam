import { afterEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { setDefaultActorResolver, withActor } from '~/core/actor'
import { createAuth } from '~/core/config/config'
import type { Events } from '~/core/events'
import { InMemoryEvents, runWithAuditEnvelope, withAuditStamping } from '~/core/events'

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

  it('keeps the operator an ambient envelope names over the bound actor', async () => {
    const { bus, seen } = capture()
    await runWithAuditEnvelope({ actorId: 'svc-reaper' }, () =>
      withActor('user-9', () => bus.emit('session.revoked', { identityId: 'user-9', sessionId: 's1' })),
    )
    expect(seen).toEqual([{ actorId: 'svc-reaper' }])
  })
})

describe('an erasure reaches the audit log with its operator', () => {
  async function setup() {
    const adapter = new MemoryAdapter()
    const stores = { identities: adapter.identities, sessions: adapter.sessions, credentials: adapter.credentials }
    const auth = createAuth({ baseUrl: 'https://x.test', stores: { ...stores, withClient: () => stores } })
    const erased: Events.EventMap['identity.erased'][] = []
    auth.events.on('identity.erased', async (p) => {
      erased.push(p)
    })
    const ids = await Promise.all(
      ['a', 'b', 'c', 'd'].map(
        async (u) => (await auth.identities.create({ profile: { email: `${u}@x.test`, username: u } })).id,
      ),
    )
    return { auth, erased, ids }
  }

  it('erase and eraseMany emit one event per row, stamped with the operator only when one is given', async () => {
    const { auth, erased, ids } = await setup()
    await auth.identities.erase(ids[0]!, { operatorId: 'op-1', reason: 'gdpr' })
    await auth.identities.eraseMany([ids[1]!, ids[2]!], { operatorId: 'op-3', reason: 'bulk' })
    await auth.identities.erase(ids[3]!, { reason: 'plain' })
    expect(erased).toEqual([
      { audit: { actorId: 'op-1' }, identityId: ids[0], reason: 'gdpr' },
      { audit: { actorId: 'op-3' }, identityId: ids[1], reason: 'bulk' },
      { audit: { actorId: 'op-3' }, identityId: ids[2], reason: 'bulk' },
      { identityId: ids[3], reason: 'plain' },
    ])
  })

  it('in a transaction the operator is stamped at the call, not lost by a flush outside its scope', async () => {
    const { auth, erased, ids } = await setup()
    const tx = auth.withTransaction({})
    await tx.identities.erase(ids[0]!, { operatorId: 'op-2', reason: 'gdpr' })
    await withActor('outer', () => tx.identities.eraseMany([ids[1]!], { reason: 'bulk' }))
    await tx.identities.erase(ids[2]!, { reason: 'plain' })
    expect(erased).toEqual([])
    await tx.pending.flush()
    expect(erased).toEqual([
      { audit: { actorId: 'op-2' }, identityId: ids[0], reason: 'gdpr' },
      { audit: { actorId: 'outer' }, identityId: ids[1], reason: 'bulk' },
      { identityId: ids[2], reason: 'plain' },
    ])
  })
})
