import { describe, expect, it, vi } from 'vitest'
import type { Sessions } from '~/core/sessions/sessions.types'
import { auditEnvelopeFor, runWithAuditEnvelope, withAuditStamping } from '../events.audit'
import { InMemoryEvents } from '../events.memory'

function actingAs(realIdentityId: string): Sessions.ActingAs {
  return {
    expiresAt: new Date(Date.now() + 60_000),
    realIdentityId,
    reason: 'support-ticket-1',
    startedAt: new Date(),
  }
}

describe('withAuditStamping', () => {
  it('stamps actingAs from the emitted session when no ambient envelope is set', async () => {
    const bus = withAuditStamping(new InMemoryEvents())
    const handler = vi.fn()
    bus.on('session.created', handler)

    await bus.emit('session.created', {
      identity: null,
      session: { actingAs: actingAs('admin-1'), id: 's1' } as Sessions.Me,
    })

    expect(handler.mock.calls[0]?.[0].audit?.actingAs?.realIdentityId).toBe('admin-1')
  })

  it('leaves audit absent for a session that is not impersonating', async () => {
    const bus = withAuditStamping(new InMemoryEvents())
    const handler = vi.fn()
    bus.on('session.created', handler)

    await bus.emit('session.created', { identity: null, session: { actingAs: null, id: 's1' } as Sessions.Me })

    expect(handler.mock.calls[0]?.[0].audit).toBeUndefined()
  })

  it('stamps session-less events from the ambient envelope', async () => {
    const bus = withAuditStamping(new InMemoryEvents())
    const handler = vi.fn()
    bus.on('mfa.enrolled', handler)

    await runWithAuditEnvelope({ actingAs: actingAs('admin-2') }, async () => {
      await bus.emit('mfa.enrolled', { identityId: 'user-1', method: 'totp' })
    })

    expect(handler.mock.calls[0]?.[0].audit?.actingAs?.realIdentityId).toBe('admin-2')
  })

  it('never overwrites an envelope the emitter supplied explicitly', async () => {
    const bus = withAuditStamping(new InMemoryEvents())
    const handler = vi.fn()
    bus.on('mfa.enrolled', handler)

    await runWithAuditEnvelope({ actingAs: actingAs('ambient') }, async () => {
      await bus.emit('mfa.enrolled', {
        audit: { actingAs: actingAs('explicit') },
        identityId: 'user-1',
        method: 'totp',
      })
    })

    expect(handler.mock.calls[0]?.[0].audit?.actingAs?.realIdentityId).toBe('explicit')
  })

  it('does not stamp events whose payload has no audit field', async () => {
    const bus = withAuditStamping(new InMemoryEvents())
    const handler = vi.fn()
    bus.on('identity.impersonated', handler)

    await runWithAuditEnvelope({ actingAs: actingAs('admin-3') }, async () => {
      await bus.emit('identity.impersonated', {
        realIdentityId: 'admin-3',
        reason: 'r',
        targetIdentityId: 'user-1',
      })
    })

    expect(handler.mock.calls[0]?.[0]).not.toHaveProperty('audit')
  })

  it('keeps envelopes isolated across concurrent interleaved flows', async () => {
    const bus = withAuditStamping(new InMemoryEvents())
    const seen: Array<string | undefined> = []
    bus.on('mfa.enrolled', (p) => {
      seen.push(p.audit?.actingAs?.realIdentityId)
    })

    const flow = async (admin: string | null, delayMs: number): Promise<void> => {
      const envelope = admin === null ? undefined : { actingAs: actingAs(admin) }
      await runWithAuditEnvelope(envelope, async () => {
        await new Promise((r) => setTimeout(r, delayMs))
        await bus.emit('mfa.enrolled', { identityId: `u-${admin ?? 'none'}`, method: 'totp' })
      })
    }

    await Promise.all([flow('admin-a', 12), flow(null, 4), flow('admin-b', 8)])

    // Ordered by delay: the un-impersonated flow lands first, then b, then a.
    expect(seen).toEqual([undefined, 'admin-b', 'admin-a'])
  })

  it('forwards listenerCount so AuthEngine.strict keeps its lockout gate', async () => {
    const inner = new InMemoryEvents()
    const bus = withAuditStamping(inner) as typeof inner
    expect(bus.listenerCount('lockout')).toBe(0)
    bus.on('lockout', vi.fn())
    expect(bus.listenerCount('lockout')).toBe(1)
  })
})

describe('auditEnvelopeFor', () => {
  it('returns undefined for a null, absent, or non-impersonating session', () => {
    expect(auditEnvelopeFor(null)).toBeUndefined()
    expect(auditEnvelopeFor(undefined)).toBeUndefined()
    expect(auditEnvelopeFor({ actingAs: null })).toBeUndefined()
  })

  it('wraps actingAs when the session is impersonating', () => {
    const a = actingAs('admin-4')
    expect(auditEnvelopeFor({ actingAs: a })).toEqual({ actingAs: a })
  })
})
