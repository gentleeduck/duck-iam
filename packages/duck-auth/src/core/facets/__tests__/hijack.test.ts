/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { InMemoryEvents } from '../../events'
import type { Session } from '../../types/session'
import { HijackFacet } from '../hijack'

function makeSession(overrides: Partial<Session.ISession> = {}): Session.ISession {
  const now = Date.now()
  return {
    id: 'sid',
    identityId: 'u',
    kind: 'user',
    aal: 1,
    factors: [],
    createdAt: now,
    rotatedAt: now,
    expiresAt: now + 60_000,
    absoluteExpiresAt: now + 60_000,
    fresh: true,
    ip: '203.0.113.1',
    userAgent: 'Mozilla/5.0',
    ...overrides,
  }
}

describe('HijackFacet', () => {
  let events: InMemoryEvents

  beforeEach(() => {
    events = new InMemoryEvents()
  })

  it('returns ok:true when fingerprint matches', async () => {
    const facet = new HijackFacet(events)
    const r = await facet.evaluate(makeSession(), { ip: '203.0.113.1', userAgent: 'Mozilla/5.0' })
    expect(r.ok).toBe(true)
  })

  it('emits suspicious + reaction on IP change (default rotate)', async () => {
    const handler = vi.fn()
    events.on('suspicious', handler)
    const facet = new HijackFacet(events)
    const r = await facet.evaluate(makeSession(), { ip: '198.51.100.1', userAgent: 'Mozilla/5.0' })
    expect(handler).toHaveBeenCalledOnce()
    expect(handler.mock.calls[0]?.[0].signal).toBe('ip-change')
    expect(r).toMatchObject({ ok: false, reaction: 'rotate', signal: 'ip-change' })
  })

  it('emits suspicious + reaction on UA change (default mfa)', async () => {
    const handler = vi.fn()
    events.on('suspicious', handler)
    const facet = new HijackFacet(events)
    const r = await facet.evaluate(makeSession(), { ip: '203.0.113.1', userAgent: 'Different/1.0' })
    expect(handler).toHaveBeenCalledOnce()
    expect(r).toMatchObject({ ok: false, reaction: 'mfa', signal: 'user-agent-change' })
  })

  it('ignore reaction still emits suspicious but returns ok:true (audit only)', async () => {
    const handler = vi.fn()
    events.on('suspicious', handler)
    const facet = new HijackFacet(events, { onIpChange: 'ignore', onUserAgentChange: 'ignore' })
    const r = await facet.evaluate(makeSession(), { ip: '198.51.100.1', userAgent: 'Other/2.0' })
    expect(handler.mock.calls.length).toBe(2)
    expect(r.ok).toBe(true)
  })

  it('applyReaction translates mfa to AUTH/STEP_UP_REQUIRED', () => {
    const facet = new HijackFacet(events)
    expect(() => facet.applyReaction('mfa')).toThrow()
    try {
      facet.applyReaction('mfa')
    } catch (err) {
      expect((err as { code: string }).code).toBe('AUTH/STEP_UP_REQUIRED')
    }
  })

  it('applyReaction translates revoke to AUTH/SESSION_REVOKED', () => {
    const facet = new HijackFacet(events)
    try {
      facet.applyReaction('revoke')
      expect.fail('expected throw')
    } catch (err) {
      expect((err as { code: string }).code).toBe('AUTH/SESSION_REVOKED')
    }
  })

  it('applyReaction is a no-op for rotate + ignore', () => {
    const facet = new HijackFacet(events)
    expect(() => facet.applyReaction('rotate')).not.toThrow()
    expect(() => facet.applyReaction('ignore')).not.toThrow()
  })

  it('does not emit suspicious when only one fingerprint side is known', async () => {
    const handler = vi.fn()
    events.on('suspicious', handler)
    const facet = new HijackFacet(events)
    // Session has IP but request does not - cannot evaluate, no event
    await facet.evaluate(makeSession(), { userAgent: 'Mozilla/5.0' })
    expect(handler).not.toHaveBeenCalled()
  })
})
