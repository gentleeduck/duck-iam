import { beforeEach, describe, expect, it, vi } from 'vitest'
import { InMemoryEvents } from '~/core/events'
import type { Session } from '~/core/types/session'
import { HijackFacet } from '../hijack'

function makeSession(overrides: Partial<Session.Me> = {}): Session.Me {
  const now = Date.now()
  return {
    id: 'sid',
    identityId: 'u',
    kind: 'user',
    aal: 1,
    factors: [],
    createdAt: new Date(now),
    rotatedAt: new Date(now),
    expiresAt: new Date(now + 60_000),
    absoluteExpiresAt: new Date(now + 60_000),
    fresh: true,
    tenantId: null,
    csrfHash: null,
    ip: '203.0.113.1',
    userAgent: 'Mozilla/5.0',
    fingerprint: null,
    actingAs: null,
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
      expect((err as { code: string }).code).toBe('AUTH_STEP_UP_REQUIRED')
    }
  })

  it('applyReaction translates revoke to AUTH/SESSION_REVOKED', () => {
    const facet = new HijackFacet(events)
    try {
      facet.applyReaction('revoke')
      expect.fail('expected throw')
    } catch (err) {
      expect((err as { code: string }).code).toBe('AUTH_SESSION_REVOKED')
    }
  })

  it('applyReaction is a no-op for rotate + ignore', () => {
    const facet = new HijackFacet(events)
    expect(() => facet.applyReaction('rotate')).not.toThrow()
    expect(() => facet.applyReaction('ignore')).not.toThrow()
  })

  it('asymmetric drift (one side missing) still emits suspicious + downgrades to rotate', async () => {
    const handler = vi.fn()
    events.on('suspicious', handler)
    const facet = new HijackFacet(events, { onIpChange: 'mfa' })
    // Session has IP but request does not - asymmetric drift. The
    // configured `'mfa'` reaction is downgraded to `'rotate'` so a
    // request behind a UA-stripping proxy doesn't force MFA, but the
    // audit pipeline still sees the drift.
    const r = await facet.evaluate(makeSession(), { userAgent: 'Mozilla/5.0' })
    expect(handler).toHaveBeenCalled()
    if (r.ok) throw new Error('expected ok:false')
    expect(r.reaction).toBe('rotate')
  })

  it('both IP and UA differ - strongest reaction wins, both suspicious events emit', async () => {
    const handler = vi.fn()
    events.on('suspicious', handler)
    // Default: onIpChange='rotate', onUserAgentChange='mfa'. UA wins.
    const facet = new HijackFacet(events)
    const r = await facet.evaluate(makeSession({ ip: '1.1.1.1', userAgent: 'Mozilla/5.0' }), {
      ip: '2.2.2.2',
      userAgent: 'curl/8.0',
    })
    expect(handler).toHaveBeenCalledTimes(2)
    if (r.ok) throw new Error('expected ok:false')
    expect(r.reaction).toBe('mfa')
    expect(r.signal).toBe('user-agent-change')
  })
})
