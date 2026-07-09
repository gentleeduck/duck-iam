import { beforeEach, describe, expect, it } from 'vitest'
import { InMemoryEvents } from '~/core/events'
import type { Session } from '~/core/types/session'
import { HijackFacet } from '../hijack.facet'

function fakeSession(overrides: Partial<Session.Me> = {}): Session.Me {
  const now = Date.now()
  return {
    id: 'sess-1',
    identityId: 'user-1',
    kind: 'user',
    aal: 1,
    factors: [{ method: 'password', completedAt: new Date(now) }],
    createdAt: new Date(now),
    rotatedAt: new Date(now),
    expiresAt: new Date(now + 60_000),
    absoluteExpiresAt: new Date(now + 60_000),
    fresh: true,
    tenantId: null,
    csrfHash: null,
    ip: null,
    userAgent: null,
    fingerprint: null,
    actingAs: null,
    ...overrides,
  }
}

describe('HijackFacet - diagnostic-string clip', () => {
  let events: InMemoryEvents
  let facet: HijackFacet
  let seen: Array<{ from: string; to: string }>

  beforeEach(() => {
    events = new InMemoryEvents()
    facet = new HijackFacet(events, { onIpChange: 'mfa', onUserAgentChange: 'mfa' })
    seen = []
    events.on('suspicious', (payload) => {
      const meta = payload.meta as { from?: unknown; to?: unknown }
      if (typeof meta.from === 'string' && typeof meta.to === 'string') {
        seen.push({ from: meta.from, to: meta.to })
      }
    })
  })

  it('passes through normal-length values unchanged', async () => {
    const session = fakeSession({ ip: '1.1.1.1', userAgent: 'Mozilla/5.0' })
    const result = await facet.evaluate(session, { ip: '2.2.2.2', userAgent: 'curl/7.84.0' })
    expect(result.ok).toBe(false)
    expect(seen).toHaveLength(2) // ip-change + user-agent-change
    for (const e of seen) {
      expect(e.from.length).toBeLessThanOrEqual(256)
      expect(e.to.length).toBeLessThanOrEqual(256)
    }
  })

  it('clips an 8 KiB User-Agent to <=256 chars + truncation marker', async () => {
    const evilUa = 'A'.repeat(8 * 1024)
    const session = fakeSession({ userAgent: 'Mozilla/5.0' })
    const result = await facet.evaluate(session, { ip: session.ip, userAgent: evilUa })
    expect(result.ok).toBe(false)
    if (result.ok === false) {
      expect(result.to.length).toBeLessThan(280)
      expect(result.to).toContain('...(truncated)')
    }
    // The same clipping applies on the emit payload.
    expect(seen).toHaveLength(1)
    expect(seen[0]!.to.length).toBeLessThan(280)
    expect(seen[0]!.to).toContain('...(truncated)')
  })

  it('clips an oversized IP (e.g. spoofed multi-MB X-Forwarded-For chain)', async () => {
    const evilIp = '1.2.3.4,'.repeat(5000)
    const session = fakeSession({ ip: '5.5.5.5', userAgent: 'curl/8' })
    const result = await facet.evaluate(session, { ip: evilIp, userAgent: session.userAgent })
    expect(result.ok).toBe(false)
    if (result.ok === false) {
      expect(result.to.length).toBeLessThan(280)
    }
  })

  it('emits both drifts with bounded meta (ip + UA both oversize)', async () => {
    const evilUa = 'U'.repeat(10_000)
    const evilIp = '9.'.repeat(5000)
    const session = fakeSession({ ip: '1.1.1.1', userAgent: 'Mozilla/5.0' })
    await facet.evaluate(session, { ip: evilIp, userAgent: evilUa })
    expect(seen).toHaveLength(2)
    for (const e of seen) {
      expect(e.from.length).toBeLessThan(280)
      expect(e.to.length).toBeLessThan(280)
    }
  })

  it('content of clipped value still includes the prefix (operators can read the partial)', async () => {
    const distinctive = 'BEGIN-MARKER-' + 'X'.repeat(8000)
    const session = fakeSession({ userAgent: 'Mozilla/5.0' })
    await facet.evaluate(session, { ip: session.ip, userAgent: distinctive })
    expect(seen).toHaveLength(1)
    expect(seen[0]!.to.startsWith('BEGIN-MARKER-')).toBe(true)
  })

  it('256-char value is NOT clipped (boundary)', async () => {
    const exactly256 = 'X'.repeat(256)
    const session = fakeSession({ userAgent: 'Mozilla/5.0' })
    await facet.evaluate(session, { ip: session.ip, userAgent: exactly256 })
    expect(seen).toHaveLength(1)
    expect(seen[0]!.to).toBe(exactly256)
    expect(seen[0]!.to).not.toContain('...(truncated)')
  })
})
