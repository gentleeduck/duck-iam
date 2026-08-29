/**
 * Hijack detection decides whether a request carrying a valid session is
 * challenged, rotated, or let through. It is a policy engine, and the way a
 * policy engine fails is by resolving the wrong way at a boundary: taking the
 * weaker of two signals, treating a stripped header as agreement, or downgrading
 * something the operator asked to be fatal.
 *
 * The comparison is deliberately three-state. Both sides absent is agreement,
 * both present and different is a mismatch, and exactly one present is
 * "asymmetric", which is softened one notch so a proxy that drops a header does
 * not force every guest through MFA. That softening is the part most worth
 * pinning: it is a deliberate weakening, and it should apply only where intended.
 */
import { describe, expect, it } from 'vitest'
import { InMemoryEvents } from '~/core/events'
import type { Sessions } from '~/core/sessions/sessions.types'
import { HijackFacet } from '../hijack.facet'
import type { Hijack } from '../hijack.types'

const BASE_IP = '203.0.113.10'
const OTHER_IP = '198.51.100.7'
const BASE_UA = 'Mozilla/5.0 (Macintosh) Safari/605'
const OTHER_UA = 'curl/8.4.0'

function session(over: Partial<Sessions.Me> = {}): Sessions.Me {
  const now = new Date()
  return {
    aal: 1,
    absoluteExpiresAt: new Date(now.getTime() + 86_400_000),
    actingAs: null,
    createdAt: now,
    csrfHash: null,
    expiresAt: new Date(now.getTime() + 60_000),
    factors: [],
    fingerprint: null,
    fresh: true,
    id: 'sess-1',
    identityId: 'user-1',
    ip: BASE_IP,
    kind: 'user',
    rotatedAt: now,
    tenantId: null,
    userAgent: BASE_UA,
    ...over,
  }
}

/** A facet plus the suspicious events it emitted. */
function makeFacet(policy: Partial<Hijack.Cfg> = {}) {
  const events = new InMemoryEvents()
  const emitted: Array<{ signal: string; score: number; meta: Record<string, unknown> }> = []
  events.on('suspicious', (payload) => {
    emitted.push(payload as never)
  })
  return { emitted, facet: new HijackFacet(events, policy) }
}

describe('a request that matches the session is let through', () => {
  it('passes when both values are identical', async () => {
    const { facet, emitted } = makeFacet()
    expect(await facet.evaluate(session(), { ip: BASE_IP, userAgent: BASE_UA })).toEqual({ ok: true })
    expect(emitted).toHaveLength(0)
  })

  it('passes when both sides have no ip and no user agent', async () => {
    const { facet } = makeFacet()
    const guest = session({ ip: null, userAgent: null })
    expect(await facet.evaluate(guest, { ip: null, userAgent: null })).toEqual({ ok: true })
  })

  it('treats null and undefined as the same absence', async () => {
    // A caller that omits the field and one that passes null must be read alike,
    // or an ordinary request becomes a drift signal.
    const { facet, emitted } = makeFacet()
    const guest = session({ ip: null, userAgent: null })
    expect(await facet.evaluate(guest, {})).toEqual({ ok: true })
    expect(await facet.evaluate(guest, { ip: undefined, userAgent: undefined })).toEqual({ ok: true })
    expect(emitted).toHaveLength(0)
  })

  it('compares exactly, so a differing case or trailing space is drift', async () => {
    const { facet } = makeFacet()
    expect(await facet.evaluate(session(), { ip: BASE_IP, userAgent: `${BASE_UA} ` })).not.toEqual({ ok: true })
    expect(await facet.evaluate(session(), { ip: BASE_IP, userAgent: BASE_UA.toUpperCase() })).not.toEqual({
      ok: true,
    })
  })
})

describe('a changed value is drift', () => {
  it('reacts to an ip change with the configured reaction', async () => {
    const { facet } = makeFacet({ onIpChange: 'revoke', onUserAgentChange: 'ignore' })
    expect(await facet.evaluate(session(), { ip: OTHER_IP, userAgent: BASE_UA })).toMatchObject({
      ok: false,
      reaction: 'revoke',
      signal: 'ip-change',
    })
  })

  it('reacts to a user agent change with the configured reaction', async () => {
    const { facet } = makeFacet({ onIpChange: 'ignore', onUserAgentChange: 'mfa' })
    expect(await facet.evaluate(session(), { ip: BASE_IP, userAgent: OTHER_UA })).toMatchObject({
      ok: false,
      reaction: 'mfa',
      signal: 'user-agent-change',
    })
  })

  it('carries the before and after values for the operator', async () => {
    const { facet } = makeFacet({ onIpChange: 'mfa' })
    expect(await facet.evaluate(session(), { ip: OTHER_IP, userAgent: BASE_UA })).toMatchObject({
      from: BASE_IP,
      to: OTHER_IP,
    })
  })

  it('emits a suspicious signal per drift, not one for the pair', async () => {
    const { facet, emitted } = makeFacet({ onIpChange: 'mfa', onUserAgentChange: 'mfa' })
    await facet.evaluate(session(), { ip: OTHER_IP, userAgent: OTHER_UA })
    expect(emitted.map((e) => e.signal).sort()).toEqual(['ip-change', 'user-agent-change'])
  })

  it('scores a user agent change above an ip change', async () => {
    // A travelling user changes address constantly; a changed browser string on
    // a live session is the stronger signal.
    const { facet, emitted } = makeFacet({ onIpChange: 'mfa', onUserAgentChange: 'mfa' })
    await facet.evaluate(session(), { ip: OTHER_IP, userAgent: OTHER_UA })
    const ip = emitted.find((e) => e.signal === 'ip-change')
    const ua = emitted.find((e) => e.signal === 'user-agent-change')
    expect((ua?.score ?? 0) > (ip?.score ?? 0)).toBe(true)
  })

  it('emits even when the policy is to ignore, so audit still sees it', async () => {
    // The reaction is what the caller does; the signal is what the operator sees.
    // Suppressing the reaction must not suppress the record.
    const { facet, emitted } = makeFacet({ onIpChange: 'ignore', onUserAgentChange: 'ignore' })
    expect(await facet.evaluate(session(), { ip: OTHER_IP, userAgent: OTHER_UA })).toEqual({ ok: true })
    expect(emitted).toHaveLength(2)
  })
})

describe('when both signals fire, the stronger reaction wins', () => {
  const cases = [
    { expected: 'revoke', ip: 'revoke', ua: 'ignore' },
    { expected: 'revoke', ip: 'ignore', ua: 'revoke' },
    { expected: 'revoke', ip: 'revoke', ua: 'mfa' },
    { expected: 'revoke', ip: 'mfa', ua: 'revoke' },
    { expected: 'mfa', ip: 'mfa', ua: 'rotate' },
    { expected: 'mfa', ip: 'rotate', ua: 'mfa' },
    { expected: 'rotate', ip: 'rotate', ua: 'ignore' },
    { expected: 'rotate', ip: 'ignore', ua: 'rotate' },
  ] as const

  for (const { expected, ip, ua } of cases) {
    it(`resolves ip:${ip} and ua:${ua} to ${expected}`, async () => {
      // The failure this guards: taking the first drift, or the weaker one, and
      // letting a revoke-worthy change through as a rotation.
      const { facet } = makeFacet({ onIpChange: ip, onUserAgentChange: ua })
      expect(await facet.evaluate(session(), { ip: OTHER_IP, userAgent: OTHER_UA })).toMatchObject({
        ok: false,
        reaction: expected,
      })
    })
  }

  it('lets the request through only when both are ignore', async () => {
    const { facet } = makeFacet({ onIpChange: 'ignore', onUserAgentChange: 'ignore' })
    expect(await facet.evaluate(session(), { ip: OTHER_IP, userAgent: OTHER_UA })).toEqual({ ok: true })
  })
})

describe('one side missing is softened, deliberately', () => {
  it('downgrades a missing request ip from revoke to rotate', async () => {
    // A proxy that strips a header must not revoke every session behind it.
    const { facet } = makeFacet({ onIpChange: 'revoke', onUserAgentChange: 'ignore' })
    expect(await facet.evaluate(session(), { ip: null, userAgent: BASE_UA })).toMatchObject({
      ok: false,
      reaction: 'rotate',
    })
  })

  it('downgrades a missing baseline ip the same way', async () => {
    const { facet } = makeFacet({ onIpChange: 'mfa', onUserAgentChange: 'ignore' })
    expect(await facet.evaluate(session({ ip: null }), { ip: OTHER_IP, userAgent: BASE_UA })).toMatchObject({
      reaction: 'rotate',
    })
  })

  it('downgrades a missing user agent from mfa to rotate', async () => {
    const { facet } = makeFacet({ onIpChange: 'ignore', onUserAgentChange: 'mfa' })
    expect(await facet.evaluate(session(), { ip: BASE_IP, userAgent: null })).toMatchObject({ reaction: 'rotate' })
  })

  it('leaves an explicit ignore alone rather than promoting it', async () => {
    const { facet } = makeFacet({ onIpChange: 'ignore', onUserAgentChange: 'ignore' })
    expect(await facet.evaluate(session(), { ip: null, userAgent: null })).toEqual({ ok: true })
  })

  it('leaves rotate at rotate', async () => {
    const { facet } = makeFacet({ onIpChange: 'rotate', onUserAgentChange: 'ignore' })
    expect(await facet.evaluate(session(), { ip: null, userAgent: BASE_UA })).toMatchObject({ reaction: 'rotate' })
  })

  it('FINDING: a stripped header softens a revoke even when the other signal is a real mismatch', async () => {
    // The asymmetric downgrade is per-signal. An attacker on a different address
    // who also omits the User-Agent turns a `revoke` on user-agent-change into a
    // `rotate`, and the surviving reaction is whatever the ip policy says. With
    // the default policy (ip: rotate, ua: mfa) the result is `rotate` rather than
    // the `mfa` an operator configured for a changed browser. Sending no header
    // is entirely within an attacker's control.
    const { facet } = makeFacet({ onIpChange: 'rotate', onUserAgentChange: 'mfa' })
    const stripped = await facet.evaluate(session(), { ip: OTHER_IP, userAgent: null })
    expect(stripped).toMatchObject({ ok: false, reaction: 'rotate' })

    // Whereas presenting a different user agent honestly gets the stronger answer.
    const honest = await facet.evaluate(session(), { ip: OTHER_IP, userAgent: OTHER_UA })
    expect(honest).toMatchObject({ ok: false, reaction: 'mfa' })
  })
})

describe('diagnostic values are capped before they reach a sink', () => {
  it('passes a normal user agent through unchanged', async () => {
    const { facet, emitted } = makeFacet({ onUserAgentChange: 'mfa' })
    await facet.evaluate(session(), { ip: BASE_IP, userAgent: OTHER_UA })
    expect(emitted[0]?.meta).toMatchObject({ from: BASE_UA, to: OTHER_UA })
  })

  it('truncates an oversize header rather than shipping kilobytes per drift', async () => {
    const { facet, emitted } = makeFacet({ onUserAgentChange: 'mfa' })
    const huge = 'U'.repeat(10_000)
    const result = await facet.evaluate(session(), { ip: BASE_IP, userAgent: huge })

    expect((emitted[0]?.meta.to as string).length).toBeLessThan(300)
    expect(emitted[0]?.meta.to).toContain('...(truncated)')
    expect((result as { to: string }).to).toContain('...(truncated)')
  })

  it('keeps a value exactly at the limit intact', async () => {
    const { facet, emitted } = makeFacet({ onUserAgentChange: 'mfa' })
    const exact = 'U'.repeat(256)
    await facet.evaluate(session(), { ip: BASE_IP, userAgent: exact })
    expect(emitted[0]?.meta.to).toBe(exact)
  })

  it('renders a missing side as an empty string rather than the word undefined', async () => {
    const { facet, emitted } = makeFacet({ onUserAgentChange: 'mfa' })
    await facet.evaluate(session(), { ip: BASE_IP, userAgent: null })
    expect(emitted[0]?.meta.to).toBe('')
  })

  it('carries an injection payload as data', async () => {
    const { facet, emitted } = makeFacet({ onUserAgentChange: 'mfa' })
    const payload = `'; DROP TABLE auth_sessions; --`
    await facet.evaluate(session(), { ip: BASE_IP, userAgent: payload })
    expect(emitted[0]?.meta.to).toBe(payload)
  })
})

describe('a guest session with no identity still reports', () => {
  it('emits without an identityId rather than a null one', async () => {
    const { facet, emitted } = makeFacet({ onIpChange: 'mfa' })
    await facet.evaluate(session({ identityId: null }), { ip: OTHER_IP, userAgent: BASE_UA })
    expect(emitted).toHaveLength(1)
    expect(emitted[0]).not.toHaveProperty('identityId')
  })
})

describe('applyReaction turns a decision into the caller’s throw', () => {
  it('throws a step-up requirement for mfa', () => {
    const { facet } = makeFacet()
    expect(() => facet.applyReaction('mfa')).toThrow(/AUTH_STEP_UP_REQUIRED/)
  })

  it('throws a revocation for revoke', () => {
    const { facet } = makeFacet()
    expect(() => facet.applyReaction('revoke')).toThrow(/AUTH_SESSION_REVOKED/)
  })

  it('does not throw for rotate, which the caller handles itself', () => {
    const { facet } = makeFacet()
    expect(() => facet.applyReaction('rotate')).not.toThrow()
  })

  it('does not throw for ignore', () => {
    const { facet } = makeFacet()
    expect(() => facet.applyReaction('ignore')).not.toThrow()
  })

  it('names the policy as the reason, so the cause is legible downstream', () => {
    const { facet } = makeFacet()
    try {
      facet.applyReaction('revoke')
    } catch (err) {
      expect((err as { meta: { reason: string } }).meta.reason).toBe('hijack-policy')
    }
  })
})

describe('the shipped defaults', () => {
  it('rotate on an ip change and step up on a user agent change', async () => {
    const { facet } = makeFacet()
    expect(await facet.evaluate(session(), { ip: OTHER_IP, userAgent: BASE_UA })).toMatchObject({
      reaction: 'rotate',
    })
    expect(await facet.evaluate(session(), { ip: BASE_IP, userAgent: OTHER_UA })).toMatchObject({ reaction: 'mfa' })
  })

  it('resolve to the user agent reaction when both change', async () => {
    const { facet } = makeFacet()
    expect(await facet.evaluate(session(), { ip: OTHER_IP, userAgent: OTHER_UA })).toMatchObject({
      reaction: 'mfa',
      signal: 'user-agent-change',
    })
  })
})
