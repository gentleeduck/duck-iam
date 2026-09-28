/**
 * Hijack detection decides whether a request carrying a valid session is
 * challenged, rotated, or let through. It is a policy engine, and the way a
 * policy engine fails is by resolving the wrong way at a boundary: taking the
 * weaker of two signals, treating a stripped header as agreement, or downgrading
 * something the operator asked to be fatal.
 */
import { describe, expect, it, vi } from 'vitest'
import { answer } from '~/core/answer'
import { AuthError } from '~/core/errors'
import { InMemoryEvents } from '~/core/events'
import type { Events } from '~/core/events/events.types'
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
    updatedAt: now,
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

/** A facet, the suspicious events it emitted, and the sessions it revoked, with `revoke` as the store. */
function makeFacet(policy: Hijack.Cfg = {}, revoke = async (id: string): Promise<Sessions.Me> => session({ id })) {
  const events = new InMemoryEvents()
  const emitted: Array<Events.EventMap['suspicious']> = []
  events.on('suspicious', (payload) => {
    emitted.push(payload)
  })
  const revoked: string[] = []
  const sessions = {
    revokeByHash: (id: string) =>
      answer(() => {
        revoked.push(id)
        return revoke(id)
      }),
  }
  return { emitted, facet: new HijackFacet(events, sessions, policy), revoked }
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

  it('reacts as configured when the sink rejects, logging each drift it could not record', async () => {
    const emit = vi.spyOn(InMemoryEvents.prototype, 'emit').mockRejectedValue(new Error('sink down'))
    const log = vi.spyOn(console, 'error').mockImplementation(() => {})
    const drifted = { ip: OTHER_IP, userAgent: OTHER_UA }
    try {
      const revoking = makeFacet({ onIpChange: 'revoke', onUserAgentChange: 'ignore' }).facet
      expect(await revoking.evaluate(session(), drifted)).toMatchObject({ ok: false, reaction: 'revoke' })
      const ignoring = makeFacet({ onIpChange: 'ignore', onUserAgentChange: 'ignore' }).facet
      expect(await ignoring.evaluate(session(), drifted)).toEqual({ ok: true })
      // The first drift's rejection does not skip the second's emit.
      expect(emit).toHaveBeenCalledTimes(4)
      expect(log).toHaveBeenCalledTimes(4)
    } finally {
      emit.mockRestore()
      log.mockRestore()
    }
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

  it('still softens a stripped header under the default, which is what a proxy needs', async () => {
    const { facet } = makeFacet({ onIpChange: 'rotate', onUserAgentChange: 'mfa' })
    const stripped = await facet.evaluate(session(), { ip: OTHER_IP, userAgent: null })
    expect(stripped).toMatchObject({ ok: false, reaction: 'rotate' })

    // Presenting a different user agent honestly has always got the stronger answer.
    const honest = await facet.evaluate(session(), { ip: OTHER_IP, userAgent: OTHER_UA })
    expect(honest).toMatchObject({ ok: false, reaction: 'mfa' })
  })
})

describe('strict closes the free downgrade a dropped header used to buy', () => {
  it('carries the configured reaction in full when the request omits the value', async () => {
    // Under `soften` an attacker on another address who also drops the User-Agent turns the `mfa`
    // configured for a changed browser into a `rotate` - and rotating leaves a stolen session in
    // the attacker's hands under a new id.
    const { facet } = makeFacet({ onIpChange: 'rotate', onMissingSignal: 'strict', onUserAgentChange: 'mfa' })
    expect(await facet.evaluate(session(), { ip: OTHER_IP, userAgent: null })).toMatchObject({
      ok: false,
      reaction: 'mfa',
    })
  })

  it('escalates a stripped ip to the full revoke as well', async () => {
    const { facet } = makeFacet({ onIpChange: 'revoke', onMissingSignal: 'strict', onUserAgentChange: 'ignore' })
    expect(await facet.evaluate(session(), { ip: null, userAgent: BASE_UA })).toMatchObject({ reaction: 'revoke' })
  })

  it('still softens a missing baseline, which no caller can arrange', async () => {
    const { facet } = makeFacet({ onIpChange: 'mfa', onMissingSignal: 'strict', onUserAgentChange: 'ignore' })
    expect(await facet.evaluate(session({ ip: null }), { ip: OTHER_IP, userAgent: BASE_UA })).toMatchObject({
      reaction: 'rotate',
    })
    const ua = makeFacet({ onIpChange: 'ignore', onMissingSignal: 'strict', onUserAgentChange: 'revoke' })
    expect(await ua.facet.evaluate(session({ userAgent: null }), { ip: BASE_IP, userAgent: OTHER_UA })).toEqual({
      from: '',
      ok: false,
      reaction: 'rotate',
      signal: 'user-agent-change',
      to: OTHER_UA,
    })
  })

  it('leaves an explicit ignore alone rather than promoting it', async () => {
    const { facet } = makeFacet({ onIpChange: 'ignore', onMissingSignal: 'strict', onUserAgentChange: 'ignore' })
    expect(await facet.evaluate(session(), { ip: null, userAgent: null })).toEqual({ ok: true })
  })
})

describe('the suspicious event names the session, and the raw values stay in-process', () => {
  it.each([
    ['an ip', { ip: OTHER_IP, userAgent: BASE_UA }, { onIpChange: 'mfa' as const }],
    ['a user agent', { ip: BASE_IP, userAgent: OTHER_UA }, { onUserAgentChange: 'mfa' as const }],
  ])('emits no address or header when %s drifts, and answers both sides to the caller', async (_, request, policy) => {
    const { facet, emitted } = makeFacet(policy)
    const result = await facet.evaluate(session(), request)
    expect(emitted).toHaveLength(1)
    expect(emitted[0]?.meta).toEqual({ sessionId: 'sess-1' })
    for (const raw of [BASE_IP, OTHER_IP, BASE_UA, OTHER_UA]) expect(JSON.stringify(emitted)).not.toContain(raw)
    expect(result).toMatchObject({ ok: false, from: request.ip === OTHER_IP ? BASE_IP : BASE_UA })
  })
})

describe('diagnostic values are capped before they reach the caller', () => {
  it('passes a normal user agent through unchanged', async () => {
    const { facet } = makeFacet({ onUserAgentChange: 'mfa' })
    const result = await facet.evaluate(session(), { ip: BASE_IP, userAgent: OTHER_UA })
    expect(result).toMatchObject({ from: BASE_UA, to: OTHER_UA })
  })

  it('truncates an oversize header to its first 256 characters rather than carrying kilobytes per drift', async () => {
    const { facet } = makeFacet({ onUserAgentChange: 'mfa' })
    const result = await facet.evaluate(session(), { ip: BASE_IP, userAgent: 'U'.repeat(10_000) })
    expect(result).toMatchObject({ to: `${'U'.repeat(256)}...(truncated)` })
  })

  it('reports an oversize ip as the session column would hold it', async () => {
    const { facet } = makeFacet({ onIpChange: 'mfa' })
    const result = await facet.evaluate(session(), { ip: '1.2.3.4,'.repeat(5000), userAgent: BASE_UA })
    expect(result).toMatchObject({ to: '1.2.3.4,'.repeat(8) })
  })

  it('truncates the recorded side too', async () => {
    const { facet } = makeFacet({ onUserAgentChange: 'mfa' })
    const result = await facet.evaluate(session({ userAgent: 'B'.repeat(1000) }), { ip: BASE_IP, userAgent: BASE_UA })
    expect(result).toMatchObject({ from: `${'B'.repeat(256)}...(truncated)` })
  })

  it('keeps a value exactly at the limit intact', async () => {
    const { facet } = makeFacet({ onUserAgentChange: 'mfa' })
    const exact = 'U'.repeat(256)
    expect(await facet.evaluate(session(), { ip: BASE_IP, userAgent: exact })).toMatchObject({ to: exact })
  })

  it('renders a missing side as an empty string rather than the word undefined', async () => {
    const { facet } = makeFacet({ onUserAgentChange: 'mfa' })
    expect(await facet.evaluate(session(), { ip: BASE_IP, userAgent: null })).toMatchObject({ to: '' })
  })

  it('carries an injection payload as data', async () => {
    const { facet } = makeFacet({ onUserAgentChange: 'mfa' })
    const payload = `'; DROP TABLE auth_sessions; --`
    expect(await facet.evaluate(session(), { ip: BASE_IP, userAgent: payload })).toMatchObject({ to: payload })
  })
})

describe('an empty request value is an absent one, as the session row stores it', () => {
  it('finds no drift against a baseline the row never recorded', async () => {
    const { facet, emitted } = makeFacet()
    expect(await facet.evaluate(session({ ip: null, userAgent: null }), { ip: '', userAgent: '' })).toEqual({
      ok: true,
    })
    expect(emitted).toEqual([])
  })

  it('softens a recorded value the request sent empty, as it does one the request dropped', async () => {
    const { facet } = makeFacet({ onMissingSignal: 'soften', onUserAgentChange: 'mfa' })
    expect(await facet.evaluate(session(), { ip: BASE_IP, userAgent: '' })).toMatchObject({
      ok: false,
      reaction: 'rotate',
    })
    const strict = makeFacet({ onMissingSignal: 'strict', onUserAgentChange: 'mfa' }).facet
    expect(await strict.evaluate(session(), { ip: BASE_IP, userAgent: '' })).toMatchObject({
      ok: false,
      reaction: 'mfa',
    })
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

describe('applyReaction carries a decision out', () => {
  it('ends the session for revoke, then refuses it, naming the policy', async () => {
    const { facet, revoked } = makeFacet()
    await expect(facet.applyReaction('revoke', session())).rejects.toMatchObject({
      code: 'AUTH_SESSION_REVOKED',
      meta: { reason: 'hijack-policy' },
    })
    expect(revoked).toEqual(['sess-1'])
  })

  it('refuses a session a concurrent request already ended', async () => {
    const { facet } = makeFacet({}, async () => {
      throw new AuthError('AUTH_SESSION_REVOKED', { reason: 'not found' })
    })
    await expect(facet.applyReaction('revoke', session())).rejects.toMatchObject({
      code: 'AUTH_SESSION_REVOKED',
      meta: { reason: 'hijack-policy' },
    })
  })

  it('raises a store outage rather than reading it as a session already ended', async () => {
    const { facet } = makeFacet({}, async () => {
      throw new AuthError('AUTH_ADAPTER_FAILED')
    })
    await expect(facet.applyReaction('revoke', session())).rejects.toMatchObject({ code: 'AUTH_ADAPTER_FAILED' })
  })

  it('asks for a step-up on mfa and ends nothing', async () => {
    const { facet, revoked } = makeFacet()
    await expect(facet.applyReaction('mfa', session())).rejects.toMatchObject({
      code: 'AUTH_STEP_UP_REQUIRED',
      meta: { challenge: { reason: 'hijack-policy' } },
    })
    expect(revoked).toEqual([])
  })

  it('does nothing for rotate, which the caller performs, or for ignore', async () => {
    const { facet, revoked } = makeFacet()
    await expect(facet.applyReaction('rotate', session())).resolves.toBeUndefined()
    await expect(facet.applyReaction('ignore', session())).resolves.toBeUndefined()
    expect(revoked).toEqual([])
  })
})

describe('a policy it cannot carry out is refused', () => {
  it('refuses a reaction or a missing-signal mode it does not know, which it enforced as nothing', () => {
    for (const json of ['{"onUserAgentChange":"MFA"}', '{"onIpChange":"block"}', '{"onMissingSignal":"Strict"}']) {
      expect(() => makeFacet(JSON.parse(json)), json).toThrow(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
    }
  })

  it('carries out the same policy spelled right', async () => {
    const { facet } = makeFacet(JSON.parse('{"onMissingSignal":"strict","onUserAgentChange":"mfa"}'))
    const drift = await facet.evaluate(session(), { ip: BASE_IP, userAgent: OTHER_UA })
    expect(drift).toMatchObject({ reaction: 'mfa' })
    if (!drift.ok) {
      await expect(facet.applyReaction(drift.reaction, session())).rejects.toMatchObject({
        code: 'AUTH_STEP_UP_REQUIRED',
      })
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
