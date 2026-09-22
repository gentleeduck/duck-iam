/**
 * `session.fresh` is one window weighed in three places: `isSessionFresh` here, `JwtTransport.verify` and
 * `checkStepUp`. The other two measure the distance with `Math.abs`; this one subtracted in one direction,
 * so a `rotatedAt` ahead of the clock gave a negative age that is under any window at all.
 *
 * Nothing bounds the column from above — `chk_auth_sessions_rotated_after_created` is a floor — and the
 * stamp is written by whichever node rotated the session, so one machine with a skewed clock hands every
 * other node sessions that never go stale. Freshness is what gates a password change.
 */
import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { InMemoryEvents } from '~/core/events'
import { isSessionFresh, SessionsImpl } from '../sessions'
import { DEFAULT_SESSION_CONFIG } from '../sessions.constants'

const WINDOW = DEFAULT_SESSION_CONFIG.freshnessMs

describe('the freshness window is bounded at both ends', () => {
  const now = Date.now()

  it.each([
    ['rotated just now', 0, true],
    ['rotated inside the window', -(WINDOW - 1_000), true],
    ['rotated exactly a window ago', -WINDOW, false],
    ['rotated past the window', -(WINDOW + 1), false],
    // The tolerance the two siblings already allow, kept so the fix is a bound and not a ban on skew.
    ['stamped slightly ahead, as node clock skew does', 30_000, true],
    ['stamped a window ahead', WINDOW, false],
    ['stamped a day ahead', 86_400_000, false],
    ['stamped a century ahead', 100 * 365 * 86_400_000, false],
  ])('%s', (_label, offsetMs, expected) => {
    expect(isSessionFresh({ fresh: true, rotatedAt: new Date(now + offsetMs) }, now, WINDOW)).toBe(expected)
  })

  it('a stored false still revokes, whatever the clock says', () => {
    // Storage can revoke freshness but never grant it, which the future-stamp bound must not undo.
    expect(isSessionFresh({ fresh: false, rotatedAt: new Date(now) }, now, WINDOW)).toBe(false)
  })

  it('fails closed on a rotatedAt nothing can read', () => {
    expect(isSessionFresh({ fresh: true, rotatedAt: new Date(Number.NaN) }, now, WINDOW)).toBe(false)
  })
})

describe('a session carrying a future rotatedAt is not fresh to read back', () => {
  let adapter: MemoryAdapter
  let facet: SessionsImpl

  beforeEach(() => {
    adapter = new MemoryAdapter()
    facet = new SessionsImpl(adapter.sessions, new InMemoryEvents(), DEFAULT_SESSION_CONFIG)
  })

  it('reads fresh for a rotation the clock agrees with, and not for one a day out', async () => {
    const live = await facet.create({ aal: 1, factors: [], identityId: 'user-1', kind: 'user' })
    // The live control: this is the same call shape as below, so a `false` there is the stamp and not
    // a session that failed to resolve at all.
    await expect(facet.getBySid(live.sid)).resolves.toMatchObject({ fresh: true })

    const skewed = await facet.create({ aal: 1, factors: [], identityId: 'user-2', kind: 'user' })
    await adapter.sessions.update(skewed.session.id, { rotatedAt: new Date(Date.now() + 86_400_000) })
    await expect(facet.getBySid(skewed.sid)).resolves.toMatchObject({ fresh: false })
  })
})
