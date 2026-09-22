/** `beginTotpEnrollment` destroyed the confirmed enrollment before minting the pending one, so starting
 *  an enrollment was a way to remove the second factor without proving it. */

import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { InMemoryEvents } from '~/core/events'
import { totpAt } from '../internal/totp'
import { MfaImpl } from '../mfa'
import { DEFAULT_MFA_CONFIG } from '../mfa.constants'

describe('MfaFacet - re-enrolling TOTP over a confirmed factor', () => {
  let adapter: MemoryAdapter
  let events: InMemoryEvents
  let facet: MfaImpl

  beforeEach(() => {
    adapter = new MemoryAdapter()
    events = new InMemoryEvents()
    facet = new MfaImpl(adapter.credentials, events, DEFAULT_MFA_CONFIG)
  })

  /** Read at the moment it is used, never captured: a step index from thirty seconds ago is outside the
   *  drift window, which would make these tests fail on a clock boundary rather than on the product. */
  const nowStep = () => Math.floor(Date.now() / 1000 / 30)

  /** The enrolled victim: a confirmed factor, whose confirming code has already spent its step. */
  async function enrolled(): Promise<{ secret: string }> {
    const challenge = await facet.beginTotpEnrollment('user-1', 'alice@x.com')
    await facet.confirmTotpEnrollment('user-1', totpAt(challenge.secret, nowStep()))
    return { secret: challenge.secret }
  }

  it('refuses rather than replacing it', async () => {
    await enrolled()

    await expect(facet.beginTotpEnrollment('user-1', 'alice@x.com')).rejects.toMatchObject({
      code: 'AUTH_MFA_REQUIRED',
    })
  })

  it('leaves the enrolled factor intact, so the victim can still step up with it', async () => {
    const victim = await enrolled()

    await facet.beginTotpEnrollment('user-1', 'alice@x.com').catch(() => null)

    expect(await facet.hasTotp('user-1')).toBe(true)
    expect(await facet.verifyTotp('user-1', totpAt(victim.secret, nowStep() + 1))).toBe(true)
  })

  it('leaves no pending row behind, so the refused enrollment cannot be confirmed afterwards', async () => {
    await enrolled()

    await facet.beginTotpEnrollment('user-1', 'alice@x.com').catch(() => null)

    // The only `totp` row is the confirmed one; `confirmTotpEnrollment` finds nothing to flip.
    const rows = await adapter.credentials.listByIdentity('user-1', 'totp', {})
    expect(rows).toHaveLength(1)
    await expect(facet.confirmTotpEnrollment('user-1', '000000')).rejects.toMatchObject({
      code: 'AUTH_MFA_REQUIRED',
    })
  })

  it('still re-enrolls through removeTotp, which is the guarded way in', async () => {
    const victim = await enrolled()

    await facet.removeTotp('user-1')
    const next = await facet.beginTotpEnrollment('user-1', 'alice@x.com')

    expect(next.secret).not.toBe(victim.secret)
    await expect(facet.confirmTotpEnrollment('user-1', totpAt(next.secret, nowStep()))).resolves.toMatchObject({
      ok: true,
    })
  })

  it('still replaces a pending enrollment rather than accumulating one per attempt', async () => {
    const first = await facet.beginTotpEnrollment('user-1', 'alice@x.com')
    const second = await facet.beginTotpEnrollment('user-1', 'alice@x.com')

    expect(second.secret).not.toBe(first.secret)
    expect(await adapter.credentials.listByIdentity('user-1', 'totp', {})).toHaveLength(1)
  })

  it('does not count a revoked enrollment, which verifyTotp would not accept either', async () => {
    await enrolled()
    const [row] = await adapter.credentials.listByIdentity('user-1', 'totp', {})
    if (!row) throw new Error('no enrollment to revoke')
    await adapter.credentials.revoke(row.id, {})

    await expect(facet.beginTotpEnrollment('user-1', 'alice@x.com')).resolves.toMatchObject({
      secret: expect.stringMatching(/^[A-Z2-7]{32}$/),
    })
  })
})
