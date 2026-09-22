/**
 * `completeStepUp` is the primary second-factor gate, and nothing bounded how often it could be tried.
 * A TOTP is six digits and `matchTotpStep` accepts a three-step drift window, so roughly three codes
 * in a million are live at any moment: unlimited online guessing is an expected ~166k requests, which
 * is minutes at a modest rate. The caller needs an AAL-1 session for the account, which is exactly the
 * attacker who has the password and not the phone - the one case the second factor exists for.
 */

import { describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import type { Identities } from '~/core/identities/identities.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { mfaProvider, totpAt } from '~/providers/mfa'
import { passwords, ScryptHasher } from '~/providers/passwords'

interface MyProfile extends Identities.ProfileMetadataBase {
  email: string
}

const MAX_ATTEMPTS = 5

function buildAuth(): AuthEngine<MyProfile> {
  const adapter = new MemoryAdapter<MyProfile>()
  return new AuthEngine<MyProfile>({
    baseUrl: 'https://app.example.com',
    limiter: new MemoryLimiter({ max: MAX_ATTEMPTS, windowMs: 60_000 }),
    providers: [passwords({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) }), mfaProvider()],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
}

/** An identity with a confirmed TOTP factor and a live AAL-1 session, which is all the gate needs. */
async function enrolled(auth: AuthEngine<MyProfile>): Promise<{ identityId: string; sid: string }> {
  const ident = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a@x.com' } })
  const challenge = await auth.mfa.beginTotpEnrollment(ident.id, 'a@x.com')
  const step = Math.floor(Date.now() / 1000 / 30)
  await auth.mfa.confirmTotpEnrollment(ident.id, totpAt(challenge.secret, step))
  const { sid } = await auth.sessions.create({
    aal: 1,
    factors: [{ completedAt: new Date(), method: 'password' }],
    identityId: ident.id,
    kind: 'user',
  })
  return { identityId: ident.id, sid }
}

/** The codes a wrong guess produces, in order, until one is refused for a reason other than the guess. */
async function grind(auth: AuthEngine<MyProfile>, sid: string, method: 'totp' | 'backup-code', tries: number) {
  const codes: string[] = []
  for (let i = 0; i < tries; i++) {
    await auth.flows
      .completeStepUp({ code: String(100000 + i), currentSid: sid, method })
      .then(() => codes.push('ACCEPTED'))
      .catch((err: { code?: string }) => codes.push(err.code ?? 'UNKNOWN'))
  }
  return codes
}

describe('completeStepUp is rate limited', () => {
  it('a run of wrong codes is eventually refused as rate limited, not as another bad guess', async () => {
    const auth = buildAuth()
    const { sid } = await enrolled(auth)

    const codes = await grind(auth, sid, 'totp', MAX_ATTEMPTS + 3)

    expect(codes).toContain('AUTH_RATE_LIMITED')
    expect(codes).not.toContain('ACCEPTED')
  })

  it('the refusal names the identity on the lockout event, so an operator can see it', async () => {
    const auth = buildAuth()
    const { identityId, sid } = await enrolled(auth)
    const onLockout = vi.fn()
    auth.events.on('lockout', onLockout)

    await grind(auth, sid, 'totp', MAX_ATTEMPTS + 3)

    expect(onLockout).toHaveBeenCalled()
    expect(onLockout.mock.calls[0]?.[0]).toMatchObject({ identityId })
  })

  it('backup codes are bounded too, being the fallback for the same gate', async () => {
    const auth = buildAuth()
    const { sid } = await enrolled(auth)

    const codes = await grind(auth, sid, 'backup-code', MAX_ATTEMPTS + 3)

    expect(codes).toContain('AUTH_RATE_LIMITED')
  })

  it('grinding one account does not refuse another', async () => {
    const auth = buildAuth()
    const victim = await enrolled(auth)
    const other = await auth.identities.create({ profile: { email: 'b@x.com', username: 'b@x.com' } })
    const challenge = await auth.mfa.beginTotpEnrollment(other.id, 'b@x.com')
    const step = Math.floor(Date.now() / 1000 / 30)
    await auth.mfa.confirmTotpEnrollment(other.id, totpAt(challenge.secret, step))
    const { sid: otherSid } = await auth.sessions.create({
      aal: 1,
      factors: [{ completedAt: new Date(), method: 'password' }],
      identityId: other.id,
      kind: 'user',
    })

    await grind(auth, victim.sid, 'totp', MAX_ATTEMPTS + 3)

    const stepped = await auth.flows.completeStepUp({
      code: totpAt(challenge.secret, step + 1),
      currentSid: otherSid,
      method: 'totp',
    })
    expect(stepped.session.aal).toBe(2)
  })
})
