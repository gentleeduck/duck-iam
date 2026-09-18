/**
 * `getBySid` used to hand back whatever the store had filed under the key, with
 * no expiry check - unlike `resolveBySid`, which it otherwise reads exactly
 * like. Every caller of it gates something privileged on the answer, and two of
 * them feed the result to `rotateOrCreate`, which mints a brand new live session
 * from whatever it is given. So an expired sid was not merely accepted at those
 * gates; presenting one resurrected the session.
 */
import { describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import type { Channel } from '~/channels/channels.types'
import { sha256 } from '~/core/crypto'
import { AuthEngine } from '~/core/engine'
import type { Identities } from '~/core/identities/identities.types'
import { DEFAULT_SESSION_CONFIG } from '~/core/sessions/sessions.constants'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { mfaProvider, totpAt } from '~/providers/mfa'
import { passwords, ScryptHasher } from '~/providers/passwords'

interface MyProfile extends Identities.ProfileMetadataBase {
  email: string
}

function fakeChannel(): Channel.Channel & { sent: Array<{ to: string; url: string }> } {
  const sent: Array<{ to: string; url: string }> = []
  return {
    id: 'fake',
    kind: 'email',
    async send(input) {
      const url = (input.vars as { url?: string }).url ?? ''
      const email = (input.identity.profile as { email?: string } | undefined)?.email ?? ''
      sent.push({ to: email, url })
      return { ok: true }
    },
    sent,
  }
}

function buildAuth(): {
  auth: AuthEngine<MyProfile>
  adapter: MemoryAdapter<MyProfile>
  channel: Channel.Channel & { sent: Array<{ to: string; url: string }> }
} {
  const adapter = new MemoryAdapter<MyProfile>()
  const channel = fakeChannel()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app.example.com',
    limiter: new MemoryLimiter({ max: 5, windowMs: 60_000 }),
    providers: [passwords({ hasher: new ScryptHasher({ keylen: 32, N: 1 << 10 }) }), mfaProvider()],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
  return { adapter, auth, channel }
}

function tokenFrom(url: string): string {
  return new URL(url).searchParams.get('token') ?? ''
}

/** Push a live session past its sliding deadline, leaving the absolute cap far off. `createdAt` moves back
 *  with it, because `expires_at >= created_at` is a constraint every dialect carries. */
async function expire(adapter: MemoryAdapter<MyProfile>, sid: string): Promise<void> {
  await adapter.sessions.update(sha256(sid), {
    absoluteExpiresAt: new Date(Date.now() + 86_400_000),
    createdAt: new Date(Date.now() - 86_400_000),
    expiresAt: new Date(Date.now() - 1000),
  })
}

describe('expired sessions are refused at every privileged gate', () => {
  it('completeStepUp refuses an expired sid instead of rotating it into a live session', async () => {
    const { auth, adapter } = buildAuth()
    const identity = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a@x.com' } })
    const challenge = await auth.mfa.beginTotpEnrollment(identity.id, 'a@x.com')
    const enrolledStep = Math.floor(Date.now() / 1000 / 30)
    await auth.mfa.confirmTotpEnrollment(identity.id, totpAt(challenge.secret, enrolledStep))

    const { sid } = await auth.sessions.create({
      aal: 1,
      factors: [{ completedAt: new Date(), method: 'password' }],
      identityId: identity.id,
      kind: 'user',
    })
    await expire(adapter, sid)

    // A correct TOTP is supplied: the code is not what should stop this.
    await expect(
      auth.flows.completeStepUp({ code: totpAt(challenge.secret, enrolledStep + 1), currentSid: sid, method: 'totp' }),
    ).rejects.toMatchObject({ code: 'AUTH_UNAUTHENTICATED' })
    // And the dead row is gone rather than left for the next attempt.
    await expect(adapter.sessions.getByHash(sha256(sid))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
  })

  it('impersonate refuses an expired admin sid, and never asks authorize() to judge a dead session', async () => {
    const { auth, adapter } = buildAuth()
    const admin = await auth.identities.create({ profile: { email: 'admin@x.com', username: 'admin' } })
    const target = await auth.identities.create({ profile: { email: 'target@x.com', username: 'target' } })
    const { sid: adminSid } = await auth.sessions.create({
      aal: 2,
      factors: [{ completedAt: new Date(), method: 'password' }],
      identityId: admin.id,
      kind: 'user',
    })
    await expire(adapter, adminSid)
    const authorize = vi.fn(async () => true)

    await expect(
      auth.flows.impersonate({ authorize, realSid: adminSid, reason: 'support', targetIdentityId: target.id }),
    ).rejects.toMatchObject({ code: 'AUTH_UNAUTHENTICATED' })
    // The app's own callback was handed the dead session to approve before this.
    expect(authorize).not.toHaveBeenCalled()
  })

  it('completePasswordReset refuses an expired AAL=2 sid at the MFA gate', async () => {
    const { auth, adapter, channel } = buildAuth()
    const identity = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'old-password-9', adapter.credentials)
    const ch = await auth.mfa.beginTotpEnrollment(identity.id, 'a@x.com')
    await auth.mfa.confirmTotpEnrollment(identity.id, totpAt(ch.secret, Math.floor(Date.now() / 1000 / 30)))
    await auth.flows.requestPasswordReset({
      channels: { email: channel },
      findIdentityByEmail: (email) => auth.identities.getByEmail(email),
      input: { email: 'a@x.com' },
    })
    const token = tokenFrom(channel.sent[0]?.url ?? '')

    const { sid } = await auth.sessions.create({
      aal: 2,
      factors: [
        { completedAt: new Date(), method: 'password' },
        { completedAt: new Date(), method: 'totp' },
      ],
      identityId: identity.id,
      kind: 'user',
    })
    await expire(adapter, sid)

    // A stale session plus a valid reset token used to change the password with
    // no live MFA behind it.
    await expect(
      auth.flows.completePasswordReset({ currentSid: sid, newPassword: 'new-password-9', token }),
    ).rejects.toMatchObject({ code: 'AUTH_RECOVERY_REQUIRES_MFA' })
  })

  it('completePasswordReset refuses a live AAL=2 sid whose freshness window has closed', async () => {
    // The compounding half: the row still says `fresh: true` because nothing
    // recomputes it, and this gate reads that field.
    const { auth, adapter, channel } = buildAuth()
    const identity = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'old-password-9', adapter.credentials)
    const ch = await auth.mfa.beginTotpEnrollment(identity.id, 'a@x.com')
    await auth.mfa.confirmTotpEnrollment(identity.id, totpAt(ch.secret, Math.floor(Date.now() / 1000 / 30)))
    await auth.flows.requestPasswordReset({
      channels: { email: channel },
      findIdentityByEmail: (email) => auth.identities.getByEmail(email),
      input: { email: 'a@x.com' },
    })
    const token = tokenFrom(channel.sent[0]?.url ?? '')

    const { sid } = await auth.sessions.create({
      aal: 2,
      factors: [
        { completedAt: new Date(), method: 'password' },
        { completedAt: new Date(), method: 'totp' },
      ],
      identityId: identity.id,
      kind: 'user',
    })
    // Live on both deadlines, but rotated long enough ago that it is not fresh. Creation moves back with
    // the rotation: a session cannot have been rotated before it existed.
    await adapter.sessions.update(sha256(sid), {
      createdAt: new Date(Date.now() - DEFAULT_SESSION_CONFIG.freshnessMs - 2000),
      fresh: true,
      rotatedAt: new Date(Date.now() - DEFAULT_SESSION_CONFIG.freshnessMs - 1000),
    })

    await expect(
      auth.flows.completePasswordReset({ currentSid: sid, newPassword: 'new-password-9', token }),
    ).rejects.toMatchObject({ code: 'AUTH_RECOVERY_REQUIRES_MFA' })
  })

  it('a live, fresh AAL=2 session still passes every one of these gates', async () => {
    // The guards above are worthless if they also refuse the legitimate case.
    const { auth, channel, adapter } = buildAuth()
    const identity = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'old-password-9', adapter.credentials)
    const ch = await auth.mfa.beginTotpEnrollment(identity.id, 'a@x.com')
    await auth.mfa.confirmTotpEnrollment(identity.id, totpAt(ch.secret, Math.floor(Date.now() / 1000 / 30)))
    await auth.flows.requestPasswordReset({
      channels: { email: channel },
      findIdentityByEmail: (email) => auth.identities.getByEmail(email),
      input: { email: 'a@x.com' },
    })
    const token = tokenFrom(channel.sent[0]?.url ?? '')

    const { sid } = await auth.sessions.create({
      aal: 2,
      factors: [
        { completedAt: new Date(), method: 'password' },
        { completedAt: new Date(), method: 'totp' },
      ],
      identityId: identity.id,
      kind: 'user',
    })
    const reset = await auth.flows.completePasswordReset({ currentSid: sid, newPassword: 'new-password-9', token })
    expect(reset.ok).toBe(true)
    // A caller who was signed in rotates through `credential-change` rather than
    // being swept with everyone else, so the reset answers with a replacement bearer.
    expect(reset.intents.length).toBeGreaterThan(0)
  })
})
