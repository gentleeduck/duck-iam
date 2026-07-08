import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { totpAt } from '~/core/mfa/totp'
import { CookieTransport } from '~/core/transport/cookie'
import type { Identity } from '~/core/types/identity'
import type { Channel } from '~/core/types/infra'
import { AuthMemoryLimiter } from '~/limiters/memory'
import { passwordProvider } from '~/providers/password'
import { ScryptHasher } from '~/providers/password/hashers/scrypt.hasher'

interface MyProfile extends Identity.ProfileMetadataBase {
  email: string
}

function fakeChannel(): Channel.Channel & { sent: Array<{ to: string; url: string }> } {
  const sent: Array<{ to: string; url: string }> = []
  return {
    kind: 'email',
    id: 'fake',
    sent,
    async send(input) {
      const url = (input.vars as { url?: string }).url ?? ''
      const email = (input.identity.profile as { email?: string } | undefined)?.email ?? ''
      sent.push({ to: email, url })
      return { ok: true }
    },
  }
}

function buildAuth(): {
  auth: AuthEngine<MyProfile>
  adapter: MemoryAdapter<MyProfile>
  channel: Channel.Channel & { sent: Array<{ to: string; url: string }> }
} {
  const adapter = new MemoryAdapter<MyProfile>()
  const channel = fakeChannel()
  const fastHasher = new ScryptHasher({ N: 1 << 10, keylen: 32 })
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app.example.com',
    transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new AuthMemoryLimiter({ max: 5, windowMs: 60_000 }),
    providers: [passwordProvider({ hasher: fastHasher })],
  })
  return { auth, adapter, channel }
}

function tokenFrom(url: string): string {
  return new URL(url).searchParams.get('token') ?? ''
}

describe('FlowsFacet - step-up', () => {
  it('checkStepUp returns satisfied:true for an AAL=2 fresh session', async () => {
    const { auth } = buildAuth()
    const { session } = await auth.sessions.create({
      identityId: 'u',
      kind: 'user',
      aal: 2,
      factors: [
        { method: 'password', completedAt: new Date() },
        { method: 'totp', completedAt: new Date() },
      ],
    })
    const r = await auth.flows.checkStepUp(session, { aal: 2 })
    expect(r.satisfied).toBe(true)
  })

  it('checkStepUp returns satisfied:false with mfa-required when AAL=1', async () => {
    const { auth } = buildAuth()
    const { session } = await auth.sessions.create({
      identityId: 'u',
      kind: 'user',
      aal: 1,
      factors: [{ method: 'password', completedAt: new Date() }],
    })
    const r = await auth.flows.checkStepUp(session, { aal: 2 })
    expect(r.satisfied).toBe(false)
    if (!r.satisfied) {
      expect(r.reason).toBe('mfa-required')
      expect(r.methods).toContain('totp')
    }
  })

  it('completeStepUp verifies TOTP + rotates the session to AAL=2', async () => {
    const { auth } = buildAuth()
    const identity = await auth.identities.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
    const challenge = await auth.mfa.beginTotpEnrollment(identity.id, 'a@x.com')
    await auth.mfa.confirmTotpEnrollment(identity.id, totpAt(challenge.secret, Math.floor(Date.now() / 1000 / 30)))

    const { session: aal1, sid: aal1Sid } = await auth.sessions.create({
      identityId: identity.id,
      kind: 'user',
      aal: 1,
      factors: [{ method: 'password', completedAt: new Date() }],
    })
    expect(aal1.aal).toBe(1)

    const code = totpAt(challenge.secret, Math.floor(Date.now() / 1000 / 30))
    const stepped = await auth.flows.completeStepUp({
      currentSid: aal1Sid,
      method: 'totp',
      code,
    })
    expect(stepped.session.aal).toBe(2)
    expect(stepped.session.factors.some((f) => f.method === 'totp')).toBe(true)
  })

  it('completeStepUp with wrong code surfaces AUTH/INVALID_CREDENTIALS', async () => {
    const { auth } = buildAuth()
    const identity = await auth.identities.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
    const challenge = await auth.mfa.beginTotpEnrollment(identity.id, 'a@x.com')
    await auth.mfa.confirmTotpEnrollment(identity.id, totpAt(challenge.secret, Math.floor(Date.now() / 1000 / 30)))

    const { sid } = await auth.sessions.create({
      identityId: identity.id,
      kind: 'user',
      aal: 1,
      factors: [{ method: 'password', completedAt: new Date() }],
    })
    await expect(auth.flows.completeStepUp({ currentSid: sid, method: 'totp', code: '000000' })).rejects.toMatchObject({
      code: 'AUTH_INVALID_CREDENTIALS',
    })
  })
})

describe('FlowsFacet - password reset', () => {
  it('requestPasswordReset for unknown email returns ok (no enumeration)', async () => {
    const { auth, channel } = buildAuth()
    const r = await auth.flows.requestPasswordReset({
      input: { email: 'ghost@x.com' },
      findIdentityByEmail: (email) => auth.identities.getByEmail(email),
      channels: { email: channel },
    })
    expect(r.ok).toBe(true)
    expect(channel.sent).toHaveLength(0)
  })

  it('requestPasswordReset for known email persists a recovery token + dispatches link', async () => {
    const { auth, channel, adapter } = buildAuth()
    const identity = await auth.identities.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'old-password')
    const handler = vi.fn()
    auth.events.on('recovery.password.requested', handler)

    await auth.flows.requestPasswordReset({
      input: { email: 'a@x.com' },
      findIdentityByEmail: (email) => auth.identities.getByEmail(email),
      channels: { email: channel },
    })

    expect(channel.sent).toHaveLength(1)
    expect(handler).toHaveBeenCalledOnce()
    const creds = await adapter.credentials.listByIdentity(identity.id, 'recovery', {})
    expect(creds).toHaveLength(1)
    expect(creds[0]?.secret).toMatch(/^[0-9a-f]{64}$/)
  })

  it('completePasswordReset swaps password + revokes all sessions', async () => {
    const { auth, channel, adapter } = buildAuth()
    const identity = await auth.identities.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'old-password-9')
    await auth.sessions.create({ identityId: identity.id, kind: 'user', aal: 1, factors: [] })

    await auth.flows.requestPasswordReset({
      input: { email: 'a@x.com' },
      findIdentityByEmail: (email) => auth.identities.getByEmail(email),
      channels: { email: channel },
    })
    const token = tokenFrom(channel.sent[0]?.url ?? '')

    const completedHandler = vi.fn()
    auth.events.on('recovery.password.completed', completedHandler)
    await auth.flows.completePasswordReset({ token, newPassword: 'new-password-9' })

    // Old password rejected; new password accepted.
    expect((await auth.passwords.verify(identity.id, 'old-password-9')).ok).toBe(false)
    expect((await auth.passwords.verify(identity.id, 'new-password-9')).ok).toBe(true)
    // Previous sessions purged.
    const sessions = await adapter.sessions.listByIdentity(identity.id)
    expect(sessions).toHaveLength(0)
    expect(completedHandler).toHaveBeenCalledOnce()
  })

  it('replay of reset token surfaces AUTH/RECOVERY_TOKEN_INVALID', async () => {
    const { auth, channel } = buildAuth()
    const identity = await auth.identities.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'old-password-9')
    await auth.flows.requestPasswordReset({
      input: { email: 'a@x.com' },
      findIdentityByEmail: (email) => auth.identities.getByEmail(email),
      channels: { email: channel },
    })
    const token = tokenFrom(channel.sent[0]?.url ?? '')
    await auth.flows.completePasswordReset({ token, newPassword: 'new-password-9' })
    await expect(auth.flows.completePasswordReset({ token, newPassword: 'second-new-password' })).rejects.toMatchObject(
      { code: 'AUTH_RECOVERY_TOKEN_INVALID' },
    )
  })

  it('reset with MFA enrolled requires fresh AAL=2 session', async () => {
    const { auth, channel } = buildAuth()
    const identity = await auth.identities.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'old-password-9')
    const ch = await auth.mfa.beginTotpEnrollment(identity.id, 'a@x.com')
    await auth.mfa.confirmTotpEnrollment(identity.id, totpAt(ch.secret, Math.floor(Date.now() / 1000 / 30)))

    await auth.flows.requestPasswordReset({
      input: { email: 'a@x.com' },
      findIdentityByEmail: (email) => auth.identities.getByEmail(email),
      channels: { email: channel },
    })
    const token = tokenFrom(channel.sent[0]?.url ?? '')

    // No currentSid -> reset refused.
    await expect(auth.flows.completePasswordReset({ token, newPassword: 'new-password-9' })).rejects.toMatchObject({
      code: 'AUTH_RECOVERY_REQUIRES_MFA',
    })

    // AAL=1 session -> still refused.
    const { sid: aal1Sid } = await auth.sessions.create({
      identityId: identity.id,
      kind: 'user',
      aal: 1,
      factors: [{ method: 'password', completedAt: new Date() }],
    })
    await expect(
      auth.flows.completePasswordReset({ token, newPassword: 'new-password-9', currentSid: aal1Sid }),
    ).rejects.toMatchObject({ code: 'AUTH_RECOVERY_REQUIRES_MFA' })

    // Fresh AAL=2 session -> reset allowed.
    const { sid: aal2Sid } = await auth.sessions.create({
      identityId: identity.id,
      kind: 'user',
      aal: 2,
      factors: [
        { method: 'password', completedAt: new Date() },
        { method: 'totp', completedAt: new Date() },
      ],
    })
    await expect(
      auth.flows.completePasswordReset({ token, newPassword: 'new-password-9', currentSid: aal2Sid }),
    ).resolves.toEqual({ ok: true })
  })

  it('expired reset token surfaces AUTH/RECOVERY_TOKEN_EXPIRED', async () => {
    const { auth, channel, adapter } = buildAuth()
    const identity = await auth.identities.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'old-password-9')
    await auth.flows.requestPasswordReset({
      input: { email: 'a@x.com' },
      findIdentityByEmail: (email) => auth.identities.getByEmail(email),
      channels: { email: channel },
    })
    const token = tokenFrom(channel.sent[0]?.url ?? '')
    const creds = await adapter.credentials.listByIdentity(identity.id, 'recovery', {})
    const cred = creds[0]
    if (!cred) throw new Error('missing credential')
    cred.expiresAt = new Date(Date.now() - 1)
    await expect(auth.flows.completePasswordReset({ token, newPassword: 'new-password-9' })).rejects.toMatchObject({
      code: 'AUTH_RECOVERY_TOKEN_EXPIRED',
    })
  })

  it('completePasswordReset rejects email-verification tokens (cross-kind confusion)', async () => {
    const { auth, channel, adapter } = buildAuth()
    const identity = await auth.identities.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'old-password-9')

    // Mint an email-verification token directly via the flow.
    await auth.flows.requestEmailVerification({
      identityId: identity.id,
      channels: { email: channel },
    })
    const verifyToken = tokenFrom(channel.sent[0]?.url ?? '')

    // Attacker tries to use it for a password reset. Must be refused.
    await expect(
      auth.flows.completePasswordReset({ token: verifyToken, newPassword: 'evil-password' }),
    ).rejects.toMatchObject({
      code: 'AUTH_RECOVERY_TOKEN_INVALID',
    })

    // Original password still works.
    const verify = await auth.passwords.verify(identity.id, 'old-password-9')
    expect(verify.ok).toBe(true)

    void adapter
  })

  it('completePasswordReset rejects account-deletion tokens', async () => {
    const { auth, channel, adapter } = buildAuth()
    const identity = await auth.identities.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'old-password-9')

    await auth.flows.requestAccountDeletion({
      identityId: identity.id,
      channels: { email: channel },
    })
    const deleteToken = tokenFrom(channel.sent[0]?.url ?? '')

    await expect(
      auth.flows.completePasswordReset({ token: deleteToken, newPassword: 'evil-password' }),
    ).rejects.toMatchObject({ code: 'AUTH_RECOVERY_TOKEN_INVALID' })

    void adapter
  })

  it('completePasswordReset rejects signup-flow tokens', async () => {
    const { auth } = buildAuth()
    // Start a signup-flow which mints a recovery+metadata.kind='signup-flow' row.
    const begin = await auth.flows.beginSignUp({ email: 'fresh@x.com' })
    expect(begin.flowToken).toBeDefined()

    await expect(
      auth.flows.completePasswordReset({ token: begin.flowToken, newPassword: 'evil-password' }),
    ).rejects.toMatchObject({ code: 'AUTH_RECOVERY_TOKEN_INVALID' })
  })
})
