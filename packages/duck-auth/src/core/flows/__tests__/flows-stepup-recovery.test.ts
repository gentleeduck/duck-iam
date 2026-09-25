import { describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import type { Credential } from '~/core/credentials'
import { AuthEngine } from '~/core/engine'
import type { Deliver } from '~/core/flows/flows.delivery'
import type { Identities } from '~/core/identities/identities.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { mfaProvider, totpAt } from '~/providers/mfa'
import { passwords, ScryptHasher } from '~/providers/passwords'

interface MyProfile extends Identities.ProfileMetadataBase {
  email: string
}

function fakeChannel(): Deliver & { sent: Array<{ to: string; url: string }> } {
  const sent: Array<{ to: string; url: string }> = []
  return Object.assign(
    async (message: Parameters<Deliver>[0]): Promise<void> => {
      const url = (message.vars as { url?: string }).url ?? ''
      const email = (message.identity.profile as { email?: string } | undefined)?.email ?? ''
      sent.push({ to: email, url })
    },
    { sent },
  )
}

function buildAuth(opts: { credentials?: (base: Credential.Store) => Credential.Store } = {}): {
  auth: AuthEngine<MyProfile>
  adapter: MemoryAdapter<MyProfile>
  channel: Deliver & { sent: Array<{ to: string; url: string }> }
} {
  const adapter = new MemoryAdapter<MyProfile>()
  const channel = fakeChannel()
  const fastHasher = new ScryptHasher({ N: 1 << 10, keylen: 32 })
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app.example.com',
    deliver: channel,
    transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: opts.credentials?.(adapter.credentials) ?? adapter.credentials,
    },
    limiter: new MemoryLimiter({ max: 5, windowMs: 60_000 }),
    providers: [passwords({ hasher: fastHasher }), mfaProvider()],
  })
  return { auth, adapter, channel }
}

function tokenFrom(url: string): string {
  return new URL(url).searchParams.get('token') ?? ''
}

describe('FlowsImpl - step-up', () => {
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
    const enrolledStep = Math.floor(Date.now() / 1000 / 30)
    await auth.mfa.confirmTotpEnrollment(identity.id, totpAt(challenge.secret, enrolledStep))

    const { session: aal1, sid: aal1Sid } = await auth.sessions.create({
      identityId: identity.id,
      kind: 'user',
      aal: 1,
      factors: [{ method: 'password', completedAt: new Date() }],
    })
    expect(aal1.aal).toBe(1)

    // A later step than the one enrollment spent: a TOTP is single-use, so a
    // step-up inside the same thirty-second window has to wait for the next code.
    const code = totpAt(challenge.secret, enrolledStep + 1)
    const stepped = await auth.flows.completeStepUp({
      currentSid: aal1Sid,
      method: 'totp',
      code,
    })
    expect(stepped.session.aal).toBe(2)
    expect(stepped.session.factors.some((f) => f.method === 'totp')).toBe(true)
  })

  it('completeStepUp with wrong code surfaces AUTH_INVALID_CREDENTIALS', async () => {
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

describe('FlowsImpl - password reset', () => {
  it('requestPasswordReset for unknown email returns ok (no enumeration)', async () => {
    const { auth, channel } = buildAuth()
    const r = await auth.flows.requestPasswordReset({
      input: { email: 'ghost@x.com' },
      findIdentityByEmail: (email) => auth.identities.getByEmail(email),
    })
    expect(r.ok).toBe(true)
    expect(channel.sent).toHaveLength(0)
  })

  it('requestPasswordReset for known email persists a recovery token + dispatches link', async () => {
    const { auth, channel, adapter } = buildAuth()
    const identity = await auth.identities.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'old-password', adapter.credentials)
    const handler = vi.fn()
    auth.events.on('recovery.password.requested', handler)

    await auth.flows.requestPasswordReset({
      input: { email: 'a@x.com' },
      findIdentityByEmail: (email) => auth.identities.getByEmail(email),
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
    await auth.passwords.set(identity.id, 'old-password-9', adapter.credentials)
    await auth.sessions.create({ identityId: identity.id, kind: 'user', aal: 1, factors: [] })

    await auth.flows.requestPasswordReset({
      input: { email: 'a@x.com' },
      findIdentityByEmail: (email) => auth.identities.getByEmail(email),
    })
    const token = tokenFrom(channel.sent[0]?.url ?? '')

    const completedHandler = vi.fn()
    auth.events.on('recovery.password.completed', completedHandler)
    await auth.flows.completePasswordReset({ token, newPassword: 'new-password-9' })

    // Old password rejected; new password accepted.
    expect((await auth.passwords.verify(identity.id, 'old-password-9', adapter.credentials)).ok).toBe(false)
    expect((await auth.passwords.verify(identity.id, 'new-password-9', adapter.credentials)).ok).toBe(true)
    // Previous sessions purged.
    const sessions = await adapter.sessions.listByIdentity(identity.id)
    expect(sessions).toHaveLength(0)
    expect(completedHandler).toHaveBeenCalledOnce()
  })

  it('a second reset reading between the winner claim and its revoke is refused', async () => {
    // The claim and the revoke are two statements. Holding the revoke open is what a loaded connection
    // pool does by itself, and it is the window a second reset slipped through - taking the password
    // with it, after the winner had already swept the sessions.
    let gatedId: string | null = null
    let calls = 0
    let release = (): void => {}
    const held = new Promise<void>((resolve) => {
      release = resolve
    })
    const { auth, adapter, channel } = buildAuth({
      credentials: (base) => ({
        ...base,
        revoke: async (id, ctx) => {
          if (id === gatedId) {
            calls += 1
            if (calls === 1) await held
          }
          return base.revoke(id, ctx)
        },
      }),
    })
    const identity = await auth.identities.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'old-password-9', adapter.credentials)
    await auth.flows.requestPasswordReset({
      findIdentityByEmail: (email) => auth.identities.getByEmail(email),
      input: { email: 'a@x.com' },
    })
    const token = tokenFrom(channel.sent[0]?.url ?? '')
    const [recovery] = await adapter.credentials.listByIdentity(identity.id, 'recovery', {})
    gatedId = recovery?.id ?? null

    const winner = auth.flows.completePasswordReset({ newPassword: 'winner-password-9', token })
    await vi.waitFor(() => {
      if (calls === 0) throw new Error('the winner has not claimed the row yet')
    })

    await expect(auth.flows.completePasswordReset({ newPassword: 'attacker-password-9', token })).rejects.toMatchObject(
      { code: 'AUTH_RECOVERY_TOKEN_INVALID' },
    )
    release()
    await winner

    // The password the loser sent is not the one left on the account.
    expect((await auth.passwords.verify(identity.id, 'winner-password-9', adapter.credentials)).ok).toBe(true)
    expect((await auth.passwords.verify(identity.id, 'attacker-password-9', adapter.credentials)).ok).toBe(false)
  })

  it('replay of reset token surfaces AUTH_RECOVERY_TOKEN_INVALID', async () => {
    const { auth, channel, adapter } = buildAuth()
    const identity = await auth.identities.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'old-password-9', adapter.credentials)
    await auth.flows.requestPasswordReset({
      input: { email: 'a@x.com' },
      findIdentityByEmail: (email) => auth.identities.getByEmail(email),
    })
    const token = tokenFrom(channel.sent[0]?.url ?? '')
    await auth.flows.completePasswordReset({ token, newPassword: 'new-password-9' })
    await expect(auth.flows.completePasswordReset({ token, newPassword: 'second-new-password' })).rejects.toMatchObject(
      { code: 'AUTH_RECOVERY_TOKEN_INVALID' },
    )
  })

  it('reset with MFA enrolled requires fresh AAL=2 session', async () => {
    const { auth, channel, adapter } = buildAuth()
    const identity = await auth.identities.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'old-password-9', adapter.credentials)
    const ch = await auth.mfa.beginTotpEnrollment(identity.id, 'a@x.com')
    await auth.mfa.confirmTotpEnrollment(identity.id, totpAt(ch.secret, Math.floor(Date.now() / 1000 / 30)))

    await auth.flows.requestPasswordReset({
      input: { email: 'a@x.com' },
      findIdentityByEmail: (email) => auth.identities.getByEmail(email),
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
    const reset = await auth.flows.completePasswordReset({
      currentSid: aal2Sid,
      newPassword: 'new-password-9',
      token,
    })
    expect(reset.ok).toBe(true)
    expect(reset.intents.length).toBeGreaterThan(0)
  })

  it('expired reset token surfaces AUTH_RECOVERY_TOKEN_EXPIRED', async () => {
    const { auth, channel, adapter } = buildAuth()
    const identity = await auth.identities.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'old-password-9', adapter.credentials)
    await auth.flows.requestPasswordReset({
      input: { email: 'a@x.com' },
      findIdentityByEmail: (email) => auth.identities.getByEmail(email),
    })
    const token = tokenFrom(channel.sent[0]?.url ?? '')
    const creds = await adapter.credentials.listByIdentity(identity.id, 'recovery', {})
    const cred = creds[0]
    if (!cred) throw new Error('missing credential')
    adapter.raw.credentials.set(cred.id, { ...cred, expiresAt: new Date(Date.now() - 1) })
    await expect(auth.flows.completePasswordReset({ token, newPassword: 'new-password-9' })).rejects.toMatchObject({
      code: 'AUTH_RECOVERY_TOKEN_EXPIRED',
    })
  })

  it('completePasswordReset rejects email-verification tokens (cross-kind confusion)', async () => {
    const { auth, channel, adapter } = buildAuth()
    const identity = await auth.identities.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'old-password-9', adapter.credentials)

    // Mint an email-verification token directly via the flow.
    await auth.flows.requestEmailVerification({
      identityId: identity.id,
    })
    const verifyToken = tokenFrom(channel.sent[0]?.url ?? '')

    // Attacker tries to use it for a password reset. Must be refused.
    await expect(
      auth.flows.completePasswordReset({ token: verifyToken, newPassword: 'evil-password' }),
    ).rejects.toMatchObject({
      code: 'AUTH_RECOVERY_TOKEN_INVALID',
    })

    // Original password still works.
    const verify = await auth.passwords.verify(identity.id, 'old-password-9', adapter.credentials)
    expect(verify.ok).toBe(true)

    void adapter
  })

  it('completePasswordReset rejects account-deletion tokens', async () => {
    const { auth, channel, adapter } = buildAuth()
    const identity = await auth.identities.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'old-password-9', adapter.credentials)

    await auth.flows.requestAccountDeletion({
      identityId: identity.id,
    })
    const deleteToken = tokenFrom(channel.sent[0]?.url ?? '')

    await expect(
      auth.flows.completePasswordReset({ token: deleteToken, newPassword: 'evil-password' }),
    ).rejects.toMatchObject({ code: 'AUTH_RECOVERY_TOKEN_INVALID' })

    void adapter
  })

  it('completePasswordReset rejects signup-flow tokens', async () => {
    const { auth } = buildAuth()
    // Start a signup-flow which mints a recovery+metadata.purpose='signup-flow' row.
    const begin = await auth.flows.beginSignUp({ email: 'fresh@x.com' })
    expect(begin.flowToken).toBeDefined()

    await expect(
      auth.flows.completePasswordReset({ token: begin.flowToken, newPassword: 'evil-password' }),
    ).rejects.toMatchObject({ code: 'AUTH_RECOVERY_TOKEN_INVALID' })
  })
})
