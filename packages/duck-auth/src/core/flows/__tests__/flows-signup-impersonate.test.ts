import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import type { Credential } from '~/core/credentials'
import { AuthEngine } from '~/core/engine'
import type { Identities } from '~/core/identities/identities.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { passwords, ScryptHasher } from '~/providers/passwords'

interface MyProfile extends Identities.ProfileMetadataBase {
  email: string
  emailVerified?: boolean
  name?: string
  acceptedTerms?: boolean
}

function buildAuth(opts: { credentials?: (base: Credential.Store) => Credential.Store } = {}): {
  auth: AuthEngine<MyProfile>
  adapter: MemoryAdapter<MyProfile>
} {
  const adapter = new MemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app',
    transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: opts.credentials?.(adapter.credentials) ?? adapter.credentials,
    },
    limiter: new MemoryLimiter({ max: 20, windowMs: 60_000 }),
    providers: [passwords({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) })],
  })
  return { auth, adapter }
}

describe('FlowsImpl - signup state machine', () => {
  let auth: AuthEngine<MyProfile>
  let adapter: MemoryAdapter<MyProfile>

  beforeEach(() => {
    ;({ auth, adapter } = buildAuth())
  })

  it('beginSignUp creates identity (emailVerified=false) + persists flow + returns plaintext flowToken', async () => {
    const { flow, flowToken } = await auth.flows.beginSignUp({
      email: 'new@x.com',
      required: ['email-verified', 'terms-accepted'],
    })
    expect(flowToken).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(flow.identityId).toBeTruthy()
    expect(flow.completed).toEqual(['email-collected'])

    const identity = await adapter.identities.find({ id: flow.identityId })
    expect(identity?.profile?.email).toBe('new@x.com')
    expect(identity?.emailVerified).toBe(false)
  })

  it('getSignUpFlow returns the stored state for a valid token', async () => {
    const { flowToken } = await auth.flows.beginSignUp({ email: 'a@x.com' })
    const got = await auth.flows.getSignUpFlow(flowToken)
    expect(got.completed).toContain('email-collected')
  })

  it('getSignUpFlow rejects a bogus token, and orNull reads that back as null', async () => {
    await expect(auth.flows.getSignUpFlow('not-real')).rejects.toMatchObject({
      code: 'AUTH_CREDENTIAL_NOT_FOUND',
    })
    await expect(auth.flows.getSignUpFlow('not-real').orNull()).resolves.toBeNull()
  })

  it('advanceSignUp appends stages idempotently and merges profile data', async () => {
    const { flowToken } = await auth.flows.beginSignUp({
      email: 'a@x.com',
      required: ['email-verified', 'profile-completed', 'terms-accepted'],
    })
    const afterEmail = await auth.flows.advanceSignUp({
      flowToken,
      stage: 'email-verified',
      profilePatch: { emailVerified: true },
    })
    expect(afterEmail.completed).toContain('email-verified')

    const afterProfile = await auth.flows.advanceSignUp({
      flowToken,
      stage: 'profile-completed',
      profilePatch: { name: 'New User' },
    })
    expect(afterProfile.data.name).toBe('New User')
    expect(afterProfile.data.emailVerified).toBe(true)

    // Idempotent: re-advancing same stage doesn't duplicate.
    const again = await auth.flows.advanceSignUp({ flowToken, stage: 'profile-completed' })
    expect(again.completed.filter((s) => s === 'profile-completed').length).toBe(1)
  })

  it('completeSignUp fails with AUTH_SIGNUP_INCOMPLETE listing missing stages', async () => {
    const { flowToken } = await auth.flows.beginSignUp({
      email: 'a@x.com',
      required: ['email-verified', 'terms-accepted'],
    })
    await expect(auth.flows.completeSignUp({ flowToken })).rejects.toMatchObject({
      code: 'AUTH_SIGNUP_INCOMPLETE',
      meta: { missing: ['email-verified', 'terms-accepted'] },
    })
  })

  it('completeSignUp succeeds when required stages are completed, issues a session, merges profile, revokes flow', async () => {
    const { flow, flowToken } = await auth.flows.beginSignUp({
      email: 'a@x.com',
      required: ['email-verified', 'terms-accepted'],
    })
    await auth.flows.advanceSignUp({
      flowToken,
      stage: 'email-verified',
      profilePatch: { emailVerified: true },
    })
    await auth.flows.advanceSignUp({
      flowToken,
      stage: 'terms-accepted',
      profilePatch: { acceptedTerms: true },
    })
    const out = await auth.flows.completeSignUp({ flowToken })
    expect(out.session!.identityId).toBe(flow.identityId)

    const fresh = await adapter.identities.find({ id: flow.identityId })
    expect(fresh?.profile?.emailVerified).toBe(true)
    expect(fresh?.profile?.acceptedTerms).toBe(true)

    // Replay refused.
    await expect(auth.flows.completeSignUp({ flowToken })).rejects.toMatchObject({
      code: 'AUTH_SIGNUP_TOKEN_INVALID',
    })
  })

  it('a second completion reading before the winner revokes gets no session of its own', async () => {
    // The replay case above is sequential, so it never opens the window. `completeSignUp` revokes its
    // flow token at the very end and the revoke is unconditional, so before the claim was added two
    // concurrent completions both read a live row and both walked away with a session.
    let gatedId: string | null = null
    let calls = 0
    let release = (): void => {}
    const held = new Promise<void>((resolve) => {
      release = resolve
    })
    const { auth: engine, adapter: ad } = buildAuth({
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
    const { flow, flowToken } = await engine.flows.beginSignUp({ email: 'race@x.com', required: ['terms-accepted'] })
    await engine.flows.advanceSignUp({ flowToken, profilePatch: { acceptedTerms: true }, stage: 'terms-accepted' })
    const [row] = await ad.credentials.listByIdentity(flow.identityId, 'recovery', {})
    gatedId = row?.id ?? null

    const winner = engine.flows.completeSignUp({ flowToken })
    await vi.waitFor(() => {
      if (calls === 0) throw new Error('the winner has not reached its revoke yet')
    })

    await expect(engine.flows.completeSignUp({ flowToken })).rejects.toMatchObject({
      code: 'AUTH_SIGNUP_TOKEN_INVALID',
    })
    release()
    expect((await winner).session).toBeTruthy()

    // One flow token, one session.
    expect(await ad.sessions.listByIdentity(flow.identityId, {})).toHaveLength(1)
  })
})

describe('FlowsImpl - impersonation', () => {
  let auth: AuthEngine<MyProfile>
  let adapter: MemoryAdapter<MyProfile>
  let adminId: string
  let targetId: string
  let adminSid: string

  beforeEach(async () => {
    ;({ adapter, auth } = buildAuth())
    const admin = await auth.identities.create({ profile: { username: 'admin@x.com', email: 'admin@x.com' } })
    adminId = admin.id
    const target = await auth.identities.create({ profile: { username: 'target@x.com', email: 'target@x.com' } })
    targetId = target.id
    const created = await auth.sessions.create({
      identityId: admin.id,
      kind: 'user',
      aal: 2,
      factors: [{ method: 'password', completedAt: new Date() }],
    })
    adminSid = created.sid
  })

  it('impersonate issues actingAs session when authorize returns true; emits identity.impersonated', async () => {
    const handler = vi.fn()
    auth.events.on('identity.impersonated', handler)
    const out = await auth.flows.impersonate({
      realSid: adminSid,
      targetIdentityId: targetId,
      reason: 'support-ticket-1234',
      authorize: async () => true,
    })
    expect(out.session.identityId).toBe(targetId)
    expect(out.session!.actingAs?.realIdentityId).toBe(adminId)
    expect(handler).toHaveBeenCalledOnce()
  })

  it('records which IAM decision allowed it, the field the event declares and nothing could supply', async () => {
    // `iamDecisionId` appeared once in the whole package: its own declaration, whose doc calls an
    // impersonation nobody can trace to an authorization "the one entry an audit log cannot afford to be
    // missing". No option carried it and the only emitter never set it.
    const seen: Array<Record<string, unknown>> = []
    auth.events.on('identity.impersonated', (p) => {
      seen.push(p as unknown as Record<string, unknown>)
    })

    await auth.flows.impersonate({
      authorize: async () => true,
      iamDecisionId: 'decision-9f3',
      realSid: adminSid,
      reason: 'support-ticket-1234',
      targetIdentityId: targetId,
    })

    expect(seen[0]?.iamDecisionId).toBe('decision-9f3')
  })

  it('omits the key entirely when no decision is named, rather than publishing an undefined', async () => {
    const seen: Array<Record<string, unknown>> = []
    auth.events.on('identity.impersonated', (p) => {
      seen.push(p as unknown as Record<string, unknown>)
    })

    await auth.flows.impersonate({
      authorize: async () => true,
      realSid: adminSid,
      reason: 'no-iam-here',
      targetIdentityId: targetId,
    })

    expect(seen[0] && 'iamDecisionId' in seen[0]).toBe(false)
  })

  it('refuses an empty or oversize iamDecisionId, as it does for reason', async () => {
    for (const bad of ['', 'd'.repeat(257)]) {
      await expect(
        auth.flows.impersonate({
          authorize: async () => true,
          iamDecisionId: bad,
          realSid: adminSid,
          reason: 'x',
          targetIdentityId: targetId,
        }),
      ).rejects.toMatchObject({ code: 'AUTH_IMPERSONATE_FORBIDDEN' })
    }
  })

  it('impersonate refused when authorize returns false', async () => {
    await expect(
      auth.flows.impersonate({
        realSid: adminSid,
        targetIdentityId: targetId,
        reason: 'x',
        authorize: async () => false,
      }),
    ).rejects.toMatchObject({ code: 'AUTH_IMPERSONATE_FORBIDDEN' })
  })

  it('refuses self-impersonation regardless of authorize result', async () => {
    await expect(
      auth.flows.impersonate({
        realSid: adminSid,
        targetIdentityId: adminId,
        reason: 'x',
        authorize: async () => true,
      }),
    ).rejects.toMatchObject({ code: 'AUTH_IMPERSONATE_FORBIDDEN' })
  })

  it('rejects oversize reason (>256 chars) with IMPERSONATE_FORBIDDEN', async () => {
    const big = 'A'.repeat(257)
    await expect(
      auth.flows.impersonate({
        realSid: adminSid,
        targetIdentityId: targetId,
        reason: big,
        authorize: async () => true,
      }),
    ).rejects.toMatchObject({ code: 'AUTH_IMPERSONATE_FORBIDDEN' })
  })

  it('rejects empty reason', async () => {
    await expect(
      auth.flows.impersonate({
        realSid: adminSid,
        targetIdentityId: targetId,
        reason: '',
        authorize: async () => true,
      }),
    ).rejects.toMatchObject({ code: 'AUTH_IMPERSONATE_FORBIDDEN' })
  })

  it('rejects non-string reason without crashing', async () => {
    await expect(
      auth.flows.impersonate({
        realSid: adminSid,
        targetIdentityId: targetId,
        reason: 42 as unknown as string,
        authorize: async () => true,
      }),
    ).rejects.toMatchObject({ code: 'AUTH_IMPERSONATE_FORBIDDEN' })
  })

  it('accepts reason at the 256-char cap (boundary)', async () => {
    const sized = 'A'.repeat(256)
    const out = await auth.flows.impersonate({
      realSid: adminSid,
      targetIdentityId: targetId,
      reason: sized,
      authorize: async () => true,
    })
    expect(out.session.actingAs?.reason).toBe(sized)
  })

  it('TTL capped at 1 hour even when caller supplies longer', async () => {
    const out = await auth.flows.impersonate({
      realSid: adminSid,
      targetIdentityId: targetId,
      reason: 'x',
      ttlMs: 24 * 60 * 60_000,
      authorize: async () => true,
    })
    const cap = 60 * 60_000
    expect(
      (out.session!.actingAs?.expiresAt?.getTime() ?? 0) - (out.session!.actingAs?.startedAt?.getTime() ?? 0),
    ).toBeLessThanOrEqual(cap)
  })

  it('releaseImpersonation revokes the actingAs session', async () => {
    const out = await auth.flows.impersonate({
      realSid: adminSid,
      targetIdentityId: targetId,
      reason: 'x',
      authorize: async () => true,
    })
    await auth.flows.releaseImpersonation(out.sid)
    await expect(auth.sessions.getBySid(out.sid)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
  })

  it('releaseImpersonation with non-impersonation SID surfaces AUTH_IMPERSONATE_EXPIRED', async () => {
    await expect(auth.flows.releaseImpersonation(adminSid)).rejects.toMatchObject({
      code: 'AUTH_IMPERSONATE_EXPIRED',
    })
  })

  it('resolveBySid honors actingAs.expiresAt (impersonation cap enforced)', async () => {
    const out = await auth.flows.impersonate({
      realSid: adminSid,
      targetIdentityId: targetId,
      reason: 'x',
      authorize: async () => true,
    })
    // Fast-forward actingAs.expiresAt into the past. Mirrors a normal
    // TTL elapse without waiting an hour.
    const row = await auth.sessions.getBySid(out.sid)
    if (!row?.actingAs) throw new Error('expected actingAs')
    adapter.raw.sessions.set(row.id, {
      ...row,
      actingAs: { ...row.actingAs, expiresAt: new Date(Date.now() - 1) },
    })
    // Re-fetch via resolveSession: should delete the row and refuse the token.
    await expect(
      auth.resolveSession({ headers: new Headers({ cookie: `duck-sid=${out.sid}` }) }),
    ).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    // Row should be gone.
    await expect(auth.sessions.getBySid(out.sid)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
  })
})
