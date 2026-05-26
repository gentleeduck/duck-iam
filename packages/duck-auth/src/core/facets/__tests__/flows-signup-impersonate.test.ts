/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAuthAdapter } from '../../../adapters/memory'
import { MemoryLimiter } from '../../../limiters/memory'
import { AuthRoot } from '../../auth'
import { ScryptHasher } from '../../password/scrypt'
import { CookieTransport } from '../../transport/cookie'

interface MyProfile {
  email: string
  emailVerified?: boolean
  name?: string
  acceptedTerms?: boolean
}

function buildAuth(): {
  auth: AuthRoot<MyProfile>
  adapter: MemoryAuthAdapter<MyProfile>
} {
  const adapter = new MemoryAuthAdapter<MyProfile>()
  const auth = new AuthRoot<MyProfile>({
    baseUrl: 'https://app',
    transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new MemoryLimiter({ max: 20, windowMs: 60_000 }),
    passwords: { hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) },
  })
  return { auth, adapter }
}

describe('FlowsFacet - signup state machine (DESIGN section 34)', () => {
  let auth: AuthRoot<MyProfile>
  let adapter: MemoryAuthAdapter<MyProfile>

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

    const identity = await adapter.identities.findById(flow.identityId, {})
    expect(identity?.profile?.email).toBe('new@x.com')
    expect(identity?.profile?.emailVerified).toBe(false)
  })

  it('getSignUpFlow returns the stored state for a valid token', async () => {
    const { flowToken } = await auth.flows.beginSignUp({ email: 'a@x.com' })
    const got = await auth.flows.getSignUpFlow(flowToken)
    expect(got?.completed).toContain('email-collected')
  })

  it('getSignUpFlow returns null for bogus token', async () => {
    expect(await auth.flows.getSignUpFlow('not-real')).toBeNull()
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

  it('completeSignUp fails with AUTH/SIGNUP_INCOMPLETE listing missing stages', async () => {
    const { flowToken } = await auth.flows.beginSignUp({
      email: 'a@x.com',
      required: ['email-verified', 'terms-accepted'],
    })
    await expect(auth.flows.completeSignUp({ flowToken })).rejects.toMatchObject({
      code: 'AUTH/SIGNUP_INCOMPLETE',
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

    const fresh = await adapter.identities.findById(flow.identityId, {})
    expect(fresh?.profile?.emailVerified).toBe(true)
    expect(fresh?.profile?.acceptedTerms).toBe(true)

    // Replay refused.
    await expect(auth.flows.completeSignUp({ flowToken })).rejects.toMatchObject({
      code: 'AUTH/SIGNUP_TOKEN_INVALID',
    })
  })
})

describe('FlowsFacet - impersonation (DESIGN section 38)', () => {
  let auth: AuthRoot<MyProfile>
  let adminId: string
  let targetId: string
  let adminSid: string

  beforeEach(async () => {
    ;({ auth } = buildAuth())
    const admin = await auth.identities.create({ profile: { email: 'admin@x.com' } })
    adminId = admin.id
    const target = await auth.identities.create({ profile: { email: 'target@x.com' } })
    targetId = target.id
    const created = await auth.sessions.create({
      identityId: admin.id,
      kind: 'user',
      aal: 2,
      factors: [{ method: 'password', completedAt: Date.now() }],
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

  it('impersonate refused when authorize returns false', async () => {
    await expect(
      auth.flows.impersonate({
        realSid: adminSid,
        targetIdentityId: targetId,
        reason: 'x',
        authorize: async () => false,
      }),
    ).rejects.toMatchObject({ code: 'AUTH/IMPERSONATE_FORBIDDEN' })
  })

  it('refuses self-impersonation regardless of authorize result', async () => {
    await expect(
      auth.flows.impersonate({
        realSid: adminSid,
        targetIdentityId: adminId,
        reason: 'x',
        authorize: async () => true,
      }),
    ).rejects.toMatchObject({ code: 'AUTH/IMPERSONATE_FORBIDDEN' })
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
    expect((out.session!.actingAs?.expiresAt ?? 0) - (out.session!.actingAs?.startedAt ?? 0)).toBeLessThanOrEqual(cap)
  })

  it('releaseImpersonation revokes the actingAs session', async () => {
    const out = await auth.flows.impersonate({
      realSid: adminSid,
      targetIdentityId: targetId,
      reason: 'x',
      authorize: async () => true,
    })
    await auth.flows.releaseImpersonation(out.sid)
    expect(await auth.sessions.getBySid(out.sid)).toBeNull()
  })

  it('releaseImpersonation with non-impersonation SID surfaces AUTH/IMPERSONATE_EXPIRED', async () => {
    await expect(auth.flows.releaseImpersonation(adminSid)).rejects.toMatchObject({
      code: 'AUTH/IMPERSONATE_EXPIRED',
    })
  })
})
