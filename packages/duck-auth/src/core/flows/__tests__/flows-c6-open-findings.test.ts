/**
 * The fifteen findings `plans/C6-flows/AUDIT.md` still had open, pinned - plus
 * one the work turned up.
 *
 *   F2  - password reset stored the raw address a second time, in credential
 *         metadata, which `identities.erase` has no reason to sweep.
 *   F6  - a failed MFA gate threw without consuming or bounding anything, so
 *         the token stayed grindable for its whole TTL.
 *   F7  - the password was written before the sessions were revoked, and the
 *         revoke bypassed the single rotation path.
 *   F10 - `requestEmailVerification` spent the limiter before it knew whether
 *         there was anything to send.
 *   F11 - `completeEmailVerification` let a stale write surface raw, after the
 *         token was already spent.
 *   F14 - impersonation sessions carried the admin's `aal` and `factors`.
 *   F15 - `releaseImpersonation` cleared the bearer, logging the admin out.
 *   F17 - `ctxFactory` was called two and three times per call.
 *   F18 - the unlink lockout guard was a read-then-write race.
 *   F19 - unlinking an authentication factor emitted nothing.
 *   F20 - `providerSub` was an unverifiable string with no stated invariant.
 *   F23 - `advanceSignUp` revoked its own token and re-inserted it.
 *   F24 - a signup rotated as a `guest-promotion`.
 *   F25 - flow state, `profilePatch` included, dodged `profileMaxBytes`.
 *   F26 - flows wrote identities through the raw store, past the facet.
 *   F28 - NEW. The MFA gate on `completePasswordReset` accepted any fresh AAL=2
 *         session, without asking whose it was.
 *
 * Each test is written to fail against the pre-fix code, not merely to describe
 * the post-fix code.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import type { Channel } from '~/channels/channels.types'
import { AuthTestChannel } from '~/channels/console'
import { getCredentialPurpose } from '~/core/credentials/credentials'
import { AuthEngine } from '~/core/engine'
import type { Identities } from '~/core/identities/identities.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { mfaProvider, totpAt } from '~/providers/mfa'
import { passwords, ScryptHasher } from '~/providers/passwords'

interface MyProfile extends Identities.ProfileMetadataBase {
  email: string
}

function build(opts: { limit?: number; profileMaxBytes?: number } = {}) {
  const adapter = new MemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app',
    ...(opts.profileMaxBytes !== undefined && { identities: { profileMaxBytes: opts.profileMaxBytes } }),
    limiter: new MemoryLimiter({ max: opts.limit ?? 50, windowMs: 60_000 }),
    providers: [passwords({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) }), mfaProvider()],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
  return { adapter, auth }
}

const ALLOW_LINK = async () => true

async function enrollTotp(auth: AuthEngine<MyProfile>, identityId: string, email: string): Promise<void> {
  const ch = await auth.mfa.beginTotpEnrollment(identityId, email)
  await auth.mfa.confirmTotpEnrollment(identityId, totpAt(ch.secret, Math.floor(Date.now() / 1000 / 30)))
}

function tokenFrom(channel: AuthTestChannel): string {
  const url = (channel.outbox.at(-1)?.vars as { url: string }).url
  return new URL(url).searchParams.get('token') ?? ''
}

// --- impersonation -----------------------------------------------------------

describe('F14 / F15 - impersonation neither carries nor returns assurance', () => {
  let auth: AuthEngine<MyProfile>
  let adminId: string
  let targetId: string
  let adminSid: string

  beforeEach(async () => {
    ;({ auth } = build())
    const admin = await auth.identities.create({ profile: { email: 'admin@x.com', username: 'admin@x.com' } })
    const target = await auth.identities.create({ profile: { email: 'target@x.com', username: 'target@x.com' } })
    adminId = admin.id
    targetId = target.id
    const created = await auth.sessions.create({
      aal: 2,
      factors: [
        { completedAt: new Date(), method: 'password' },
        { completedAt: new Date(), method: 'totp' },
      ],
      identityId: admin.id,
      kind: 'user',
    })
    adminSid = created.sid
  })

  const start = () =>
    auth.flows.impersonate({
      authorize: async () => true,
      realSid: adminSid,
      reason: 'support-ticket-1234',
      targetIdentityId: targetId,
    })

  it('F14 - the impersonation session records no factors, whatever the admin did', async () => {
    const out = await start()
    expect(out.session.identityId).toBe(targetId)
    // The admin's own session is AAL 2 with a totp factor. Copying that onto the
    // target's session made `session.factors` answer for the wrong person.
    expect(out.session.aal).toBe(1)
    expect(out.session.factors).toEqual([])
    expect(out.session.actingAs?.realIdentityId).toBe(adminId)
  })

  it('F15 - release hands the operator a session of their own instead of logging them out', async () => {
    const out = await start()
    const released = await auth.flows.releaseImpersonation(out.sid)

    expect(released.session?.identityId).toBe(adminId)
    expect(released.session?.actingAs).toBeNull()
    expect(released.sid).not.toBe('')
    // A `transport.revoke()` intent carries no cookie value; an `issue` does.
    expect(released.intents.some((i) => i.type === 'setCookie' && i.value !== '')).toBe(true)
    // And the returned sid actually resolves.
    expect((await auth.sessions.getBySid(released.sid))?.identityId).toBe(adminId)
  })

  it('F15 - the impersonation sid is dead once released', async () => {
    const out = await start()
    await auth.flows.releaseImpersonation(out.sid)
    expect(await auth.sessions.getBySid(out.sid)).toBeNull()
  })

  it('F15 - the returned session starts at AAL 1, so privileged work needs a fresh step-up', async () => {
    const out = await start()
    const released = await auth.flows.releaseImpersonation(out.sid)
    expect(released.session?.aal).toBe(1)
    expect(released.session?.factors).toEqual([])
  })

  it('F15 - an operator whose own identity is gone gets the bearer cleared, not an error', async () => {
    const out = await start()
    await auth.identities.erase(adminId, { reason: 'gdpr' })
    const released = await auth.flows.releaseImpersonation(out.sid)
    expect(released.session).toBeNull()
    expect(released.sid).toBe('')
    expect(await auth.sessions.getBySid(out.sid)).toBeNull()
  })
})

// --- provider linking --------------------------------------------------------

describe('F17 / F18 / F19 / F20 - provider linking', () => {
  let auth: AuthEngine<MyProfile>
  let adapter: MemoryAdapter<MyProfile>
  let identityId: string

  beforeEach(async () => {
    ;({ adapter, auth } = build())
    const ident = await auth.identities.create({ profile: { email: 'u@x.com', username: 'u@x.com' } })
    identityId = ident.id
  })

  it('F20 - a link with no authorize callback is a wiring fault, not a link', async () => {
    await expect(
      auth.flows.linkProvider({
        authorize: undefined as unknown as typeof ALLOW_LINK,
        identityId,
        providerId: 'authGoogle',
        providerSub: 'sub-1',
      }),
    ).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
    expect((await auth.identities.getById(identityId))?.providers).toEqual([])
  })

  it('F20 - a refusal writes nothing and reports as a provider failure', async () => {
    await expect(
      auth.flows.linkProvider({
        authorize: async () => false,
        identityId,
        providerId: 'authGoogle',
        providerSub: 'sub-1',
      }),
    ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED', meta: { detail: 'authorize() returned false' } })
    expect((await auth.identities.getById(identityId))?.providers).toEqual([])
  })

  it('F20 - the callback sees the identity it is being asked about', async () => {
    const seen = vi.fn(
      async (_input: { identity: Identities.Me<MyProfile>; providerId: string; providerSub: string }) => true,
    )
    await auth.flows.linkProvider({ authorize: seen, identityId, providerId: 'authGoogle', providerSub: 'sub-1' })
    expect(seen).toHaveBeenCalledWith(expect.objectContaining({ providerId: 'authGoogle', providerSub: 'sub-1' }))
    expect(seen.mock.calls[0]?.[0]?.identity.id).toBe(identityId)
  })

  it('F17 - one context per call, not two or three', async () => {
    const built: unknown[] = []
    const deps = auth.flows.deps
    const original = deps.ctxFactory
    deps.ctxFactory = (tenantId?: string) => {
      built.push(tenantId)
      return original(tenantId)
    }
    await auth.flows.linkProvider({ authorize: ALLOW_LINK, identityId, providerId: 'authGoogle', providerSub: 's1' })
    expect(built).toHaveLength(1)
    built.length = 0
    await auth.flows.unlinkProvider({ allowLockout: true, identityId, providerId: 'authGoogle' })
    expect(built).toHaveLength(1)
    deps.ctxFactory = original
  })

  it('F19 - unlinking emits identity.unlinked, the mirror of identity.linked', async () => {
    const seen = vi.fn()
    auth.events.on('identity.unlinked', seen)
    await auth.flows.linkProvider({ authorize: ALLOW_LINK, identityId, providerId: 'authGoogle', providerSub: 's1' })
    await auth.flows.linkProvider({ authorize: ALLOW_LINK, identityId, providerId: 'authGithub', providerSub: 's2' })
    await auth.flows.unlinkProvider({ identityId, providerId: 'authGoogle' })
    expect(seen).toHaveBeenCalledOnce()
    expect(seen.mock.calls[0]?.[0]).toMatchObject({
      allowedLockout: false,
      identityId,
      providerId: 'authGoogle',
    })
  })

  it('F19 - the event records that a caller overrode the lockout guard', async () => {
    const seen = vi.fn()
    auth.events.on('identity.unlinked', seen)
    await auth.flows.linkProvider({ authorize: ALLOW_LINK, identityId, providerId: 'authGoogle', providerSub: 's1' })
    await auth.flows.unlinkProvider({ allowLockout: true, identityId, providerId: 'authGoogle' })
    expect(seen.mock.calls[0]?.[0]).toMatchObject({ allowedLockout: true })
  })

  it('F18 - two concurrent unlinks of different providers cannot both land', async () => {
    await auth.flows.linkProvider({ authorize: ALLOW_LINK, identityId, providerId: 'authGoogle', providerSub: 's1' })
    await auth.flows.linkProvider({ authorize: ALLOW_LINK, identityId, providerId: 'authGithub', providerSub: 's2' })
    // No password, no passkey: these two links are the entire set of factors,
    // and each unlink on its own is legal because the other one survives it.
    const results = await Promise.allSettled([
      auth.flows.unlinkProvider({ identityId, providerId: 'authGoogle' }),
      auth.flows.unlinkProvider({ identityId, providerId: 'authGithub' }),
    ])
    const after = await auth.identities.getById(identityId)
    expect(after?.providers.length).toBeGreaterThan(0)
    expect(results.some((r) => r.status === 'rejected')).toBe(true)
  })

  it('F18 - a rolled-back unlink restores the link it removed, addedAt and all', async () => {
    await auth.flows.linkProvider({ authorize: ALLOW_LINK, identityId, providerId: 'authGoogle', providerSub: 's1' })
    await auth.flows.linkProvider({ authorize: ALLOW_LINK, identityId, providerId: 'authGithub', providerSub: 's2' })
    const before = await auth.identities.getById(identityId)
    await Promise.allSettled([
      auth.flows.unlinkProvider({ identityId, providerId: 'authGoogle' }),
      auth.flows.unlinkProvider({ identityId, providerId: 'authGithub' }),
    ])
    const after = await auth.identities.getById(identityId)
    // Not vacuous: the loop below proves nothing about an empty list.
    expect(after?.providers.length).toBeGreaterThan(0)
    for (const link of after?.providers ?? []) {
      const original = before?.providers.find((p) => p.providerId === link.providerId)
      expect(link.providerSub).toBe(original?.providerSub)
      expect(link.addedAt.getTime()).toBe(original?.addedAt.getTime())
    }
  })

  it('F18 - a live password still counts as the surviving factor', async () => {
    await auth.flows.linkProvider({ authorize: ALLOW_LINK, identityId, providerId: 'authGoogle', providerSub: 's1' })
    await auth.passwords.set(identityId, 'a-real-password-1', adapter.credentials)
    await expect(auth.flows.unlinkProvider({ identityId, providerId: 'authGoogle' })).resolves.toMatchObject({
      identityId,
    })
    expect((await auth.identities.getById(identityId))?.providers).toEqual([])
  })
})

// --- signup ------------------------------------------------------------------

describe('F23 / F24 / F25 / F26 - signup', () => {
  it('F25 - an oversized initialProfile is refused before anything is stored', async () => {
    const { adapter, auth } = build({ profileMaxBytes: 256 })
    await expect(
      auth.flows.beginSignUp({ email: 'big@x.com', initialProfile: { bio: 'x'.repeat(400) } as Partial<MyProfile> }),
    ).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
    const ident = await adapter.identities.findByEmail('big@x.com')
    expect(await adapter.credentials.listByIdentity(ident?.id ?? 'none', 'recovery', {})).toEqual([])
  })

  it('F25 - an oversized profilePatch is refused mid-flow, and the flow survives', async () => {
    const { auth } = build({ profileMaxBytes: 256 })
    const { flowToken } = await auth.flows.beginSignUp({ email: 'a@x.com' })
    await expect(
      auth.flows.advanceSignUp({
        flowToken,
        profilePatch: { bio: 'x'.repeat(400) } as Partial<MyProfile>,
        stage: 'profile-completed',
      }),
    ).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
    // Refused, not destroyed: the token is still the one the caller holds.
    const flow = await auth.flows.getSignUpFlow(flowToken)
    expect(flow?.completed).toEqual(['email-collected'])
  })

  it('F23 - advancing never revokes the token it was handed', async () => {
    const { adapter, auth } = build()
    const { flow, flowToken } = await auth.flows.beginSignUp({ email: 'a@x.com' })
    await auth.flows.advanceSignUp({ flowToken, stage: 'email-verified' })
    await auth.flows.advanceSignUp({ flowToken, stage: 'terms-accepted' })
    const rows = await adapter.credentials.listByIdentity(flow.identityId, 'recovery', {})
    // One row, never revoked - it used to be revoked and re-inserted on every
    // stage, so a failure between the two left the user holding a dead token.
    expect(rows).toHaveLength(1)
    expect(rows[0]?.revokedAt).toBeNull()
    expect((await auth.flows.getSignUpFlow(flowToken))?.completed).toEqual([
      'email-collected',
      'email-verified',
      'terms-accepted',
    ])
  })

  it('F23 - a concurrent advance still loses on the version guard', async () => {
    const { auth } = build()
    const { flowToken } = await auth.flows.beginSignUp({ email: 'a@x.com' })
    const results = await Promise.allSettled([
      auth.flows.advanceSignUp({ flowToken, stage: 'email-verified' }),
      auth.flows.advanceSignUp({ flowToken, stage: 'terms-accepted' }),
    ])
    expect(results.filter((r) => r.status === 'rejected')).toHaveLength(1)
  })

  it('F24 - `sign-up` is a purpose the rotation matrix decided about, not an unhandled one', async () => {
    const { auth } = build()
    const ident = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a@x.com' } })
    const guest = await auth.sessions.create({ aal: 1, factors: [], identityId: null, kind: 'guest' })
    // The switch in `rotateOrCreate` is exhaustive: a purpose added to the union
    // without a case throws `AUTH_MISCONFIGURED` rather than silently doing
    // nothing. This asserts the case exists and revokes, which is what
    // `guest-promotion` did and what a signup needs - the name is what changed.
    const out = await auth.sessions.rotateOrCreate({
      aal: 1,
      factors: [{ completedAt: new Date(), method: 'magic-link' }],
      identity: ident,
      identityId: ident.id,
      kind: 'user',
      previousSid: guest.sid,
      purpose: 'sign-up',
    })
    expect(out.session.identityId).toBe(ident.id)
    expect(await auth.sessions.getBySid(guest.sid)).toBeNull()
  })

  it('F24 - completeSignUp still revokes what it came in on', async () => {
    const { auth } = build()
    const guest = await auth.sessions.create({ aal: 1, factors: [], identityId: null, kind: 'guest' })
    const { flowToken } = await auth.flows.beginSignUp({ email: 'a@x.com', required: [] })
    const out = await auth.flows.completeSignUp({ flowToken, previousSid: guest.sid })
    expect(out.sid).not.toBe(guest.sid)
    expect(await auth.sessions.getBySid(guest.sid)).toBeNull()
  })

  it('F26 - completeSignUp goes through the facet, so the cap applies to the merge', async () => {
    const { auth } = build({ profileMaxBytes: 400 })
    const { flow, flowToken } = await auth.flows.beginSignUp({ email: 'a@x.com', required: [] })
    // Fatten the identity row directly, under the cap, then complete: the merge
    // of the two crosses it. The raw store would have written it regardless.
    const ident = await auth.identities.getById(flow.identityId)
    if (!ident) throw new Error('expected identity')
    await auth.identities.updateProfile(ident.id, { bio: 'y'.repeat(300) } as Partial<MyProfile>, ident.version)
    const flow2 = await auth.flows.advanceSignUp({
      flowToken,
      profilePatch: { nickname: 'z'.repeat(200) } as Partial<MyProfile>,
      stage: 'profile-completed',
    })
    expect(flow2.completed).toContain('profile-completed')
    await expect(auth.flows.completeSignUp({ flowToken })).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
  })
})

// --- email verification ------------------------------------------------------

describe('F10 / F11 / F26 - email verification', () => {
  it('F10 - an unknown identity does not spend the limiter', async () => {
    const { auth } = build({ limit: 2 })
    const channel = new AuthTestChannel()
    for (let i = 0; i < 5; i++) {
      await expect(
        auth.flows.requestEmailVerification({ channels: { email: channel }, identityId: 'no-such-id' }),
      ).rejects.toMatchObject({ code: 'AUTH_UNAUTHENTICATED' })
    }
  })

  it('F10 - an already-verified address does not spend the limiter either', async () => {
    const { adapter, auth } = build({ limit: 2 })
    const channel = new AuthTestChannel()
    const ident = await auth.identities.create({
      emailVerified: true,
      profile: { email: 'v@x.com', username: 'v@x.com' },
    })
    for (let i = 0; i < 5; i++) {
      await expect(
        auth.flows.requestEmailVerification({ channels: { email: channel }, identityId: ident.id }),
      ).resolves.toEqual({ ok: true })
    }
    expect(channel.outbox).toHaveLength(0)
    expect(await adapter.credentials.listByIdentity(ident.id, 'recovery', {})).toEqual([])
  })

  it('F26 - verification writes the column through the facet and answers with the verified row', async () => {
    const { auth } = build()
    const channel = new AuthTestChannel()
    const ident = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a@x.com' } })
    await auth.flows.requestEmailVerification({ channels: { email: channel }, identityId: ident.id })
    const out = await auth.flows.completeEmailVerification({ token: tokenFrom(channel) })
    expect(out.identity.emailVerified).toBe(true)
    expect((await auth.identities.getById(ident.id))?.emailVerified).toBe(true)
  })

  it('F11 - a profile write landing mid-verification is absorbed, not surfaced', async () => {
    const { adapter, auth } = build()
    const channel = new AuthTestChannel()
    const ident = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a@x.com' } })
    await auth.flows.requestEmailVerification({ channels: { email: channel }, identityId: ident.id })

    // Bump the row's version between the facet's read and its write, exactly
    // once - the shape of a concurrent profile update. The token is already
    // spent by then, so an unhandled AUTH_STALE_WRITE would strand the user.
    const store = adapter.identities
    const original = store.update.bind(store)
    let raced = false
    store.update = async (id, patch, expectedVersion) => {
      if (!raced && 'emailVerified' in patch) {
        raced = true
        const cur = await store.findById(id)
        if (cur) await original(id, { profile: { ...cur.profile, touched: true } }, cur.version)
      }
      return original(id, patch, expectedVersion)
    }
    try {
      const out = await auth.flows.completeEmailVerification({ token: tokenFrom(channel) })
      expect(raced).toBe(true)
      expect(out.identity.emailVerified).toBe(true)
    } finally {
      store.update = original
    }
  })
})

// --- password reset ----------------------------------------------------------

describe('F2 / F6 / F7 / F28 - password reset', () => {
  let auth: AuthEngine<MyProfile>
  let adapter: MemoryAdapter<MyProfile>
  let channel: AuthTestChannel
  let identityId: string

  const request = () =>
    auth.flows.requestPasswordReset({
      channels: { email: channel },
      findIdentityByEmail: (email) => auth.identities.getByEmail(email),
      input: { email: 'a@x.com' },
    })

  beforeEach(async () => {
    ;({ adapter, auth } = build())
    channel = new AuthTestChannel()
    const ident = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a@x.com' } })
    identityId = ident.id
    await auth.passwords.set(identityId, 'old-password-9', adapter.credentials)
  })

  it('F2 - the reset row carries a purpose and no address', async () => {
    await request()
    const rows = await adapter.credentials.listByIdentity(identityId, 'recovery', {})
    expect(rows).toHaveLength(1)
    expect(rows[0]?.metadata).toEqual({ purpose: 'password-reset' })
  })

  it('F7 - a failing session sweep leaves the old password in place', async () => {
    await request()
    const token = tokenFrom(channel)
    const sessions = auth.flows.deps.sessions
    const original = sessions.revokeAllForIdentity.bind(sessions)
    sessions.revokeAllForIdentity = async () => {
      throw new Error('store is down')
    }
    try {
      await expect(auth.flows.completePasswordReset({ newPassword: 'new-password-9', token })).rejects.toThrow(
        'store is down',
      )
    } finally {
      sessions.revokeAllForIdentity = original
    }
    // The old password still verifies: the write never happened, so nobody is
    // holding a live session under a password the account holder just set.
    expect((await auth.passwords.verify(identityId, 'old-password-9', adapter.credentials)).ok).toBe(true)
  })

  it('F28 - a stepped-up session belonging to someone else does not satisfy the gate', async () => {
    await enrollTotp(auth, identityId, 'a@x.com')
    await request()
    const token = tokenFrom(channel)

    const attacker = await auth.identities.create({ profile: { email: 'e@x.com', username: 'e@x.com' } })
    const theirs = await auth.sessions.create({
      aal: 2,
      factors: [
        { completedAt: new Date(), method: 'password' },
        { completedAt: new Date(), method: 'totp' },
      ],
      identityId: attacker.id,
      kind: 'user',
    })

    await expect(
      auth.flows.completePasswordReset({ currentSid: theirs.sid, newPassword: 'new-password-9', token }),
    ).rejects.toMatchObject({ code: 'AUTH_RECOVERY_REQUIRES_MFA' })
    expect((await auth.passwords.verify(identityId, 'old-password-9', adapter.credentials)).ok).toBe(true)
  })

  it('F6 - grinding the MFA gate runs out of attempts and burns the token', async () => {
    const limit = 3
    ;({ adapter, auth } = build({ limit }))
    channel = new AuthTestChannel()
    const ident = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a@x.com' } })
    identityId = ident.id
    await auth.passwords.set(identityId, 'old-password-9', adapter.credentials)
    await enrollTotp(auth, identityId, 'a@x.com')
    await request()
    const token = tokenFrom(channel)

    let sawRateLimit = false
    for (let i = 0; i < limit + 2; i++) {
      const err = await auth.flows
        .completePasswordReset({ newPassword: 'new-password-9', token })
        .then(() => null)
        .catch((e: { code?: string }) => e)
      if (err?.code === 'AUTH_RATE_LIMITED') {
        sawRateLimit = true
        break
      }
      expect(err?.code).toBe('AUTH_RECOVERY_REQUIRES_MFA')
    }
    expect(sawRateLimit).toBe(true)
    // Spent. Even a caller who now steps up correctly gets nothing. Filtered by
    // purpose because `recovery` is also where MFA backup codes live.
    const rows = await adapter.credentials.listByIdentity(identityId, 'recovery', {})
    expect(rows.filter((r) => getCredentialPurpose(r) === 'password-reset')).toEqual([])
  })
})
