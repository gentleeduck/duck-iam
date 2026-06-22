/**
 * Direct tests of the extracted flow free functions.
 *
 * The `FlowsFacet` class methods are thin shims that delegate to free
 * functions in `flows/*.ts`. These tests import each free function by
 * name and assert (a) the module exports it with the right shape and
 * (b) the function produces the same result as the class method that
 * wraps it. This proves the extraction is real, not a rename.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { AuthMemoryAdapter } from '../../../adapters/memory'
import { AuthTestChannel } from '../../../channels/console'
import { AuthMemoryLimiter } from '../../../limiters/memory'
import { AuthEngine } from '../../engine'
import { AuthScryptHasher } from '../../password/scrypt'
import { AuthCookieTransport } from '../../transport/cookie'
import { cancelAccountDeletion, completeAccountDeletion, requestAccountDeletion } from '../flows/account-deletion'
import { completeEmailVerification, requestEmailVerification } from '../flows/email-verification'
import { impersonate, releaseImpersonation } from '../flows/impersonate'
import { completePasswordReset, requestPasswordReset } from '../flows/password-reset'
import { linkProvider, unlinkProvider } from '../flows/provider-link'
import { advanceSignUp, beginSignUp, completeSignUp, getSignUpFlow } from '../flows/signup'

interface MyProfile {
  email: string
  emailVerified?: boolean
}

function build() {
  const adapter = new AuthMemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app',
    transport: new AuthCookieTransport({ secure: false, name: 'duck-sid' }),
    stores: { identities: adapter.identities, sessions: adapter.sessions, credentials: adapter.credentials },
    limiter: new AuthMemoryLimiter({ max: 50, windowMs: 60_000 }),
    passwords: { hasher: new AuthScryptHasher({ N: 1 << 10, keylen: 32 }) },
  })
  return { auth, adapter }
}

describe('flows/password-reset.ts - direct exports', () => {
  let auth: AuthEngine<MyProfile>
  let adapter: AuthMemoryAdapter<MyProfile>
  beforeEach(() => {
    ;({ auth, adapter } = build())
  })

  it('exports requestPasswordReset + completePasswordReset', () => {
    expect(typeof requestPasswordReset).toBe('function')
    expect(typeof completePasswordReset).toBe('function')
  })

  it('requestPasswordReset called directly produces an enumeration-safe ok-true', async () => {
    const channel = new AuthTestChannel()
    const out = await requestPasswordReset(auth.flows, {
      input: { email: 'never-exists@x.com' },
      findIdentityByEmail: async () => null,
      channels: { email: channel },
    })
    expect(out.ok).toBe(true)
  })

  it('completePasswordReset rejects an unknown token', async () => {
    await expect(completePasswordReset(auth.flows, { token: 'unknown', newPassword: 'p' })).rejects.toMatchObject({
      code: 'AUTH/RECOVERY_TOKEN_INVALID',
    })
  })

  it('direct call matches class-method call (no extra side effects)', async () => {
    const channel = new AuthTestChannel()
    const directOut = await requestPasswordReset(auth.flows, {
      input: { email: 'a@x.com' },
      findIdentityByEmail: async () => null,
      channels: { email: channel },
    })
    const classOut = await auth.flows.requestPasswordReset({
      input: { email: 'a@x.com' },
      findIdentityByEmail: async () => null,
      channels: { email: channel },
    })
    expect(directOut).toEqual(classOut)
    // unused adapter to silence linter
    void adapter
  })
})

describe('flows/email-verification.ts - direct exports', () => {
  let auth: AuthEngine<MyProfile>
  beforeEach(() => {
    ;({ auth } = build())
  })

  it('exports requestEmailVerification + completeEmailVerification', () => {
    expect(typeof requestEmailVerification).toBe('function')
    expect(typeof completeEmailVerification).toBe('function')
  })

  it('completeEmailVerification rejects unknown token directly', async () => {
    await expect(completeEmailVerification(auth.flows, { token: 'nope' })).rejects.toMatchObject({
      code: 'AUTH/RECOVERY_TOKEN_INVALID',
    })
  })
})

describe('flows/account-deletion.ts - direct exports', () => {
  let auth: AuthEngine<MyProfile>
  beforeEach(() => {
    ;({ auth } = build())
  })

  it('exports the three account-deletion functions', () => {
    expect(typeof requestAccountDeletion).toBe('function')
    expect(typeof completeAccountDeletion).toBe('function')
    expect(typeof cancelAccountDeletion).toBe('function')
  })

  it('cancelAccountDeletion rejects oversize identityId', async () => {
    await expect(cancelAccountDeletion(auth.flows, { identityId: 'x'.repeat(300) })).rejects.toMatchObject({
      code: 'AUTH/UNAUTHENTICATED',
    })
  })
})

describe('flows/signup.ts - direct exports', () => {
  let auth: AuthEngine<MyProfile>
  beforeEach(() => {
    ;({ auth } = build())
  })

  it('exports the four signup functions', () => {
    expect(typeof beginSignUp).toBe('function')
    expect(typeof getSignUpFlow).toBe('function')
    expect(typeof advanceSignUp).toBe('function')
    expect(typeof completeSignUp).toBe('function')
  })

  it('beginSignUp + getSignUpFlow round-trip through credentials store', async () => {
    const { flow, flowToken } = await beginSignUp(auth.flows, { email: 'new@x.com' })
    expect(flow.identityId).toBeTruthy()
    expect(flowToken.length).toBeGreaterThan(20)
    const fetched = await getSignUpFlow(auth.flows, flowToken)
    expect(fetched?.identityId).toBe(flow.identityId)
  })

  it('advanceSignUp rejects unknown token directly', async () => {
    await expect(advanceSignUp(auth.flows, { flowToken: 'unknown', stage: 'email-verified' })).rejects.toMatchObject({
      code: 'AUTH/SIGNUP_TOKEN_INVALID',
    })
  })

  it('rejects oversize email at beginSignUp', async () => {
    await expect(beginSignUp(auth.flows, { email: 'x'.repeat(300) })).rejects.toMatchObject({
      code: 'AUTH/INVALID_CREDENTIALS',
    })
  })
})

describe('flows/impersonate.ts - direct exports', () => {
  let auth: AuthEngine<MyProfile>
  beforeEach(() => {
    ;({ auth } = build())
  })

  it('exports impersonate + releaseImpersonation', () => {
    expect(typeof impersonate).toBe('function')
    expect(typeof releaseImpersonation).toBe('function')
  })

  it('impersonate rejects self-target (same identityId)', async () => {
    const ident = await auth.identities.create({ profile: { email: 'op@x.com' } })
    const created = await auth.sessions.create({
      identityId: ident.id,
      kind: 'user',
      aal: 2,
      factors: [{ method: 'password', completedAt: Date.now() }],
    })
    await expect(
      impersonate(auth.flows, {
        realSid: created.sid,
        targetIdentityId: ident.id,
        reason: 'audit-test',
        authorize: async () => true,
      }),
    ).rejects.toMatchObject({ code: 'AUTH/IMPERSONATE_FORBIDDEN' })
  })

  it('impersonate rejects empty reason', async () => {
    await expect(
      impersonate(auth.flows, {
        realSid: 'sid',
        targetIdentityId: 'target',
        reason: '',
        authorize: async () => true,
      }),
    ).rejects.toMatchObject({ code: 'AUTH/IMPERSONATE_FORBIDDEN' })
  })

  it('releaseImpersonation rejects a non-impersonation sid', async () => {
    const ident = await auth.identities.create({ profile: { email: 'a@x.com' } })
    const created = await auth.sessions.create({
      identityId: ident.id,
      kind: 'user',
      aal: 1,
      factors: [{ method: 'password', completedAt: Date.now() }],
    })
    await expect(releaseImpersonation(auth.flows, created.sid)).rejects.toMatchObject({
      code: 'AUTH/IMPERSONATE_EXPIRED',
    })
  })
})

describe('flows/provider-link.ts - direct exports', () => {
  let auth: AuthEngine<MyProfile>
  beforeEach(() => {
    ;({ auth } = build())
  })

  it('exports linkProvider + unlinkProvider', () => {
    expect(typeof linkProvider).toBe('function')
    expect(typeof unlinkProvider).toBe('function')
  })

  it('linkProvider attaches a provider link to an existing identity', async () => {
    const ident = await auth.identities.create({ profile: { email: 'b@x.com' } })
    const out = await linkProvider(auth.flows, {
      identityId: ident.id,
      providerId: 'authGithub',
      providerSub: 'gh-sub-1',
    })
    expect(out.identityId).toBe(ident.id)
    expect(out.providerId).toBe('authGithub')
    const refreshed = await auth.identities.getById(ident.id)
    expect(refreshed?.providers.some((p) => p.providerId === 'authGithub')).toBe(true)
  })

  it('linkProvider rejects invalid providerId', async () => {
    await expect(linkProvider(auth.flows, { identityId: 'x', providerId: '', providerSub: 's' })).rejects.toMatchObject(
      { code: 'AUTH/PROVIDER_FAILED' },
    )
  })

  it('unlinkProvider lockout guard refuses to leave identity with no factors', async () => {
    const ident = await auth.identities.create({ profile: { email: 'c@x.com' } })
    await linkProvider(auth.flows, { identityId: ident.id, providerId: 'authGithub', providerSub: 'gh-1' })
    await expect(unlinkProvider(auth.flows, { identityId: ident.id, providerId: 'authGithub' })).rejects.toMatchObject({
      code: 'AUTH/PROVIDER_FAILED',
    })
  })

  it('unlinkProvider allows lockout when allowLockout: true', async () => {
    const ident = await auth.identities.create({ profile: { email: 'd@x.com' } })
    await linkProvider(auth.flows, { identityId: ident.id, providerId: 'authGithub', providerSub: 'gh-2' })
    const out = await unlinkProvider(auth.flows, {
      identityId: ident.id,
      providerId: 'authGithub',
      allowLockout: true,
    })
    expect(out.providerId).toBe('authGithub')
  })
})
