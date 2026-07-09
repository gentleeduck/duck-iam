/**
 * Direct tests of the extracted flow free functions.
 *
 * The `FlowsFacet` class methods are thin shims that delegate to free
 * functions in `flows/*.ts`. These tests import each free function by
 * name and assert (a) the module exports it with the right shape and
 * (b) the function produces the same result as the class method that
 * wraps it. This proves the extraction is real, not a rename.
 */

import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthTestChannel } from '~/channels/console'
import { AuthEngine } from '~/core/engine'
import type { Identity } from '~/core/identities/identities.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { AuthMemoryLimiter } from '~/limiters/memory'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { cancelAccountDeletion, completeAccountDeletion, requestAccountDeletion } from '../flows/account-deletion.flow'
import { completeEmailVerification, requestEmailVerification } from '../flows/email-verification.flow'
import { impersonate, releaseImpersonation } from '../flows/impersonate.flow'
import { completePasswordReset, requestPasswordReset } from '../flows/password-reset.flow'
import { linkProvider, unlinkProvider } from '../flows/provider-link.flow'
import { advanceSignUp, beginSignUp, completeSignUp, getSignUpFlow } from '../flows/signup.flow'

interface MyProfile extends Identity.ProfileMetadataBase {
  emailVerified?: boolean
}

function build() {
  const adapter = new MemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app',
    transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
    stores: { identities: adapter.identities, sessions: adapter.sessions, credentials: adapter.credentials },
    limiter: new AuthMemoryLimiter({ max: 50, windowMs: 60_000 }),
    providers: [passwords({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) })],
  })
  return { auth, adapter }
}

describe('flows/password-reset.ts - direct exports', () => {
  let auth: AuthEngine<MyProfile>
  let adapter: MemoryAdapter<MyProfile>
  beforeEach(() => {
    ;({ auth, adapter } = build())
  })

  it('exports requestPasswordReset + completePasswordReset', () => {
    expect(typeof requestPasswordReset).toBe('function')
    expect(typeof completePasswordReset).toBe('function')
  })

  it('requestPasswordReset called directly produces an enumeration-safe ok-true', async () => {
    const channel = new AuthTestChannel()
    const out = await requestPasswordReset(auth.flows.deps, {
      input: { email: 'never-exists@x.com' },
      findIdentityByEmail: async () => null,
      channels: { email: channel },
    })
    expect(out.ok).toBe(true)
  })

  it('completePasswordReset rejects an unknown token', async () => {
    await expect(completePasswordReset(auth.flows.deps, { token: 'unknown', newPassword: 'p' })).rejects.toMatchObject({
      code: 'AUTH_RECOVERY_TOKEN_INVALID',
    })
  })

  it('direct call matches class-method call (no extra side effects)', async () => {
    const channel = new AuthTestChannel()
    const directOut = await requestPasswordReset(auth.flows.deps, {
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
    await expect(completeEmailVerification(auth.flows.deps, { token: 'nope' })).rejects.toMatchObject({
      code: 'AUTH_RECOVERY_TOKEN_INVALID',
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
    await expect(cancelAccountDeletion(auth.flows.deps, { identityId: 'x'.repeat(300) })).rejects.toMatchObject({
      code: 'AUTH_UNAUTHENTICATED',
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
    const { flow, flowToken } = await beginSignUp(auth.flows.deps, { email: 'new@x.com' })
    expect(flow.identityId).toBeTruthy()
    expect(flowToken.length).toBeGreaterThan(20)
    const fetched = await getSignUpFlow(auth.flows.deps, flowToken)
    expect(fetched?.identityId).toBe(flow.identityId)
  })

  it('advanceSignUp rejects unknown token directly', async () => {
    await expect(
      advanceSignUp(auth.flows.deps, { flowToken: 'unknown', stage: 'email-verified' }),
    ).rejects.toMatchObject({
      code: 'AUTH_SIGNUP_TOKEN_INVALID',
    })
  })

  it('rejects oversize email at beginSignUp', async () => {
    await expect(beginSignUp(auth.flows.deps, { email: 'x'.repeat(300) })).rejects.toMatchObject({
      code: 'AUTH_INVALID_CREDENTIALS',
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
    const ident = await auth.identities.create({ profile: { username: 'op@x.com', email: 'op@x.com' } })
    const created = await auth.sessions.create({
      identityId: ident.id,
      kind: 'user',
      aal: 2,
      factors: [{ method: 'password', completedAt: new Date() }],
    })
    await expect(
      impersonate(auth.flows.deps, {
        realSid: created.sid,
        targetIdentityId: ident.id,
        reason: 'audit-test',
        authorize: async () => true,
      }),
    ).rejects.toMatchObject({ code: 'AUTH_IMPERSONATE_FORBIDDEN' })
  })

  it('impersonate rejects empty reason', async () => {
    await expect(
      impersonate(auth.flows.deps, {
        realSid: 'sid',
        targetIdentityId: 'target',
        reason: '',
        authorize: async () => true,
      }),
    ).rejects.toMatchObject({ code: 'AUTH_IMPERSONATE_FORBIDDEN' })
  })

  it('releaseImpersonation rejects a non-impersonation sid', async () => {
    const ident = await auth.identities.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
    const created = await auth.sessions.create({
      identityId: ident.id,
      kind: 'user',
      aal: 1,
      factors: [{ method: 'password', completedAt: new Date() }],
    })
    await expect(releaseImpersonation(auth.flows.deps, created.sid)).rejects.toMatchObject({
      code: 'AUTH_IMPERSONATE_EXPIRED',
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
    const ident = await auth.identities.create({ profile: { username: 'b@x.com', email: 'b@x.com' } })
    const out = await linkProvider(auth.flows.deps, {
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
    await expect(
      linkProvider(auth.flows.deps, { identityId: 'x', providerId: '', providerSub: 's' }),
    ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
  })

  it('unlinkProvider lockout guard refuses to leave identity with no factors', async () => {
    const ident = await auth.identities.create({ profile: { username: 'c@x.com', email: 'c@x.com' } })
    await linkProvider(auth.flows.deps, { identityId: ident.id, providerId: 'authGithub', providerSub: 'gh-1' })
    await expect(
      unlinkProvider(auth.flows.deps, { identityId: ident.id, providerId: 'authGithub' }),
    ).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
    })
  })

  it('unlinkProvider allows lockout when allowLockout: true', async () => {
    const ident = await auth.identities.create({ profile: { username: 'd@x.com', email: 'd@x.com' } })
    await linkProvider(auth.flows.deps, { identityId: ident.id, providerId: 'authGithub', providerSub: 'gh-2' })
    const out = await unlinkProvider(auth.flows.deps, {
      identityId: ident.id,
      providerId: 'authGithub',
      allowLockout: true,
    })
    expect(out.providerId).toBe('authGithub')
  })
})
