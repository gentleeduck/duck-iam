/** D1 - `beginSignUp` wrote a real identity row for any address, unrated. */

import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { getCredentialPurpose } from '~/core/credentials/credentials'
import { AuthEngine } from '~/core/engine'
import type { Identities } from '~/core/identities/identities.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { mfaProvider, totpAt } from '~/providers/mfa'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { authTestDeliver } from '~/test'

interface MyProfile extends Identities.ProfileMetadataBase {
  email: string
}

function build() {
  const adapter = new MemoryAdapter<MyProfile>()
  const channel = authTestDeliver()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app',
    deliver: channel.deliver,
    limiter: new MemoryLimiter({ max: 50, windowMs: 60_000 }),
    providers: [passwords({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) }), mfaProvider()],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
  return { adapter, auth, channel }
}

describe('D1 - a squat is reclaimed', () => {
  let auth: AuthEngine<MyProfile>
  let adapter: MemoryAdapter<MyProfile>

  beforeEach(() => {
    ;({ adapter, auth } = build())
  })

  it('the real owner gets the row the attacker parked on', async () => {
    const squat = await auth.flows.beginSignUp({ email: 'victim@corp.com' })
    const parked = await auth.identities.getByEmail('victim@corp.com')

    // This used to throw AUTH_EMAIL_TAKEN and there was nothing the real user
    // could do about it, ever.
    const real = await auth.flows.beginSignUp({ email: 'victim@corp.com' })

    expect(real.flow.identityId).toBe(parked?.id)
    expect(real.flowToken).not.toBe(squat.flowToken)
  })

  it("the attacker's token is dead the moment the row is reclaimed", async () => {
    const squat = await auth.flows.beginSignUp({ email: 'victim@corp.com' })
    await auth.flows.beginSignUp({ email: 'victim@corp.com' })

    // Two live tokens on one row would let whoever started first finish the
    // signup the second caller is paying for.
    await expect(auth.flows.getSignUpFlow(squat.flowToken)).rejects.toMatchObject({
      code: 'AUTH_CREDENTIAL_NOT_FOUND',
    })
    await expect(
      auth.flows.advanceSignUp({ flowToken: squat.flowToken, stage: 'email-verified' }),
    ).rejects.toMatchObject({ code: 'AUTH_SIGNUP_TOKEN_INVALID' })
  })

  it('reclaiming does not pile up rows, tokens or accounts', async () => {
    await auth.flows.beginSignUp({ email: 'victim@corp.com' })
    await auth.flows.beginSignUp({ email: 'victim@corp.com' })
    const latest = await auth.flows.beginSignUp({ email: 'victim@corp.com' })

    const rows = await adapter.credentials.listByIdentity(latest.flow.identityId, 'recovery', {})
    const live = rows.filter((r) => getCredentialPurpose(r) === 'signup-flow' && r.revokedAt === null)
    expect(live).toHaveLength(1)
  })

  it('the reclaimed profile is the new signup, not the squatter', async () => {
    await auth.flows.beginSignUp({ email: 'victim@corp.com', initialProfile: { username: 'attacker' } })
    const real = await auth.flows.beginSignUp({ email: 'victim@corp.com', initialProfile: { username: 'realuser' } })
    expect((await auth.identities.getById(real.flow.identityId)).profile.username).toBe('realuser')
  })
})

describe('D1 - an account is not a squat', () => {
  let auth: AuthEngine<MyProfile>
  let adapter: MemoryAdapter<MyProfile>
  let channel: ReturnType<typeof build>['channel']

  beforeEach(() => {
    ;({ adapter, auth, channel } = build())
  })

  it('a password makes the row untouchable, even unverified', async () => {
    // The rule that matters. `completeSignUp` mints a session for the reclaimed
    // identity, so reclaiming an account with a credential on it would hand that
    // account to whoever asked for the address next.
    const ident = await auth.identities.create({ profile: { email: 'sam@x.com', username: 'sam' } })
    await auth.passwords.set(ident.id, 'correct-horse-battery', adapter.credentials)
    expect((await auth.identities.getById(ident.id)).emailVerified).toBe(false)

    await expect(auth.flows.beginSignUp({ email: 'sam@x.com' })).rejects.toMatchObject({ code: 'AUTH_EMAIL_TAKEN' })
  })

  it('a provider link makes the row untouchable', async () => {
    const ident = await auth.identities.create({ profile: { email: 'sam@x.com', username: 'sam' } })
    await auth.flows.linkProvider({
      authorize: async () => true,
      identityId: ident.id,
      providerId: 'google',
      providerSub: 'g-1',
    })
    await expect(auth.flows.beginSignUp({ email: 'sam@x.com' })).rejects.toMatchObject({ code: 'AUTH_EMAIL_TAKEN' })
  })

  it('MFA backup codes make the row untouchable, though they carry no purpose', async () => {
    // Backup codes are `kind: 'recovery'` with `metadata: null`, so they have no
    // `purpose` to compare - the predicate has to read "not signup-flow" rather
    // than "is a password".
    const ident = await auth.identities.create({ profile: { email: 'sam@x.com', username: 'sam' } })
    const enrol = await auth.mfa.beginTotpEnrollment(ident.id, 'sam@x.com')
    await auth.mfa.confirmTotpEnrollment(ident.id, totpAt(enrol.secret, Math.floor(Date.now() / 1000 / 30)))
    await expect(auth.flows.beginSignUp({ email: 'sam@x.com' })).rejects.toMatchObject({ code: 'AUTH_EMAIL_TAKEN' })
  })

  it('a verified address makes the row untouchable even with nothing else on it', async () => {
    const ident = await auth.identities.create({ profile: { email: 'sam@x.com', username: 'sam' } })
    await auth.flows.requestEmailVerification({ identityId: ident.id })
    const url = (channel.outbox.at(-1)?.vars as { url: string }).url
    await auth.flows.completeEmailVerification({ token: new URL(url).searchParams.get('token') ?? '' })

    await expect(auth.flows.beginSignUp({ email: 'sam@x.com' })).rejects.toMatchObject({ code: 'AUTH_EMAIL_TAKEN' })
  })

  it('a credential in another tenant still counts - the check is unscoped', async () => {
    // Identities are global, credentials are not. A tenant-scoped read would call
    // an account with a password in tenant B abandoned and hand it over.
    const ident = await auth.identities.create({ profile: { email: 'sam@x.com', username: 'sam' } })
    await adapter.credentials.create(
      {
        expiresAt: null,
        identityId: ident.id,
        kind: 'password',
        lastUsedAt: null,
        metadata: null,
        revokedAt: null,
        secret: 'hash',
        tenantId: 'tenant-b',
      },
      { tenantId: 'tenant-b' },
    )
    await expect(auth.flows.beginSignUp({ email: 'sam@x.com' })).rejects.toMatchObject({ code: 'AUTH_EMAIL_TAKEN' })
  })

  it('a revoked credential does not keep a dead row locked up', async () => {
    const ident = await auth.identities.create({ profile: { email: 'sam@x.com', username: 'sam' } })
    await auth.passwords.set(ident.id, 'correct-horse-battery', adapter.credentials)
    for (const c of await adapter.credentials.listByIdentity(ident.id, null, {})) {
      await adapter.credentials.revoke(c.id, {})
    }
    const out = await auth.flows.beginSignUp({ email: 'sam@x.com' })
    expect(out.flow.identityId).toBe(ident.id)
  })
})

describe('D1 - a completed signup stops being reclaimable', () => {
  it('completeSignUp records the verification the stage claimed', async () => {
    // Without this the column stays false forever, and the reclaim rule - which
    // reads that column - would hand finished accounts to the next caller.
    const { auth } = build()
    const { flowToken } = await auth.flows.beginSignUp({ email: 'new@x.com', required: ['email-verified'] })
    await auth.flows.advanceSignUp({ flowToken, stage: 'email-verified' })
    const out = await auth.flows.completeSignUp({ flowToken })

    expect(out.session?.identityId).toBeTruthy()
    const ident = await auth.identities.getByEmail('new@x.com')
    expect(ident?.emailVerified).toBe(true)
    await expect(auth.flows.beginSignUp({ email: 'new@x.com' })).rejects.toMatchObject({ code: 'AUTH_EMAIL_TAKEN' })
  })

  it('a signup that never proved the address does not claim it was verified', async () => {
    const { auth } = build()
    const { flowToken } = await auth.flows.beginSignUp({ email: 'lax@x.com', required: [] })
    await auth.flows.completeSignUp({ flowToken })
    expect((await auth.identities.getByEmail('lax@x.com')).emailVerified).toBe(false)
  })
})
