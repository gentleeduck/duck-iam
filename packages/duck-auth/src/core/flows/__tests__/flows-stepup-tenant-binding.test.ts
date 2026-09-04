/**
 * The F28 shape, found by sweeping for it: a gate that resolves its scope from
 * one input and acts on another, with nothing binding the two.
 *
 * `completeStepUp` took an optional `tenantId` that scoped the MFA credential
 * read, while the session it was stepping up carried a tenant of its own -
 * and the default when it was omitted was `{}`, an unscoped read. So a factor
 * enrolled in tenant B satisfied a step-up for a session in tenant A: a tenant
 * that had never seen a factor for that identity and whose `hasTotp` therefore
 * never demanded one. Credentials are tenant-scoped; identities are not.
 *
 * The parameter is gone. The factor is read in the session's tenant, and there
 * is no second input left to disagree with it.
 */

import { describe, expect, it } from 'vitest'
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

function buildAuth() {
  const adapter = new MemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app.example.com',
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    limiter: new MemoryLimiter({ max: 20, windowMs: 60_000 }),
    providers: [passwords({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) }), mfaProvider()],
  })
  return { adapter, auth }
}

/**
 * Enrol a confirmed TOTP factor for `identityId` inside `tenantId`, and hand
 * back a code for the *next* step - the enrolment code is consumed, and
 * replaying it would fail for a reason that has nothing to do with tenants.
 */
async function enrolTotp(
  auth: AuthEngine<MyProfile>,
  identityId: string,
  tenantId?: string,
): Promise<{ nextCode: string }> {
  const tenant = tenantId === undefined ? {} : { tenantId }
  const challenge = await auth.mfa.beginTotpEnrollment(identityId, 'a@x.com', tenant)
  const step = Math.floor(Date.now() / 1000 / 30)
  await auth.mfa.confirmTotpEnrollment(identityId, totpAt(challenge.secret, step), tenant)
  return { nextCode: totpAt(challenge.secret, step + 1) }
}

describe('completeStepUp binds the factor to the session it is stepping up', () => {
  it('a factor enrolled in another tenant does not satisfy a step-up in this one', async () => {
    const { auth } = buildAuth()
    const ident = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a@x.com' } })
    // Enrolled in tenant B only. Tenant A has never seen a factor for this id.
    const { nextCode } = await enrolTotp(auth, ident.id, 'tenant-b')
    expect(await auth.mfa.hasTotp(ident.id, { tenantId: 'tenant-a' })).toBe(false)

    const { sid } = await auth.sessions.create({
      aal: 1,
      factors: [{ completedAt: new Date(), method: 'password' }],
      identityId: ident.id,
      kind: 'user',
      tenantId: 'tenant-a',
    })

    await expect(
      auth.flows.completeStepUp({
        code: nextCode,
        currentSid: sid,
        method: 'totp',
      }),
    ).rejects.toMatchObject({ code: 'AUTH_INVALID_CREDENTIALS' })
  })

  it('the factor enrolled in the session own tenant does satisfy it', async () => {
    const { auth } = buildAuth()
    const ident = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a@x.com' } })
    const { nextCode } = await enrolTotp(auth, ident.id, 'tenant-a')
    const { sid } = await auth.sessions.create({
      aal: 1,
      factors: [{ completedAt: new Date(), method: 'password' }],
      identityId: ident.id,
      kind: 'user',
      tenantId: 'tenant-a',
    })

    const stepped = await auth.flows.completeStepUp({
      code: nextCode,
      currentSid: sid,
      method: 'totp',
    })
    expect(stepped.session.aal).toBe(2)
    // And it stays in the tenant it was in.
    expect(stepped.session.tenantId).toBe('tenant-a')
  })

  it('a backup code from another tenant does not satisfy it either', async () => {
    const { auth } = buildAuth()
    const ident = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a@x.com' } })
    await enrolTotp(auth, ident.id, 'tenant-b')
    const codes = await auth.mfa.regenerateBackupCodes(ident.id, { tenantId: 'tenant-b' })

    const { sid } = await auth.sessions.create({
      aal: 1,
      factors: [{ completedAt: new Date(), method: 'password' }],
      identityId: ident.id,
      kind: 'user',
      tenantId: 'tenant-a',
    })

    await expect(
      auth.flows.completeStepUp({ code: codes[0]!, currentSid: sid, method: 'backup-code' }),
    ).rejects.toMatchObject({ code: 'AUTH_INVALID_CREDENTIALS' })
  })

  it('a global session reads unscoped, the way every other credential read does', async () => {
    const { auth } = buildAuth()
    const ident = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a@x.com' } })
    const { nextCode } = await enrolTotp(auth, ident.id)
    const { sid } = await auth.sessions.create({
      aal: 1,
      factors: [{ completedAt: new Date(), method: 'password' }],
      identityId: ident.id,
      kind: 'user',
    })

    const stepped = await auth.flows.completeStepUp({
      code: nextCode,
      currentSid: sid,
      method: 'totp',
    })
    expect(stepped.session.aal).toBe(2)
    expect(stepped.session.tenantId).toBeNull()
  })

  it('there is no tenantId parameter left to disagree with the session', async () => {
    // A JS host passing one is simply ignored - the shape that used to be the
    // bug no longer exists in the signature.
    const { auth } = buildAuth()
    const ident = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a@x.com' } })
    const { nextCode } = await enrolTotp(auth, ident.id, 'tenant-b')
    const { sid } = await auth.sessions.create({
      aal: 1,
      factors: [{ completedAt: new Date(), method: 'password' }],
      identityId: ident.id,
      kind: 'user',
      tenantId: 'tenant-a',
    })
    const input = {
      code: nextCode,
      currentSid: sid,
      method: 'totp',
      tenantId: 'tenant-b',
    } as unknown as Parameters<typeof auth.flows.completeStepUp>[0]

    await expect(auth.flows.completeStepUp(input)).rejects.toMatchObject({ code: 'AUTH_INVALID_CREDENTIALS' })
  })
})
