/** A call naming no tenant reaches only the rows with no tenant, so the engine's own work across an account names
 *  every tenant: ending its sessions, sweeping an unproven address, counting its ways in. */
import { describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { orNull } from '~/core/answer'
import { AuthEngine } from '~/core/engine'
import type { Identities } from '~/core/identities/identities.types'
import type { Provider } from '~/core/provider/provider.types'
import type { TenantContext } from '~/core/tenant/tenant.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { apiKeyProvider } from '~/providers/api-key'
import { magicLink } from '~/providers/magic-link'
import { mfaProvider, totpAt } from '~/providers/mfa'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { authTestDataAtRest, authTestDeliver } from '~/test'

interface P extends Identities.ProfileMetadataBase {
  email: string
}

const PASSWORD = 'correct-horse-battery'
const step = (): number => Math.floor(Date.now() / 1000 / 30)
const oauth = () => [{ completedAt: new Date(), method: 'oauth' as const }]

function build(session: { maxSessionsPerIdentity?: number } = {}) {
  const adapter = new MemoryAdapter<P>()
  const mail = authTestDeliver()
  // Answers whatever the test last set, as any provider in the open list may.
  let emitted: Provider.InternalIntent[] = []
  const custom: Provider.Me<unknown, unknown, P> = {
    begin: async () => [],
    complete: async () => emitted,
    id: 'custom',
    kind: 'custom',
  }
  const auth = new AuthEngine<P>({
    baseUrl: 'https://app.example.com',
    deliver: mail.deliver,
    limiter: new MemoryLimiter({ max: 50, windowMs: 60_000 }),
    providers: [
      passwords({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) }),
      mfaProvider({ dataAtRest: authTestDataAtRest() }),
      magicLink<P>({
        deliver: mail.deliver,
        findIdentityByEmail: (email) => orNull(adapter.identities.find({ email })),
      }),
      apiKeyProvider(),
      custom,
    ],
    session,
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid' }),
  })
  const t = {
    adapter,
    auth,
    async identity(email: string, emailVerified = true): Promise<string> {
      return (await auth.identities.create({ emailVerified, profile: { email, username: email } })).id
    },
    async session(identityId: string, tenantId: string): Promise<string> {
      return (await auth.sessions.create({ aal: 1, factors: oauth(), identityId, kind: 'user', tenantId })).sid
    },
    live: async (sid: string): Promise<boolean> => (await auth.sessions.getBySid(sid).orNull()) !== null,
    async totp(id: string, ctx: TenantContext = {}): Promise<string> {
      const { secret } = await auth.mfa.beginTotpEnrollment(id, id, null, ctx)
      await auth.mfa.confirmTotpEnrollment(id, totpAt(secret, step()), null, ctx)
      return secret
    },
    /** Signs in through the custom provider, which answers `intents`. */
    custom(intents: Provider.InternalIntent[]) {
      emitted = intents
      return auth.flows.signIn({ input: {}, providerId: 'custom' })
    },
    /** The token of the last message of `kind`. */
    token(kind: string): string {
      const sent = mail.outbox.filter((m) => m.kind === kind).at(-1)
      return sent ? (new URL(sent.vars.url).searchParams.get('token') ?? '') : ''
    },
  }
  return t
}

describe("the engine's work across an account's tenants", () => {
  it('caps the sessions of an identity across its tenants', async () => {
    const t = build({ maxSessionsPerIdentity: 2 })
    const id = await t.identity('a@x.com')
    const first = await t.session(id, 'a')
    await t.session(id, 'b')
    await t.session(id, 'a')

    expect(await t.live(first)).toBe(false)
  })

  it('a sign-in that ends the other sessions ends them in every tenant', async () => {
    const t = build()
    const id = await t.identity('a@x.com')
    const elsewhere = await t.session(id, 'b')

    const { sid } = await t.custom([
      { aal: 1, endOtherSessions: true, factors: oauth(), identityId: id, type: 'startSession' },
    ])

    expect(await t.live(elsewhere)).toBe(false)
    expect(await t.live(sid)).toBe(true)
  })

  it('so does the answered challenge of such a sign-in', async () => {
    const t = build()
    const id = await t.identity('a@x.com')
    const secret = await t.totp(id)
    const elsewhere = await t.session(id, 'b')
    const { challenge } = await t.custom([
      { aal: 1, endOtherSessions: true, factors: oauth(), identityId: id, type: 'startSession' },
    ])

    await t.auth.flows.completeStepUp({
      challenge: challenge?.token ?? '',
      code: totpAt(secret, step() + 1),
      method: 'totp',
    })

    expect(await t.live(elsewhere)).toBe(false)
  })

  it('a completed account deletion ends the sessions of every tenant', async () => {
    const t = build()
    const id = await t.identity('a@x.com')
    const elsewhere = await t.session(id, 'b')

    await t.auth.flows.requestAccountDeletion({ identityId: id })
    await t.auth.flows.completeAccountDeletion({ token: t.token('account-deletion') })

    expect(await t.live(elsewhere)).toBe(false)
  })

  it('a password reset without a session ends the sessions of every tenant', async () => {
    const t = build()
    const id = await t.identity('a@x.com')
    await t.auth.passwords.set(id, PASSWORD, t.adapter.credentials, null)
    const elsewhere = await t.session(id, 'b')

    await t.auth.flows.requestPasswordReset({
      findIdentityByEmail: (email) => orNull(t.auth.identities.getByEmail(email)),
      input: { email: 'a@x.com' },
    })
    await t.auth.flows.completePasswordReset({ newPassword: 'new-password-9', token: t.token('password-reset') })

    expect(await t.live(elsewhere)).toBe(false)
  })

  it('revoking an API key ends the sessions it opened, in every tenant', async () => {
    const t = build()
    const id = await t.identity('a@x.com')
    const { key } = await t.auth.apiKeys.create(id, { name: 'ci', scopes: [], session: null }, { tenantId: 'a' })
    const factors = [{ completedAt: new Date(), method: 'api-key' as const }]
    const { sid } = await t.auth.sessions.create({ aal: 1, factors, identityId: id, kind: 'apikey', tenantId: 'a' })

    await t.auth.apiKeys.revoke(key.id, { tenantId: 'a' })

    expect(await t.live(sid)).toBe(false)
  })

  it('reclaiming an abandoned sign-up ends its flow and its sessions in every tenant', async () => {
    const t = build()
    const begun = await t.auth.flows.beginSignUp({ email: 'a@x.com', required: ['terms-accepted'], tenantId: 'a' })
    const squatter = await t.session(begun.flow.identityId, 'b')

    await t.auth.flows.beginSignUp({ email: 'a@x.com' })

    await expect(
      t.auth.flows.advanceSignUp({ flowToken: begun.flowToken, stage: 'terms-accepted', tenantId: 'a' }),
    ).rejects.toMatchObject({ code: 'AUTH_SIGNUP_TOKEN_INVALID' })
    expect(await t.live(squatter)).toBe(false)
  })

  it("an unproven address's first link ends and reports the sessions of every tenant before it marks the address", async () => {
    const t = build()
    const id = await t.identity('a@x.com', false)
    const squatter = await t.session(id, 'b')
    const squatterId = (await t.auth.sessions.getBySid(squatter)).id
    const revoked: string[] = []
    t.auth.events.on('session.revoked', (p) => {
      revoked.push(p.sessionId)
    })
    await t.auth.flows.beginProvider('magic-link', { email: 'a@x.com' })
    // Stops the sweep at the write that marks the address, which a crash there would.
    vi.spyOn(t.adapter.identities, 'update').mockRejectedValueOnce(new Error('crashed'))

    await expect(
      t.auth.flows.signIn({ input: { token: t.token('magic-link') }, providerId: 'magic-link' }),
    ).rejects.toThrow('crashed')

    expect(await t.live(squatter)).toBe(false)
    expect(revoked).toEqual([squatterId])
  })

  it("an unproven address's first link revokes what was enrolled on it in every tenant", async () => {
    const t = build()
    const id = await t.identity('a@x.com', false)
    await t.auth.passwords.set(id, PASSWORD, t.adapter.credentials, null, { tenantId: 'b' })
    await t.auth.flows.beginProvider('magic-link', { email: 'a@x.com' })

    await t.auth.flows.signIn({ input: { token: t.token('magic-link') }, providerId: 'magic-link' })

    expect(await t.auth.passwords.verify(id, PASSWORD, t.adapter.credentials, { tenantId: 'b' })).toEqual({
      ok: false,
    })
  })

  it('unlinking a provider counts a password the account holds in a tenant as a way in', async () => {
    const t = build()
    const id = await t.identity('a@x.com')
    await t.adapter.identities.link(id, { providerId: 'oauth:github', providerSub: '583231', tenantId: null })
    await t.auth.passwords.set(id, PASSWORD, t.adapter.credentials, null, { tenantId: 'a' })

    await expect(t.auth.identities.unlink(id, 'oauth:github', null)).resolves.toMatchObject({ providers: [] })
  })
})

describe("a link's gate asks only the tenant the link opens", () => {
  const github = { providerId: 'oauth:github', providerSub: '583231' }

  it('refuses a link in a tenant holding a factor, and takes one with no tenant past it', async () => {
    const t = build()
    const id = await t.identity('a@x.com')
    await t.totp(id, { tenantId: 'a' })

    await expect(t.auth.identities.link(id, github, null, { tenantId: 'a' })).rejects.toMatchObject({
      code: 'AUTH_MFA_REQUIRED',
    })
    await expect(
      t.auth.flows.linkProvider({
        ...github,
        authorize: async () => true,
        identityId: id,
        session: null,
        tenantId: 'a',
      }),
    ).rejects.toMatchObject({ code: 'AUTH_MFA_REQUIRED' })
    await expect(t.auth.identities.link(id, github, null)).resolves.toMatchObject({
      providers: [{ ...github, tenantId: null }],
    })
    await expect(
      t.auth.flows.linkProvider({ ...github, authorize: async () => true, identityId: id, session: null }),
    ).resolves.toMatchObject({ providerId: github.providerId })
  })

  it('and an unlink', async () => {
    const t = build()
    const id = await t.identity('a@x.com')
    await t.adapter.identities.link(id, { ...github, tenantId: 'a' })
    await t.adapter.identities.link(id, { ...github, tenantId: null })
    await t.auth.passwords.set(id, PASSWORD, t.adapter.credentials, null)
    await t.auth.passwords.set(id, PASSWORD, t.adapter.credentials, null, { tenantId: 'a' })
    await t.totp(id, { tenantId: 'a' })

    await expect(t.auth.identities.unlink(id, github.providerId, null, { tenantId: 'a' })).rejects.toMatchObject({
      code: 'AUTH_MFA_REQUIRED',
    })
    await expect(
      t.auth.flows.unlinkProvider({ identityId: id, providerId: github.providerId, session: null, tenantId: 'a' }),
    ).rejects.toMatchObject({ code: 'AUTH_MFA_REQUIRED' })
    await expect(
      t.auth.flows.unlinkProvider({ identityId: id, providerId: github.providerId, session: null }),
    ).resolves.toMatchObject({ identity: { providers: [{ ...github, tenantId: 'a' }] } })
    await t.adapter.identities.link(id, { ...github, tenantId: null })
    await expect(t.auth.identities.unlink(id, github.providerId, null)).resolves.toMatchObject({
      providers: [{ ...github, tenantId: 'a' }],
    })
  })
})

describe('a gate in front of a write the account holds in every tenant', () => {
  it("asks for the key's tenant's factors to mint a key in it, whatever context the call names", async () => {
    const t = build()
    const id = await t.identity('a@x.com')
    await t.totp(id, { tenantId: 'a' })

    await expect(
      t.auth.apiKeys.create(id, { name: 'ci', scopes: [], session: null, tenantId: 'a' }),
    ).rejects.toMatchObject({ code: 'AUTH_MFA_REQUIRED' })
  })
})
