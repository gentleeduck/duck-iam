/** An account holding anything beside the factor it signs in with gets no session from that factor alone: the
 *  sign-in stops at a challenge, and only the second factor turns it into a session. */
import { describe, expect, it, onTestFinished, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { orNull } from '~/core/answer'
import { randomToken, sha256 } from '~/core/crypto'
import { AuthEngine } from '~/core/engine'
import type { Flows } from '~/core/flows/flows.types'
import type { Identities } from '~/core/identities/identities.types'
import type { Provider } from '~/core/provider/provider.types'
import type { Sessions } from '~/core/sessions/sessions.types'
import type { TenantContext } from '~/core/tenant/tenant.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { mfaProvider, RememberMeFacet, totpAt } from '~/providers/mfa'
import {
  AuthMemoryPasskeyChallengeStore,
  beginPasskeyRegistration,
  completePasskeyRegistration,
  type Passkey,
  passkey,
} from '~/providers/passkey'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { authTestDataAtRest, authTestDeliver } from '~/test'
import { type SoftAuthenticator, softAuthenticator } from '~/test/soft-authenticator'

interface P extends Identities.ProfileMetadataBase {
  email: string
}

const RP = { expectedOrigins: 'https://app.example.com', rpID: 'app.example.com' }
const PASSWORD = 'correct-horse-battery'
const device = (): SoftAuthenticator => softAuthenticator(RP.rpID, RP.expectedOrigins)
const TOTP = ['totp', 'backup-code']
const step = (): number => Math.floor(Date.now() / 1000 / 30)

/** The challenge a sign-in stopped at, failing the test when it opened a session instead. */
function challenged(out: Flows.SignInOutcome): Flows.SignInChallenge {
  if (out.challenge === null) throw new Error('the sign-in opened a session')
  return out.challenge
}

function build() {
  const adapter = new MemoryAdapter<P>()
  const mail = authTestDeliver()
  const challenges = new AuthMemoryPasskeyChallengeStore()
  let challenge = ''
  const passkeys: Passkey.Options = {
    ...RP,
    // Records each challenge, which the soft authenticator signs in place of a browser.
    challengeStore: {
      put: (k, v, ttlMs) => {
        challenge = v
        return challenges.put(k, v, ttlMs)
      },
      take: (k) => challenges.take(k),
    },
    findIdentityByEmail: async (email) => orNull(adapter.identities.find({ email })),
    rpName: 'app',
  }
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
      passkey<P>(passkeys),
      custom,
    ],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid' }),
  })
  let ceremonies = 0
  const nextKey = (): string => `ceremony-${++ceremonies}`
  const t = {
    adapter,
    auth,
    outbox: mail.outbox,
    /** Signs in through the custom provider, which answers `intents`. */
    custom: (intents: Provider.InternalIntent[], rememberedDevice?: string) => {
      emitted = intents
      return auth.flows.signIn({
        input: {},
        providerId: 'custom',
        ...(rememberedDevice !== undefined && { rememberedDevice }),
      })
    },
    async addPasskey(id: string, key: SoftAuthenticator, session: Sessions.Me | null = null): Promise<void> {
      const sessionId = nextKey()
      const input = { credentialStore: adapter.credentials, identityId: id, session, sessionId, tenant: {} }
      await beginPasskeyRegistration(passkeys, { ...input, userName: id })
      await completePasskeyRegistration(passkeys, { ...input, response: key.register(challenge) })
    },
    async passkeySignIn(email: string, key: SoftAuthenticator, count: number, verified = true) {
      const sessionId = nextKey()
      await auth.flows.beginProvider('passkey', { email, sessionId })
      return auth.flows.signIn({
        input: { email, response: key.assert(challenge, count, { verified }), sessionId },
        providerId: 'passkey',
      })
    },
    async finishWithPasskey(token: string, email: string, key: SoftAuthenticator, count: number) {
      const sessionId = nextKey()
      await auth.flows.beginProvider('passkey', { email, sessionId })
      return auth.flows.completeStepUp({
        challenge: token,
        method: 'passkey',
        passkey: { response: key.assert(challenge, count), sessionId },
      })
    },
    devices: new RememberMeFacet(adapter.credentials, { authRandomToken: randomToken, authSha256: sha256 }),
    async account(email: string, tenant: TenantContext = {}): Promise<string> {
      const { id } = await auth.identities.create({ profile: { email, username: email } })
      await auth.passwords.set(id, PASSWORD, adapter.credentials, null, tenant)
      return id
    },
    signIn: (email: string, tenantId?: string) =>
      auth.flows.signIn({
        input: { email, password: PASSWORD },
        providerId: 'password',
        ...(tenantId !== undefined && { tenantId }),
      }),
    /** Enrolls a TOTP on an account with no other factor, and answers its secret and backup codes. */
    async enrollTotp(id: string, email: string, tenant: TenantContext = {}) {
      const { secret } = await auth.mfa.beginTotpEnrollment(id, email, null, tenant)
      const confirmed = await auth.mfa.confirmTotpEnrollment(id, totpAt(secret, step()), null, tenant)
      return { codes: confirmed.ok ? confirmed.backupCodes : [], secret }
    },
    async totp(id: string, email: string): Promise<string> {
      return (await t.enrollTotp(id, email)).secret
    },
    /** Finishes a challenge with the TOTP's next code. */
    finish: (token: string, secret: string) =>
      auth.flows.completeStepUp({ challenge: token, code: totpAt(secret, step() + 1), method: 'totp' }),
  }
  return t
}

describe('a sign-in beside a second factor', () => {
  it('stops at a challenge and opens no session', async () => {
    const t = build()
    const id = await t.account('a@x.com')
    await t.totp(id, 'a@x.com')

    const out = await t.signIn('a@x.com')

    expect(out).toMatchObject({ challenge: { identityId: id, methods: TOTP }, session: null, sid: '' })
    expect(out.challenge?.token).toEqual(expect.any(String))
    expect(await t.adapter.sessions.listByIdentity(id)).toEqual([])
  })

  it('opens the session at AAL 2 once the second factor answers it', async () => {
    const t = build()
    const id = await t.account('a@x.com')
    const secret = await t.totp(id, 'a@x.com')
    const { token } = challenged(await t.signIn('a@x.com'))

    const out = await t.auth.flows.completeStepUp({
      challenge: token,
      code: totpAt(secret, step() + 1),
      method: 'totp',
    })

    expect(out.session).toMatchObject({ aal: 2, identityId: id, kind: 'user' })
    expect(out.session.factors.map((f) => f.method)).toEqual(['password', 'totp'])
    expect((await t.auth.sessions.getBySid(out.sid).orNull())?.id).toBe(out.session.id)
  })

  it('opens one session only', async () => {
    const t = build()
    const id = await t.account('a@x.com')
    const { codes, secret } = await t.enrollTotp(id, 'a@x.com')
    const { token } = challenged(await t.signIn('a@x.com'))
    await t.finish(token, secret)

    const again = t.auth.flows.completeStepUp({ challenge: token, code: codes[0] ?? '', method: 'backup-code' })

    await expect(again).rejects.toMatchObject({ code: 'AUTH_UNAUTHENTICATED' })
    expect(await t.adapter.sessions.listByIdentity(id)).toHaveLength(1)
  })

  it('opens one session for two answers racing on it', async () => {
    const t = build()
    const id = await t.account('a@x.com')
    const { codes, secret } = await t.enrollTotp(id, 'a@x.com')
    const { token } = challenged(await t.signIn('a@x.com'))

    const answers = await Promise.allSettled([
      t.finish(token, secret),
      t.auth.flows.completeStepUp({ challenge: token, code: codes[0] ?? '', method: 'backup-code' }),
    ])

    expect(answers.map((a) => a.status).sort()).toEqual(['fulfilled', 'rejected'])
    expect(answers.find((a) => a.status === 'rejected')).toMatchObject({ reason: { code: 'AUTH_UNAUTHENTICATED' } })
    expect(await t.adapter.sessions.listByIdentity(id)).toHaveLength(1)
  })

  it('stays open after a wrong code, for the right one', async () => {
    const t = build()
    const id = await t.account('a@x.com')
    const secret = await t.totp(id, 'a@x.com')
    const { token } = challenged(await t.signIn('a@x.com'))

    const wrong = t.auth.flows.completeStepUp({ challenge: token, code: '000000', method: 'totp' })

    await expect(wrong).rejects.toMatchObject({ code: 'AUTH_INVALID_CREDENTIALS' })
    expect((await t.finish(token, secret)).session.aal).toBe(2)
  })

  it('is refused once it has expired', async () => {
    const t = build()
    const id = await t.account('a@x.com')
    const secret = await t.totp(id, 'a@x.com')
    const { expiresAt, token } = challenged(await t.signIn('a@x.com'))
    vi.useFakeTimers({ toFake: ['Date'] })
    onTestFinished(() => {
      vi.useRealTimers()
    })
    vi.setSystemTime(expiresAt.getTime() + 1)

    await expect(t.finish(token, secret)).rejects.toMatchObject({ code: 'AUTH_UNAUTHENTICATED' })
  })

  it('is refused once revoked', async () => {
    const t = build()
    const id = await t.account('a@x.com')
    const { codes } = await t.enrollTotp(id, 'a@x.com')
    const { token } = challenged(await t.signIn('a@x.com'))
    for (const row of await t.adapter.credentials.listByIdentity(id, 'recovery', {})) {
      if (row.metadata?.purpose === 'mfa-challenge') await t.adapter.credentials.revoke(row.id, {})
    }

    const out = t.auth.flows.completeStepUp({ challenge: token, code: codes[0] ?? '', method: 'backup-code' })

    await expect(out).rejects.toMatchObject({ code: 'AUTH_UNAUTHENTICATED' })
  })

  it('is retired by the next sign-in', async () => {
    const t = build()
    const id = await t.account('a@x.com')
    const secret = await t.totp(id, 'a@x.com')
    const first = challenged(await t.signIn('a@x.com'))
    const second = challenged(await t.signIn('a@x.com'))

    await expect(t.finish(first.token, secret)).rejects.toMatchObject({ code: 'AUTH_UNAUTHENTICATED' })
    expect((await t.finish(second.token, secret)).session.aal).toBe(2)
  })

  it('bounds the guesses per identity, however many sign-ins they spread over', async () => {
    const t = build()
    const id = await t.account('a@x.com')
    const secret = await t.totp(id, 'a@x.com')
    const guess = (token: string) => t.auth.flows.completeStepUp({ challenge: token, code: '000000', method: 'totp' })

    for (let i = 0; i < 5; i++) {
      const { token } = challenged(await t.signIn('a@x.com'))
      for (let j = 0; j < 10; j++)
        await expect(guess(token)).rejects.toMatchObject({ code: 'AUTH_INVALID_CREDENTIALS' })
    }
    const { token } = challenged(await t.signIn('a@x.com'))

    await expect(t.finish(token, secret)).rejects.toMatchObject({ code: 'AUTH_RATE_LIMITED' })
  })

  it("refuses a remembered device's token, which is no challenge", async () => {
    const t = build()
    const id = await t.account('a@x.com')
    const { codes, secret } = await t.enrollTotp(id, 'a@x.com')
    const stepped = await t.finish(challenged(await t.signIn('a@x.com')).token, secret)
    const { token } = await t.devices.issue(id, stepped.session)

    const out = t.auth.flows.completeStepUp({ challenge: token, code: codes[0] ?? '', method: 'backup-code' })

    await expect(out).rejects.toMatchObject({ code: 'AUTH_UNAUTHENTICATED' })
  })

  it('refuses a token no sign-in issued', async () => {
    const t = build()
    const id = await t.account('a@x.com')
    const secret = await t.totp(id, 'a@x.com')
    challenged(await t.signIn('a@x.com'))

    await expect(t.finish('not-a-challenge', secret)).rejects.toMatchObject({ code: 'AUTH_UNAUTHENTICATED' })
    await expect(t.finish('', secret)).rejects.toMatchObject({ code: 'AUTH_UNAUTHENTICATED' })
  })

  it("opens the session in the tenant it was issued in, against that tenant's factor", async () => {
    const t = build()
    const id = await t.account('a@x.com', { tenantId: 'acme' })
    const acme = await t.enrollTotp(id, 'a@x.com', { tenantId: 'acme' })
    const globex = await t.enrollTotp(id, 'a@x.com', { tenantId: 'globex' })
    const { token } = challenged(await t.signIn('a@x.com', 'acme'))

    await expect(t.finish(token, globex.secret)).rejects.toMatchObject({ code: 'AUTH_INVALID_CREDENTIALS' })
    expect((await t.finish(token, acme.secret)).session).toMatchObject({ aal: 2, tenantId: 'acme' })
  })
})

describe('a remembered device', () => {
  it('skips the challenge for its own identity, at the AAL the first factor reached', async () => {
    const t = build()
    const id = await t.account('a@x.com')
    const secret = await t.totp(id, 'a@x.com')
    const stepped = await t.finish(challenged(await t.signIn('a@x.com')).token, secret)
    const { token } = await t.devices.issue(id, stepped.session)

    const out = await t.auth.flows.signIn({
      input: { email: 'a@x.com', password: PASSWORD },
      providerId: 'password',
      rememberedDevice: token,
    })

    expect(out).toMatchObject({ challenge: null, session: { aal: 1, identityId: id } })
  })

  it('does not skip it for another identity, or for a token it cannot read', async () => {
    const t = build()
    const a = await t.account('a@x.com')
    const b = await t.account('b@x.com')
    const secret = await t.totp(a, 'a@x.com')
    await t.totp(b, 'b@x.com')
    const stepped = await t.finish(challenged(await t.signIn('a@x.com')).token, secret)
    const { token } = await t.devices.issue(a, stepped.session)
    const signIn = (rememberedDevice: string) =>
      t.auth.flows.signIn({ input: { email: 'b@x.com', password: PASSWORD }, providerId: 'password', rememberedDevice })

    for (const device of [token, 'not-a-device', '']) {
      expect((await signIn(device)).challenge).toMatchObject({ identityId: b })
    }
  })
})

describe('a passkey', () => {
  it('that verified the user signs in at AAL 2 without a challenge', async () => {
    const t = build()
    const id = await t.account('a@x.com')
    const key = device()
    await t.addPasskey(id, key)

    const out = await t.passkeySignIn('a@x.com', key, 1)

    expect(out).toMatchObject({ challenge: null, session: { aal: 2, identityId: id } })
  })

  it('that did not is not asked for again, which an authenticator without a PIN cannot answer', async () => {
    const t = build()
    const id = await t.account('a@x.com')
    const key = device()
    await t.addPasskey(id, key)

    const out = await t.passkeySignIn('a@x.com', key, 1, false)

    expect(out).toMatchObject({ challenge: null, session: { aal: 1, identityId: id } })
  })

  it('that did not still leaves the TOTP to answer', async () => {
    const t = build()
    const id = await t.account('a@x.com')
    const key = device()
    await t.addPasskey(id, key)
    const { session } = await t.passkeySignIn('a@x.com', key, 1)
    const { secret } = await t.auth.mfa.beginTotpEnrollment(id, 'a@x.com', session)
    await t.auth.mfa.confirmTotpEnrollment(id, totpAt(secret, step()), session)

    const out = await t.passkeySignIn('a@x.com', key, 2, false)

    expect(challenged(out).methods).toEqual(TOTP)
  })

  it('answers a password sign-in on its account', async () => {
    const t = build()
    const id = await t.account('a@x.com')
    const key = device()
    await t.addPasskey(id, key)
    const { methods, token } = challenged(await t.signIn('a@x.com'))

    const out = await t.finishWithPasskey(token, 'a@x.com', key, 1)

    expect(methods).toEqual(['passkey'])
    expect(out.session.factors.map((f) => f.method)).toEqual(['password', 'passkey'])
  })
})

describe('any provider', () => {
  const now = () => [{ completedAt: new Date(), method: 'oauth' as const }]

  it('stops at the same challenge, whatever its first factor', async () => {
    const t = build()
    const id = await t.account('a@x.com')
    const secret = await t.totp(id, 'a@x.com')

    const { token } = challenged(await t.custom([{ aal: 1, factors: now(), identityId: id, type: 'startSession' }]))

    expect((await t.finish(token, secret)).session.factors.map((f) => f.method)).toEqual(['oauth', 'totp'])
  })

  it('lets an API key through, which signs in a machine and not a person', async () => {
    const t = build()
    const id = await t.account('a@x.com')
    await t.totp(id, 'a@x.com')
    const factors = [{ completedAt: new Date(), method: 'api-key' as const }]

    const out = await t.custom([{ aal: 1, factors, identityId: id, kind: 'apikey', type: 'startSession' }])

    expect(out).toMatchObject({ challenge: null, session: { kind: 'apikey' } })
  })

  it('ends the other sessions only once the challenge is answered, when it asked to', async () => {
    const t = build()
    const id = await t.account('a@x.com')
    const secret = await t.totp(id, 'a@x.com')
    const other = await t.auth.sessions.create({ aal: 1, factors: now(), identityId: id, kind: 'user' })
    const intent = {
      aal: 1 as const,
      endOtherSessions: true,
      factors: now(),
      identityId: id,
      type: 'startSession' as const,
    }

    const { token } = challenged(await t.custom([intent]))
    expect(await t.auth.sessions.getBySid(other.sid).orNull()).not.toBeNull()
    const out = await t.finish(token, secret)

    expect(await t.auth.sessions.getBySid(other.sid).orNull()).toBeNull()
    expect(await t.auth.sessions.getBySid(out.sid).orNull()).not.toBeNull()
  })

  it('demanding a second factor gets the challenge on a remembered device too', async () => {
    const t = build()
    const id = await t.account('a@x.com')
    const secret = await t.totp(id, 'a@x.com')
    const stepped = await t.finish(challenged(await t.signIn('a@x.com')).token, secret)
    const { token } = await t.devices.issue(id, stepped.session)
    const start = { aal: 1 as const, factors: now(), identityId: id, type: 'startSession' as const }

    expect((await t.custom([start], token)).challenge).toBeNull()
    const demanded = await t.custom([start, { identityId: id, methods: ['totp'], type: 'requireMfa' }], token)

    expect(challenged(demanded).methods).toEqual(TOTP)
  })

  it('demanding a second factor gets the challenge on an account that has one', async () => {
    const t = build()
    const id = await t.account('a@x.com')
    const secret = await t.totp(id, 'a@x.com')
    const start = { aal: 2 as const, factors: now(), identityId: id, type: 'startSession' as const }

    const { token } = challenged(await t.custom([start, { identityId: id, methods: ['totp'], type: 'requireMfa' }]))

    expect((await t.finish(token, secret)).session.aal).toBe(2)
  })
})

describe('the session a challenge opens', () => {
  it('is reported signed in when it opens, not when the challenge does', async () => {
    const t = build()
    const id = await t.account('a@x.com')
    const secret = await t.totp(id, 'a@x.com')
    const reported: string[][] = []
    t.auth.events.on('signin.success', ({ factors }) => {
      reported.push(factors.map((f) => f.method))
    })

    const { token } = challenged(await t.signIn('a@x.com'))
    expect(reported).toEqual([])
    await t.finish(token, secret)

    expect(reported).toEqual([['password', 'totp']])
  })

  it('replaces the one the request came in on', async () => {
    const t = build()
    const id = await t.account('a@x.com')
    const secret = await t.totp(id, 'a@x.com')
    const before = await t.auth.sessions.create({ aal: 1, factors: [], identityId: null, kind: 'guest' })
    const { token } = challenged(await t.signIn('a@x.com'))

    await t.auth.flows.completeStepUp({
      challenge: token,
      code: totpAt(secret, step() + 1),
      method: 'totp',
      previousSid: before.sid,
    })

    expect(await t.auth.sessions.getBySid(before.sid).orNull()).toBeNull()
  })

  it('cannot be opened by a challenge a password reset outlived', async () => {
    const t = build()
    const id = await t.account('a@x.com')
    const { codes, secret } = await t.enrollTotp(id, 'a@x.com')
    const stepped = await t.finish(challenged(await t.signIn('a@x.com')).token, secret)
    const pending = challenged(await t.signIn('a@x.com'))
    await t.auth.flows.requestPasswordReset({
      findIdentityByEmail: (email) => t.auth.identities.getByEmail(email),
      input: { email: 'a@x.com' },
    })
    const [sent] = t.outbox
    const reset = sent?.kind === 'password-reset' ? (new URL(sent.vars.url).searchParams.get('token') ?? '') : ''
    await t.auth.flows.completePasswordReset({ currentSid: stepped.sid, newPassword: 'new-password-9', token: reset })

    const late = t.auth.flows.completeStepUp({ challenge: pending.token, code: codes[0] ?? '', method: 'backup-code' })

    await expect(late).rejects.toMatchObject({ code: 'AUTH_UNAUTHENTICATED' })
  })
})
