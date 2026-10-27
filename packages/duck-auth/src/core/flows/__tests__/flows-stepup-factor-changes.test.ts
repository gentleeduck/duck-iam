/** A password alone is the only account that changes its factors without a step-up. Beside anything else, adding,
 *  removing or replacing a factor, minting backup codes, remembering a device or resetting the password needs a
 *  session stepped up with what the account already holds. */
import { describe, expect, it, onTestFinished, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { orNull } from '~/core/answer'
import { randomToken, sha256 } from '~/core/crypto'
import { AuthEngine } from '~/core/engine'
import type { Identities } from '~/core/identities/identities.types'
import type { Sessions } from '~/core/sessions/sessions.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { apiKeyProvider } from '~/providers/api-key'
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
const step = (): number => Math.floor(Date.now() / 1000 / 30)
const device = (): SoftAuthenticator => softAuthenticator(RP.rpID, RP.expectedOrigins)
const refusedFor = (methods: string[]) => ({ code: 'AUTH_MFA_REQUIRED', meta: { methods } })
const TOTP = ['totp', 'backup-code']
/** What a step-up answers: a live session, or a password sign-in's challenge. */
type Target = { currentSid: string } | { challenge: string }

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
  const auth = new AuthEngine<P>({
    baseUrl: 'https://app.example.com',
    deliver: mail.deliver,
    limiter: new MemoryLimiter({ max: 50, windowMs: 60_000 }),
    providers: [
      passwords({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) }),
      mfaProvider({ dataAtRest: authTestDataAtRest() }),
      passkey<P>(passkeys),
      apiKeyProvider(),
    ],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid' }),
  })
  const mfaRp = { ...RP, challengeStore: challenges }
  let ceremonies = 0
  const nextKey = (): string => `ceremony-${++ceremonies}`

  const t = {
    adapter,
    auth,
    mfaRp,
    outbox: mail.outbox,
    passkeys,
    async account(email: string): Promise<string> {
      const { id } = await auth.identities.create({ profile: { email, username: email } })
      await auth.passwords.set(id, PASSWORD, adapter.credentials, null)
      return id
    },
    /** Signs in on the password alone, which opens a session only while the account holds nothing beside it. */
    async passwordSession(email: string): Promise<{ session: Sessions.Me; sid: string }> {
      const { session, sid } = await auth.flows.signIn({ input: { email, password: PASSWORD }, providerId: 'password' })
      if (session === null) throw new Error(`${email} holds a second factor`)
      return { session, sid }
    },
    /** Signs in on the password, which an account holding a second factor answers with a challenge. */
    async challenge(email: string, tenantId?: string): Promise<Target> {
      const { challenge } = await auth.flows.signIn({
        input: { email, password: PASSWORD },
        providerId: 'password',
        ...(tenantId !== undefined && { tenantId }),
      })
      if (challenge === null) throw new Error(`${email} signed in without a second factor`)
      return { challenge: challenge.token }
    },
    /** Enrolls a TOTP and answers its secret and backup codes. */
    async enrollTotp(id: string, email: string, session: Sessions.Me | null = null) {
      const { secret } = await auth.mfa.beginTotpEnrollment(id, email, session)
      const confirmed = await auth.mfa.confirmTotpEnrollment(id, totpAt(secret, step()), session)
      return { codes: confirmed.ok ? confirmed.backupCodes : [], secret }
    },
    async totp(id: string, email: string, session: Sessions.Me | null = null): Promise<string> {
      return (await t.enrollTotp(id, email, session)).secret
    },
    async beginKey(id: string, session: Sessions.Me | null = null) {
      const challengeKey = nextKey()
      const options = await auth.mfa.beginWebauthnMfaEnrollment(id, {
        ...mfaRp,
        challengeKey,
        rpName: 'app',
        session,
        userName: id,
      })
      return { challenge: options.challenge, challengeKey }
    },
    completeKey(
      id: string,
      begun: { challengeKey: string; challenge: string },
      key: SoftAuthenticator,
      session: Sessions.Me | null = null,
    ) {
      return auth.mfa.confirmWebauthnMfaEnrollment(id, {
        ...mfaRp,
        challengeKey: begun.challengeKey,
        response: key.register(begun.challenge),
        session,
      })
    },
    async addKey(id: string, key: SoftAuthenticator, session: Sessions.Me | null = null): Promise<void> {
      await t.completeKey(id, await t.beginKey(id, session), key, session)
    },
    async beginPasskey(id: string, session: Sessions.Me | null = null) {
      const sessionId = nextKey()
      await beginPasskeyRegistration(passkeys, {
        credentialStore: adapter.credentials,
        identityId: id,
        session,
        sessionId,
        tenant: {},
        userName: id,
      })
      return { challenge, sessionId }
    },
    completePasskey(
      id: string,
      begun: { sessionId: string; challenge: string },
      key: SoftAuthenticator,
      session: Sessions.Me | null = null,
    ) {
      return completePasskeyRegistration(passkeys, {
        credentialStore: adapter.credentials,
        identityId: id,
        response: key.register(begun.challenge),
        session,
        sessionId: begun.sessionId,
        tenant: {},
      })
    },
    async addPasskey(id: string, key: SoftAuthenticator, session: Sessions.Me | null = null): Promise<void> {
      await t.completePasskey(id, await t.beginPasskey(id, session), key, session)
    },
    stepUpWithTotp: (on: Target, secret: string) =>
      auth.flows.completeStepUp({ ...on, code: totpAt(secret, step() + 1), method: 'totp' }),
    async stepUpWithKey(on: Target, id: string, key: SoftAuthenticator, count: number) {
      const challengeKey = nextKey()
      const options = await auth.mfa.beginWebauthnMfaVerify(id, { ...mfaRp, challengeKey })
      return auth.flows.completeStepUp({
        ...on,
        method: 'webauthn',
        webauthn: { ...mfaRp, challengeKey, response: key.assert(options.challenge, count) },
      })
    },
    async stepUpWithPasskey(on: Target, email: string, key: SoftAuthenticator, count: number, verified = true) {
      const sessionId = nextKey()
      await auth.flows.beginProvider('passkey', { email, sessionId })
      return auth.flows.completeStepUp({
        ...on,
        method: 'passkey',
        passkey: { response: key.assert(challenge, count, { verified }), sessionId },
      })
    },
    async passkeySignIn(email: string, key: SoftAuthenticator, count: number) {
      const sessionId = nextKey()
      await auth.flows.beginProvider('passkey', { email, sessionId })
      return auth.flows.signIn({
        input: { email, response: key.assert(challenge, count), sessionId },
        providerId: 'passkey',
      })
    },
  }
  return t
}

describe('adding an authenticator beside a TOTP', () => {
  it('refuses a passkey from a password-only session, so it never signs in at AAL 2', async () => {
    const t = build()
    const id = await t.account('a@x.com')
    const { session } = await t.passwordSession('a@x.com')
    await t.totp(id, 'a@x.com', session)
    const key = device()

    await expect(t.beginPasskey(id, session)).rejects.toMatchObject(refusedFor(TOTP))
    await expect(t.passkeySignIn('a@x.com', key, 1)).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
  })

  it('refuses a security key from a password-only session, so it never steps up', async () => {
    const t = build()
    const id = await t.account('a@x.com')
    const { session, sid } = await t.passwordSession('a@x.com')
    await t.totp(id, 'a@x.com', session)
    const key = device()

    await expect(t.beginKey(id, session)).rejects.toMatchObject(refusedFor(TOTP))
    await expect(t.stepUpWithKey({ currentSid: sid }, id, key, 1)).rejects.toMatchObject({
      code: 'AUTH_INVALID_CREDENTIALS',
    })
  })

  it('refuses a new TOTP from a password-only session, and keeps the old one', async () => {
    const t = build()
    const id = await t.account('a@x.com')
    const { session, sid } = await t.passwordSession('a@x.com')
    const secret = await t.totp(id, 'a@x.com', session)

    await expect(t.auth.mfa.beginTotpEnrollment(id, 'a@x.com', session)).rejects.toMatchObject(refusedFor(TOTP))
    expect((await t.stepUpWithTotp({ currentSid: sid }, secret)).session.aal).toBe(2)
  })

  it('adds both from a session stepped up with the TOTP', async () => {
    const t = build()
    const id = await t.account('a@x.com')
    const secret = await t.totp(id, 'a@x.com')
    const stepped = await t.stepUpWithTotp(await t.challenge('a@x.com'), secret)
    const key = device()
    const pk = device()

    await t.addKey(id, key, stepped.session)
    await t.addPasskey(id, pk, stepped.session)
    expect((await t.passkeySignIn('a@x.com', pk, 1)).session?.aal).toBe(2)
    expect((await t.stepUpWithKey(await t.challenge('a@x.com'), id, key, 1)).session.aal).toBe(2)
  })

  it('replaces the TOTP from a stepped-up session, the old one working until the new one confirms', async () => {
    const t = build()
    const id = await t.account('a@x.com')
    const old = await t.enrollTotp(id, 'a@x.com')
    const stepped = await t.auth.flows.completeStepUp({
      ...(await t.challenge('a@x.com')),
      code: old.codes[0] ?? '',
      method: 'backup-code',
    })

    const { secret } = await t.auth.mfa.beginTotpEnrollment(id, 'a@x.com', stepped.session)
    expect(await t.auth.mfa.verifyTotp(id, totpAt(old.secret, step() + 1))).toBe(true)
    const confirmed = await t.auth.mfa.confirmTotpEnrollment(id, totpAt(secret, step()), stepped.session)

    expect(confirmed.ok).toBe(true)
    // Past every step the old secret spent, so only its removal refuses it.
    vi.useFakeTimers({ toFake: ['Date'] })
    onTestFinished(() => {
      vi.useRealTimers()
    })
    vi.setSystemTime(Date.now() + 120_000)
    expect(await t.auth.mfa.verifyTotp(id, totpAt(old.secret, step()))).toBe(false)
    expect(await t.auth.mfa.verifyTotp(id, totpAt(secret, step()))).toBe(true)
    // One left, whichever a store lists first.
    expect(await t.auth.mfa.removeTotp(id, stepped.session)).toEqual({ removed: 1 })
  })
})

describe('adding an authenticator beside a security key', () => {
  it('refuses a second key from a password-only session', async () => {
    const t = build()
    const id = await t.account('b@x.com')
    const { session } = await t.passwordSession('b@x.com')
    await t.addKey(id, device(), session)

    await expect(t.beginKey(id, session)).rejects.toMatchObject(refusedFor(['webauthn']))
    expect(await t.adapter.credentials.listByIdentity(id, 'webauthn-mfa', {})).toHaveLength(1)
  })

  it('refuses a passkey or a TOTP from a password-only session', async () => {
    const t = build()
    const id = await t.account('b@x.com')
    const { session } = await t.passwordSession('b@x.com')
    await t.addKey(id, device(), session)

    await expect(t.beginPasskey(id, session)).rejects.toMatchObject(refusedFor(['webauthn']))
    await expect(t.auth.mfa.beginTotpEnrollment(id, 'b@x.com', session)).rejects.toMatchObject(refusedFor(['webauthn']))
    expect(await t.adapter.credentials.listByIdentity(id, 'passkey', {})).toHaveLength(0)
    expect(await t.adapter.credentials.listByIdentity(id, 'totp', {})).toHaveLength(0)
  })

  it('adds a backup key from a session stepped up with the first one', async () => {
    const t = build()
    const id = await t.account('b@x.com')
    const first = device()
    await t.addKey(id, first)
    const stepped = await t.stepUpWithKey(await t.challenge('b@x.com'), id, first, 1)
    const backup = device()

    await t.addKey(id, backup, stepped.session)
    expect((await t.stepUpWithKey(await t.challenge('b@x.com'), id, backup, 1)).session.aal).toBe(2)
  })

  it('names every factor the account holds', async () => {
    const t = build()
    const id = await t.account('b@x.com')
    const { session } = await t.passwordSession('b@x.com')
    const secret = await t.totp(id, 'b@x.com', session)
    const stepped = await t.stepUpWithTotp(await t.challenge('b@x.com'), secret)
    await t.addKey(id, device(), stepped.session)
    await t.addPasskey(id, device(), stepped.session)

    await expect(t.beginPasskey(id, session)).rejects.toMatchObject(refusedFor([...TOTP, 'webauthn', 'passkey']))
  })
})

describe('a passkey beside the password', () => {
  it('refuses a key, a TOTP and another passkey from a password-only session', async () => {
    const t = build()
    const id = await t.account('p@x.com')
    const { session } = await t.passwordSession('p@x.com')
    await t.addPasskey(id, device(), session)

    await expect(t.beginKey(id, session)).rejects.toMatchObject(refusedFor(['passkey']))
    await expect(t.auth.mfa.beginTotpEnrollment(id, 'p@x.com', session)).rejects.toMatchObject(refusedFor(['passkey']))
    await expect(t.beginPasskey(id, session)).rejects.toMatchObject(refusedFor(['passkey']))
  })

  it('steps a password session up, which then adds each of them', async () => {
    const t = build()
    const id = await t.account('p@x.com')
    const { session, sid } = await t.passwordSession('p@x.com')
    const pk = device()
    await t.addPasskey(id, pk, session)

    const stepped = await t.stepUpWithPasskey({ currentSid: sid }, 'p@x.com', pk, 1)
    expect(stepped.session).toMatchObject({ aal: 2, factors: [{ method: 'password' }, { method: 'passkey' }] })
    await t.addKey(id, device(), stepped.session)
    await t.totp(id, 'p@x.com', stepped.session)
    await t.addPasskey(id, device(), stepped.session)
    expect(await t.auth.passkeys.list(id, t.adapter.credentials)).toHaveLength(2)
  })

  it('does not step up on a passkey that did not verify the user', async () => {
    const t = build()
    const id = await t.account('p@x.com')
    const pk = device()
    await t.addPasskey(id, pk)
    const on = await t.challenge('p@x.com')

    await expect(t.stepUpWithPasskey(on, 'p@x.com', pk, 1, false)).rejects.toMatchObject({
      code: 'AUTH_INVALID_CREDENTIALS',
    })
    // The same count again: the refusal left none behind.
    expect((await t.stepUpWithPasskey(on, 'p@x.com', pk, 1)).session.aal).toBe(2)
  })

  it("does not step up on another account's passkey", async () => {
    const t = build()
    const id = await t.account('p@x.com')
    await t.addPasskey(id, device())
    const other = await t.account('q@x.com')
    const theirs = device()
    await t.addPasskey(other, theirs)

    await expect(t.stepUpWithPasskey(await t.challenge('p@x.com'), 'q@x.com', theirs, 1)).rejects.toMatchObject({
      code: 'AUTH_INVALID_CREDENTIALS',
    })
    expect((await t.stepUpWithPasskey(await t.challenge('q@x.com'), 'q@x.com', theirs, 1)).session.aal).toBe(2)
  })

  it('names the missing provider when the engine has no passkey()', async () => {
    const adapter = new MemoryAdapter<P>()
    const auth = new AuthEngine<P>({
      baseUrl: 'https://app.example.com',
      limiter: new MemoryLimiter({ max: 50, windowMs: 60_000 }),
      providers: [
        passwords({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) }),
        mfaProvider({ dataAtRest: authTestDataAtRest() }),
      ],
      stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
      transport: new CookieTransport({ name: 'duck-sid' }),
    })
    const { id } = await auth.identities.create({ profile: { email: 'r@x.com', username: 'r@x.com' } })
    await auth.passwords.set(id, PASSWORD, adapter.credentials, null)
    const { sid } = await auth.flows.signIn({ input: { email: 'r@x.com', password: PASSWORD }, providerId: 'password' })

    await expect(
      auth.flows.completeStepUp({ currentSid: sid, method: 'passkey', passkey: { response: {}, sessionId: 's' } }),
    ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_NOT_REGISTERED' })
  })
})

describe('removing a factor or minting backup codes', () => {
  async function everyFactor(t: ReturnType<typeof build>) {
    const id = await t.account('f@x.com')
    const { session } = await t.passwordSession('f@x.com')
    const secret = await t.totp(id, 'f@x.com', session)
    const stepped = await t.stepUpWithTotp(await t.challenge('f@x.com'), secret)
    await t.addKey(id, device(), stepped.session)
    await t.addPasskey(id, device(), stepped.session)
    const [held] = await t.auth.passkeys.list(id, t.adapter.credentials)
    return { id, passkeyId: held?.id ?? '', session, stepped: stepped.session }
  }

  it('refuses each from a password-only session', async () => {
    const t = build()
    const { id, passkeyId, session } = await everyFactor(t)
    const store = t.adapter.credentials
    const all = refusedFor([...TOTP, 'webauthn', 'passkey'])

    await expect(t.auth.mfa.removeTotp(id, session)).rejects.toMatchObject(all)
    await expect(t.auth.mfa.removeWebauthnMfa(id, session)).rejects.toMatchObject(all)
    await expect(t.auth.mfa.removeBackupCodes(id, session)).rejects.toMatchObject(all)
    await expect(t.auth.mfa.regenerateBackupCodes(id, session)).rejects.toMatchObject(all)
    await expect(t.auth.passkeys.revoke(id, passkeyId, store, session)).rejects.toMatchObject(all)
    await expect(t.auth.passkeys.revokeAll(id, store, session)).rejects.toMatchObject(all)

    expect(await t.auth.mfa.hasTotp(id)).toBe(true)
    expect(await t.auth.mfa.hasWebauthnMfa(id)).toBe(true)
    expect(await t.auth.mfa.remainingBackupCodes(id)).toBe(10)
    expect(await t.auth.passkeys.list(id, store)).toHaveLength(1)
  })

  it('does each from a stepped-up session, leaving a password that needs none', async () => {
    const t = build()
    const { id, passkeyId, stepped } = await everyFactor(t)
    const store = t.adapter.credentials

    expect(await t.auth.mfa.regenerateBackupCodes(id, stepped)).toHaveLength(10)
    expect(await t.auth.mfa.removeBackupCodes(id, stepped)).toEqual({ removed: 10 })
    expect((await t.auth.passkeys.revoke(id, passkeyId, store, stepped)).revokedAt).not.toBeNull()
    expect(await t.auth.passkeys.revokeAll(id, store, stepped)).toEqual([])
    expect(await t.auth.mfa.removeWebauthnMfa(id, stepped)).toEqual({ removed: 1 })
    expect(await t.auth.mfa.removeTotp(id, stepped)).toEqual({ removed: 1 })

    await t.addKey(id, device())
    expect(await t.auth.mfa.hasWebauthnMfa(id)).toBe(true)
  })

  it('counts the backup codes a removed TOTP leaves behind, until they go too', async () => {
    const t = build()
    const id = await t.account('b@x.com')
    const { session } = await t.passwordSession('b@x.com')
    const secret = await t.totp(id, 'b@x.com', session)
    const stepped = await t.stepUpWithTotp(await t.challenge('b@x.com'), secret)
    await t.auth.mfa.removeTotp(id, stepped.session)

    await expect(t.addKey(id, device(), session)).rejects.toMatchObject(refusedFor(['backup-code']))
    await t.auth.mfa.removeBackupCodes(id, stepped.session)
    await t.addKey(id, device(), session)
    expect(await t.auth.mfa.hasWebauthnMfa(id)).toBe(true)
  })
})

describe('a key, a link or a password beside a second factor', () => {
  const CI = { name: 'CI', scopes: ['deploy'] }
  const GITHUB = { providerId: 'oauth:github', providerSub: '583231' }
  const GITLAB = { providerId: 'oauth:gitlab', providerSub: '1024' }
  const link = (t: ReturnType<typeof build>, id: string, session: Sessions.Me | null) =>
    t.auth.flows.linkProvider({
      ...GITHUB,
      authorize: async ({ identity }) => identity.id === id,
      identityId: id,
      session,
    })
  const unlink = (t: ReturnType<typeof build>, id: string, session: Sessions.Me | null) =>
    t.auth.flows.unlinkProvider({ identityId: id, providerId: 'oauth:github', session })
  const linksOf = async (t: ReturnType<typeof build>, id: string) =>
    (await t.auth.identities.getById(id).orNull())?.providers.map((p) => p.providerId)

  it('refuses an api key from a password-only session, and mints none', async () => {
    const t = build()
    const id = await t.account('k@x.com')
    const { session } = await t.passwordSession('k@x.com')
    await t.totp(id, 'k@x.com', session)

    await expect(t.auth.apiKeys.create(id, { ...CI, session })).rejects.toMatchObject(refusedFor(TOTP))
    expect(await t.auth.apiKeys.list(id)).toEqual([])
  })

  it('mints one from a stepped-up session', async () => {
    const t = build()
    const id = await t.account('k@x.com')
    const secret = await t.totp(id, 'k@x.com')
    const stepped = await t.stepUpWithTotp(await t.challenge('k@x.com'), secret)

    const { plaintext } = await t.auth.apiKeys.create(id, { ...CI, session: stepped.session })
    expect((await t.auth.apiKeys.verify(plaintext)).identityId).toBe(id)
  })

  it('refuses to rotate a key from a password-only session, and leaves it working', async () => {
    const t = build()
    const id = await t.account('k@x.com')
    const { session } = await t.passwordSession('k@x.com')
    const { key, plaintext } = await t.auth.apiKeys.create(id, { ...CI, session })
    await t.totp(id, 'k@x.com', session)

    await expect(t.auth.apiKeys.rotate(key.id, session)).rejects.toMatchObject(refusedFor(TOTP))
    expect((await t.auth.apiKeys.verify(plaintext)).identityId).toBe(id)
  })

  it("rotates one from its owner's stepped-up session, and from no one else's", async () => {
    const t = build()
    const id = await t.account('k@x.com')
    const { key } = await t.auth.apiKeys.create(id, { ...CI, session: null })
    const secret = await t.totp(id, 'k@x.com')
    const other = await t.account('o@x.com')
    const otherSecret = await t.totp(other, 'o@x.com')
    const theirs = await t.stepUpWithTotp(await t.challenge('o@x.com'), otherSecret)
    const stepped = await t.stepUpWithTotp(await t.challenge('k@x.com'), secret)

    await expect(t.auth.apiKeys.rotate(key.id, theirs.session)).rejects.toMatchObject(refusedFor(TOTP))
    const next = await t.auth.apiKeys.rotate(key.id, stepped.session)
    expect((await t.auth.apiKeys.verify(next.plaintext)).identityId).toBe(id)
  })

  it('refuses a provider link from a password-only session, and links nothing', async () => {
    const t = build()
    const id = await t.account('l@x.com')
    const { session } = await t.passwordSession('l@x.com')
    await t.totp(id, 'l@x.com', session)

    await expect(link(t, id, session)).rejects.toMatchObject(refusedFor(TOTP))
    expect(await linksOf(t, id)).toEqual([])
  })

  it('links and unlinks one from a stepped-up session', async () => {
    const t = build()
    const id = await t.account('l@x.com')
    const secret = await t.totp(id, 'l@x.com')
    const stepped = await t.stepUpWithTotp(await t.challenge('l@x.com'), secret)

    await link(t, id, stepped.session)
    expect(await linksOf(t, id)).toEqual(['oauth:github'])
    await unlink(t, id, stepped.session)
    expect(await linksOf(t, id)).toEqual([])
  })

  it('refuses to unlink a provider from a password-only session, and keeps it', async () => {
    const t = build()
    const id = await t.account('l@x.com')
    const { session } = await t.passwordSession('l@x.com')
    await link(t, id, session)
    await t.totp(id, 'l@x.com', session)

    await expect(unlink(t, id, session)).rejects.toMatchObject(refusedFor(TOTP))
    expect(await linksOf(t, id)).toEqual(['oauth:github'])
  })

  it('refuses a new password from a password-only session, and keeps the old one', async () => {
    const t = build()
    const id = await t.account('w@x.com')
    const { session } = await t.passwordSession('w@x.com')
    await t.totp(id, 'w@x.com', session)
    const store = t.adapter.credentials

    await expect(t.auth.passwords.set(id, 'new-password-9', store, session)).rejects.toMatchObject(refusedFor(TOTP))
    expect((await t.auth.passwords.verify(id, PASSWORD, store)).ok).toBe(true)
  })

  it('sets one from a stepped-up session', async () => {
    const t = build()
    const id = await t.account('w@x.com')
    const secret = await t.totp(id, 'w@x.com')
    const stepped = await t.stepUpWithTotp(await t.challenge('w@x.com'), secret)
    const store = t.adapter.credentials

    await t.auth.passwords.set(id, 'new-password-9', store, stepped.session)
    expect((await t.auth.passwords.verify(id, 'new-password-9', store)).ok).toBe(true)
  })

  it('needs no session on an account with nothing beside the password', async () => {
    const t = build()
    const id = await t.account('n@x.com')
    const store = t.adapter.credentials

    const { key } = await t.auth.apiKeys.create(id, { ...CI, session: null })
    const next = await t.auth.apiKeys.rotate(key.id, null)
    await link(t, id, null)
    await unlink(t, id, null)
    await t.auth.identities.link(id, GITLAB, null)
    await t.auth.identities.unlink(id, 'oauth:gitlab', null)
    await t.auth.passwords.set(id, 'new-password-9', store, null)

    expect((await t.auth.apiKeys.verify(next.plaintext)).identityId).toBe(id)
    expect(await linksOf(t, id)).toEqual([])
    expect((await t.auth.passwords.verify(id, 'new-password-9', store)).ok).toBe(true)
  })

  it('refuses a link or unlink through the identities facet from a password-only session, and changes nothing', async () => {
    const t = build()
    const id = await t.account('p@x.com')
    const { session } = await t.passwordSession('p@x.com')
    await t.auth.identities.link(id, GITLAB, session)
    await t.totp(id, 'p@x.com', session)

    await expect(t.auth.identities.link(id, GITHUB, session)).rejects.toMatchObject(refusedFor(TOTP))
    await expect(t.auth.identities.unlink(id, 'oauth:gitlab', session)).rejects.toMatchObject(refusedFor(TOTP))
    expect(await linksOf(t, id)).toEqual(['oauth:gitlab'])
  })

  it('links and unlinks through it from a stepped-up session', async () => {
    const t = build()
    const id = await t.account('p@x.com')
    const secret = await t.totp(id, 'p@x.com')
    const stepped = await t.stepUpWithTotp(await t.challenge('p@x.com'), secret)

    await t.auth.identities.link(id, GITHUB, stepped.session)
    expect(await linksOf(t, id)).toEqual(['oauth:github'])
    await t.auth.identities.unlink(id, 'oauth:github', stepped.session)
    expect(await linksOf(t, id)).toEqual([])
  })

  it('leaves out of a batch link each account the session cannot change', async () => {
    const t = build()
    const own = await t.account('b@x.com')
    const secret = await t.totp(own, 'b@x.com')
    const guarded = await t.account('g@x.com')
    await t.totp(guarded, 'g@x.com')
    const open = await t.account('o@x.com')
    const stepped = await t.stepUpWithTotp(await t.challenge('b@x.com'), secret)
    const rows = [own, guarded, open].map((identityId) => ({
      identityId,
      link: { ...GITHUB, providerSub: identityId },
    }))

    const linked = await t.auth.identities.linkMany(rows, stepped.session)
    expect(linked.map((row) => row.id)).toEqual([own, open])
    expect(await linksOf(t, guarded)).toEqual([])
  })

  it('and out of a batch unlink', async () => {
    const t = build()
    const own = await t.account('b@x.com')
    const guarded = await t.account('g@x.com')
    const open = await t.account('o@x.com')
    const ids = [own, guarded, open]
    await t.auth.identities.linkMany(
      ids.map((identityId) => ({ identityId, link: { ...GITHUB, providerSub: identityId } })),
      null,
    )
    const secret = await t.totp(own, 'b@x.com')
    await t.totp(guarded, 'g@x.com')
    const stepped = await t.stepUpWithTotp(await t.challenge('b@x.com'), secret)

    const rows = ids.map((identityId) => ({ identityId, providerId: GITHUB.providerId }))
    const unlinked = await t.auth.identities.unlinkMany(rows, stepped.session)
    expect(unlinked.map((row) => row.id)).toEqual([own, open])
    expect(await linksOf(t, guarded)).toEqual(['oauth:github'])
  })

  it("folds no login into an account with a second factor through bulkCreate's merge", async () => {
    const t = build()
    const guarded = await t.account('g@x.com')
    await t.totp(guarded, 'g@x.com')
    const open = await t.account('o@x.com')
    const row = (email: string) => ({
      profile: { email, username: email },
      providers: [{ ...GITHUB, providerSub: email }],
    })

    await t.auth.identities.bulkCreate([row('g@x.com'), row('o@x.com')], { mode: 'merge' })
    expect(await linksOf(t, guarded)).toEqual([])
    expect(await linksOf(t, open)).toEqual(['oauth:github'])
  })
})

it('remembers a device only for a stepped-up session', async () => {
  const t = build()
  const id = await t.account('d@x.com')
  const { session } = await t.passwordSession('d@x.com')
  const secret = await t.totp(id, 'd@x.com', session)
  const devices = new RememberMeFacet(t.adapter.credentials, { authRandomToken: randomToken, authSha256: sha256 })

  await expect(devices.issue(id, session)).rejects.toMatchObject(refusedFor(TOTP))
  const stepped = await t.stepUpWithTotp(await t.challenge('d@x.com'), secret)
  const issued = await devices.issue(id, stepped.session)
  expect((await devices.verify(issued.token)).identityId).toBe(id)
})

it('asks a password reset on a passkey account for the passkey', async () => {
  const t = build()
  const id = await t.account('r@x.com')
  const pk = device()
  await t.addPasskey(id, pk)
  await t.auth.flows.requestPasswordReset({
    findIdentityByEmail: (email) => t.auth.identities.getByEmail(email),
    input: { email: 'r@x.com' },
  })
  const [sent] = t.outbox
  const token = sent?.kind === 'password-reset' ? (new URL(sent.vars.url).searchParams.get('token') ?? '') : ''

  expect(sent?.kind === 'password-reset' && sent.vars.requiresMfa).toBe(true)
  await expect(t.auth.flows.completePasswordReset({ newPassword: 'new-password-9', token })).rejects.toMatchObject({
    code: 'AUTH_RECOVERY_REQUIRES_MFA',
    meta: { methods: ['passkey'] },
  })
  const { sid } = await t.passkeySignIn('r@x.com', pk, 1)
  await t.auth.flows.completePasswordReset({ currentSid: sid ?? '', newPassword: 'new-password-9', token })
  expect((await t.auth.passwords.verify(id, 'new-password-9', t.adapter.credentials)).ok).toBe(true)
})

describe('the session that allows it', () => {
  it("must be the identity's own", async () => {
    const t = build()
    const id = await t.account('a@x.com')
    await t.totp(id, 'a@x.com')
    const other = await t.account('o@x.com')
    const otherSecret = await t.totp(other, 'o@x.com')
    const theirs = await t.stepUpWithTotp(await t.challenge('o@x.com'), otherSecret)

    await expect(t.beginPasskey(id, theirs.session)).rejects.toMatchObject(refusedFor(TOTP))
    await expect(t.beginKey(id, theirs.session)).rejects.toMatchObject(refusedFor(TOTP))
    await expect(t.auth.mfa.removeTotp(id, theirs.session)).rejects.toMatchObject(refusedFor(TOTP))
  })

  it('must be from the tenant it changes, whose factors are its own', async () => {
    const t = build()
    const { id } = await t.auth.identities.create({ profile: { email: 'm@x.com', username: 'm@x.com' } })
    const secrets: string[] = []
    for (const tenantId of ['a', 'b']) {
      await t.auth.passwords.set(id, PASSWORD, t.adapter.credentials, null, { tenantId })
      const { secret } = await t.auth.mfa.beginTotpEnrollment(id, 'm@x.com', null, { tenantId })
      await t.auth.mfa.confirmTotpEnrollment(id, totpAt(secret, step()), null, { tenantId })
      secrets.push(secret)
    }
    const stepped = await t.stepUpWithTotp(await t.challenge('m@x.com', 'a'), secrets[0] ?? '')
    const begin = (tenantId: string) =>
      t.auth.mfa.beginWebauthnMfaEnrollment(
        id,
        { ...t.mfaRp, challengeKey: `in-${tenantId}`, rpName: 'app', session: stepped.session, userName: id },
        { tenantId },
      )
    const register = (tenantId: string) =>
      beginPasskeyRegistration(t.passkeys, {
        credentialStore: t.adapter.credentials,
        identityId: id,
        session: stepped.session,
        sessionId: `pk-${tenantId}`,
        tenant: { tenantId },
        userName: id,
      })
    const github = { providerId: 'oauth:github', providerSub: '583231' }
    const link = (tenantId: string) => t.auth.identities.link(id, github, stepped.session, { tenantId })
    const unlink = (tenantId: string) => t.auth.identities.unlink(id, github.providerId, stepped.session, { tenantId })
    const gitlab = { providerId: 'oauth:gitlab', providerSub: '1024' }
    const linkMany = (tenantId: string) =>
      t.auth.identities.linkMany([{ identityId: id, link: gitlab }], stepped.session, { tenantId })
    const unlinkMany = (tenantId: string) =>
      t.auth.identities.unlinkMany([{ identityId: id, providerId: gitlab.providerId }], stepped.session, { tenantId })

    await expect(begin('b')).rejects.toMatchObject(refusedFor(TOTP))
    await expect(register('b')).rejects.toMatchObject(refusedFor(TOTP))
    await expect(link('b')).rejects.toMatchObject(refusedFor(TOTP))
    expect(await linkMany('b')).toEqual([])
    await expect(t.auth.mfa.removeTotp(id, stepped.session, { tenantId: 'b' })).rejects.toMatchObject(refusedFor(TOTP))
    await expect(begin('a')).resolves.toBeDefined()
    await expect(register('a')).resolves.toBeDefined()
    await expect(link('a')).resolves.toBeDefined()
    expect(await linkMany('a')).toHaveLength(1)
    await expect(unlink('b')).rejects.toMatchObject(refusedFor(TOTP))
    expect(await unlinkMany('b')).toEqual([])
    await expect(unlink('a')).resolves.toBeDefined()
    expect(await unlinkMany('a')).toHaveLength(1)
    await expect(t.auth.mfa.removeTotp(id, stepped.session, { tenantId: 'a' })).resolves.toEqual({ removed: 1 })
  })

  it('must still be fresh', async () => {
    const t = build()
    const id = await t.account('a@x.com')
    const secret = await t.totp(id, 'a@x.com')
    const stepped = await t.stepUpWithTotp(await t.challenge('a@x.com'), secret)
    const stale = { ...stepped.session, fresh: false }

    await expect(t.beginPasskey(id, stale)).rejects.toMatchObject(refusedFor(TOTP))
    await expect(t.beginKey(id, stale)).rejects.toMatchObject(refusedFor(TOTP))
    await expect(t.auth.mfa.removeTotp(id, stale)).rejects.toMatchObject(refusedFor(TOTP))
  })

  it('is asked for again at the second call, so a ceremony begun stepped up cannot finish without it', async () => {
    const t = build()
    const id = await t.account('a@x.com')
    const { session } = await t.passwordSession('a@x.com')
    const key = device()
    await t.addKey(id, key, session)
    const stepped = await t.stepUpWithKey(await t.challenge('a@x.com'), id, key, 1)
    const refused = refusedFor(['webauthn'])

    const keyCeremony = await t.beginKey(id, stepped.session)
    await expect(t.completeKey(id, keyCeremony, device(), session)).rejects.toMatchObject(refused)
    const passkeyCeremony = await t.beginPasskey(id, stepped.session)
    await expect(t.completePasskey(id, passkeyCeremony, device())).rejects.toMatchObject(refused)
    const { secret } = await t.auth.mfa.beginTotpEnrollment(id, 'a@x.com', stepped.session)
    await expect(t.auth.mfa.confirmTotpEnrollment(id, totpAt(secret, step()), session)).rejects.toMatchObject(refused)

    expect(await t.adapter.credentials.listByIdentity(id, 'webauthn-mfa', {})).toHaveLength(1)
    expect(await t.adapter.credentials.listByIdentity(id, 'passkey', {})).toHaveLength(0)
    expect(await t.auth.mfa.hasTotp(id)).toBe(false)
  })
})

it('needs no session for an authenticator on an account with no second factor', async () => {
  const t = build()
  const withPasskey = await t.account('n@x.com')
  const withKey = await t.account('m@x.com')
  const withTotp = await t.account('k@x.com')
  const pk = device()
  const key = device()

  await t.addPasskey(withPasskey, pk)
  await t.addKey(withKey, key)
  const secret = await t.totp(withTotp, 'k@x.com')
  expect((await t.passkeySignIn('n@x.com', pk, 1)).session?.aal).toBe(2)
  expect((await t.stepUpWithKey(await t.challenge('m@x.com'), withKey, key, 1)).session.aal).toBe(2)
  expect((await t.stepUpWithTotp(await t.challenge('k@x.com'), secret)).session.aal).toBe(2)
})

it('does not count a TOTP enrollment that was never confirmed', async () => {
  const t = build()
  const id = await t.account('u@x.com')
  await t.auth.mfa.beginTotpEnrollment(id, 'u@x.com', null)
  const { session } = await t.passwordSession('u@x.com')

  await t.addPasskey(id, device(), session)
  expect(await t.auth.passkeys.list(id, t.adapter.credentials)).toHaveLength(1)
})
