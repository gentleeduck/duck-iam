/**
 * E2E: the token-carrying flows against REAL Postgres and REAL Redis.
 *
 * Password reset, email verification and account deletion all hand a secret to a
 * channel, then take it back later and act on it. That is the same shape as an
 * OIDC authorization code, and every bug this audit found sat in that shape: the
 * token has to work once, expire, belong to exactly one account, and leave the
 * right wreckage behind when it is spent.
 *
 * Two of those are only observable against a real store. Whether the reset marked
 * the token spent is a claim about a row a later request reads back, and whether
 * it revoked the other devices is a claim about rows nobody in this process is
 * holding.
 *
 * Skips when DUCKAUTH_E2E_DATABASE_URL or DUCKAUTH_E2E_REDIS_URL is unset;
 * `globalSetup` provisions both when docker is available.
 */
import Redis from 'ioredis'
import { Pool } from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DrizzlePgAdapter } from '~/adapters/drizzle/pg'
import { type ValkeyClient, valkeyAdapter } from '~/adapters/valkey'
import { AuthTestChannel } from '~/channels/console'
import { getCredentialPurpose } from '~/core/credentials/credentials'
import { AuthEngine } from '~/core/engine'
import { redisIdempotency } from '~/core/idempotency'
import { RedisIdempotency } from '~/core/idempotency/idempotency.redis'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { RedisLimiter } from '~/limiters/redis'
import { mfaProvider } from '~/providers/mfa'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { applyPgSchema, databaseUrl, dropPrefix, e2ePrefix, redisUrl } from '~/test/e2e-env'

const PG_URL = databaseUrl()
const REDIS_URL = redisUrl()
const suite = PG_URL && REDIS_URL ? describe : describe.skip

type Profile = { username: string; email: string }
const PASSWORD = 'correct-horse-battery'
const NEW_PASSWORD = 'a-different-horse-entirely'

suite('E2E token flows on real Postgres + Redis', () => {
  let pool: Pool
  let raw: Redis
  let prefix: string
  let auth: AuthEngine<Profile>
  let stores: DrizzlePgAdapter
  const planted: string[] = []

  const cookie = (sid: string) => ({ headers: new Headers({ cookie: `duck-sid=${sid}` }) })

  /** Pull the `token` query param out of whatever the channel was handed. */
  function tokenFrom(channel: AuthTestChannel, index = 0): string {
    const entry = channel.outbox[index]
    if (!entry) throw new Error('channel received nothing')
    const url = (entry.vars as { url?: string }).url
    if (!url) throw new Error(`no url on the message: ${JSON.stringify(entry.vars)}`)
    const token = new URL(url).searchParams.get('token')
    if (!token) throw new Error(`no token on the url: ${url}`)
    return token
  }

  async function newUser(label: string): Promise<{ id: string; email: string }> {
    const email = `${label}-${e2ePrefix()}@test.local`
    const identity = await auth.identities.create({ profile: { email, username: email } })
    await auth.passwords.set(identity.id, PASSWORD, stores.credentials)
    planted.push(identity.id)
    return { email, id: identity.id }
  }

  const findByEmail = async (email: string) => stores.identities.find({ email })

  async function requestReset(email: string): Promise<{ channel: AuthTestChannel; token: string }> {
    const channel = new AuthTestChannel()
    await auth.flows.requestPasswordReset({
      channels: { email: channel },
      findIdentityByEmail: findByEmail,
      input: { email },
    })
    return { channel, token: tokenFrom(channel) }
  }

  async function signIn(email: string) {
    return auth.flows.signIn({ input: { email, password: PASSWORD }, providerId: 'password' })
  }

  beforeAll(async () => {
    pool = new Pool({ connectionString: PG_URL })
    await applyPgSchema(pool)
    raw = new Redis(REDIS_URL as string, { lazyConnect: true, maxRetriesPerRequest: 2 })
    await raw.connect()
    prefix = e2ePrefix()
    stores = new DrizzlePgAdapter(PG_URL as string)

    auth = new AuthEngine<Profile>({
      baseUrl: 'https://app.test',
      idempotency: redisIdempotency({ prefix, redis: valkeyAdapter(raw as unknown as ValkeyClient.Me) }),
      limiter: new RedisLimiter({
        max: 500,
        prefix,
        redis: valkeyAdapter(raw as unknown as ValkeyClient.Me),
        windowMs: 60_000,
      }),
      stores: { credentials: stores.credentials, identities: stores.identities, sessions: stores.sessions },
      transport: new CookieTransport({ name: 'duck-sid', secure: false }),
    })
    auth.providers.register(passwords<Profile>({ hasher: new ScryptHasher({ keylen: 32, N: 1 << 10 }) }))
    // The reset flow asks whether the account has MFA before swapping a password,
    // so the provider has to be present even when no test enrolls one.
    const mfa = mfaProvider()
    auth.providers.register(typeof mfa === 'function' ? mfa(auth as never) : mfa)
  }, 60_000)

  afterAll(async () => {
    if (raw) {
      await dropPrefix(raw, prefix)
      await raw.quit()
    }
    if (pool && planted.length > 0) {
      await pool.query('DELETE FROM auth_identities WHERE id = ANY($1::uuid[])', [planted])
    }
    await pool?.end()
  })

  describe('password reset: the token works once', () => {
    it('changes the password and lets the new one sign in', async () => {
      const user = await newUser('reset-happy')
      const { token } = await requestReset(user.email)

      await auth.flows.completePasswordReset({ newPassword: NEW_PASSWORD, token })

      const signedIn = await auth.flows.signIn({
        input: { email: user.email, password: NEW_PASSWORD },
        providerId: 'password',
      })
      expect(signedIn.sid).toBeTruthy()
    })

    it('refuses the old password afterwards', async () => {
      const user = await newUser('reset-old-pw')
      const { token } = await requestReset(user.email)
      await auth.flows.completePasswordReset({ newPassword: NEW_PASSWORD, token })

      await expect(signIn(user.email)).rejects.toMatchObject({ code: 'AUTH_INVALID_CREDENTIALS' })
    })

    it('refuses the same token a second time', async () => {
      const user = await newUser('reset-replay')
      const { token } = await requestReset(user.email)
      await auth.flows.completePasswordReset({ newPassword: NEW_PASSWORD, token })

      await expect(
        auth.flows.completePasswordReset({ newPassword: 'yet-another-password', token }),
      ).rejects.toMatchObject({ code: 'AUTH_RECOVERY_TOKEN_INVALID' })
    })

    it('admits exactly one of two simultaneous redemptions', async () => {
      // Both halves of a double-clicked reset link arriving at once.
      const user = await newUser('reset-race')
      const { token } = await requestReset(user.email)

      const settled = await Promise.allSettled([
        auth.flows.completePasswordReset({ newPassword: NEW_PASSWORD, token }),
        auth.flows.completePasswordReset({ newPassword: 'a-third-password', token }),
      ])
      expect(settled.filter((r) => r.status === 'fulfilled')).toHaveLength(1)
    })

    it('refuses a token that was never issued', async () => {
      await expect(
        auth.flows.completePasswordReset({ newPassword: NEW_PASSWORD, token: `made-up-${e2ePrefix()}` }),
      ).rejects.toMatchObject({ code: 'AUTH_RECOVERY_TOKEN_INVALID' })
    })

    it('refuses a token issued for a different account', async () => {
      // Two live resets at once: neither token may act on the other's account.
      const mine = await newUser('reset-mine')
      const theirs = await newUser('reset-theirs')
      const { token: theirToken } = await requestReset(theirs.email)
      await requestReset(mine.email)

      await auth.flows.completePasswordReset({ newPassword: NEW_PASSWORD, token: theirToken })

      // Their password changed; mine did not.
      const stillMine = await signIn(mine.email)
      expect(stillMine.sid).toBeTruthy()
    })

    it('revokes every other session for the account', async () => {
      // The reason a reset exists: whoever was in the account is put out of it.
      const user = await newUser('reset-revokes')
      const a = await signIn(user.email)
      const b = await signIn(user.email)
      const { token } = await requestReset(user.email)

      await auth.flows.completePasswordReset({ newPassword: NEW_PASSWORD, token })

      expect(await auth.resolveSession(cookie(a.sid))).toBeNull()
      expect(await auth.resolveSession(cookie(b.sid))).toBeNull()
    })

    it('leaves other accounts signed in', async () => {
      const victim = await newUser('reset-victim')
      const bystander = await newUser('reset-bystander')
      const theirs = await signIn(bystander.email)
      const { token } = await requestReset(victim.email)

      await auth.flows.completePasswordReset({ newPassword: NEW_PASSWORD, token })

      expect(await auth.resolveSession(cookie(theirs.sid))).not.toBeNull()
    })

    it('says nothing about whether an address is registered', async () => {
      // Enumeration: the response for an unknown address must look like the
      // response for a known one.
      const channel = new AuthTestChannel()
      const result = await auth.flows.requestPasswordReset({
        channels: { email: channel },
        findIdentityByEmail: findByEmail,
        input: { email: `nobody-${e2ePrefix()}@test.local` },
      })
      expect(result).toEqual({ ok: true })
      expect(channel.outbox).toHaveLength(0)
    })

    it('issues a distinct token each time it is asked', async () => {
      const user = await newUser('reset-distinct')
      const first = await requestReset(user.email)
      const second = await requestReset(user.email)
      expect(first.token).not.toBe(second.token)
    })
  })

  describe('email verification', () => {
    it('marks the address verified and refuses the token afterwards', async () => {
      const user = await newUser('verify')
      const channel = new AuthTestChannel()
      await auth.flows.requestEmailVerification({
        channels: { email: channel },
        identityId: user.id,
      })
      const token = tokenFrom(channel)

      const done = await auth.flows.completeEmailVerification({ token })
      expect(done.identityId).toBe(user.id)

      const verified = await stores.identities.find({ id: user.id })
      expect(verified?.emailVerified).toBe(true)

      await expect(auth.flows.completeEmailVerification({ token })).rejects.toMatchObject({
        code: 'AUTH_RECOVERY_TOKEN_INVALID',
      })
    })

    it('writes the column and leaves no flag in the profile for a caller to set', async () => {
      // Verification used to live in both places and only the profile one was written, so a
      // consumer reading the typed row saw `false` forever. The column wins: `updateProfile`
      // merges a caller's patch unfiltered, so a flag in the profile is one the subject of the
      // decision can set on themselves.
      const user = await newUser('verify-column')
      const channel = new AuthTestChannel()
      await auth.flows.requestEmailVerification({ channels: { email: channel }, identityId: user.id })
      await auth.flows.completeEmailVerification({ token: tokenFrom(channel) })

      const row = await stores.identities.find({ id: user.id })
      expect(row?.emailVerified).toBe(true)
      expect((row?.profile as { emailVerified?: boolean }).emailVerified).toBeUndefined()
    })
    it('refuses a token that was never issued', async () => {
      await expect(auth.flows.completeEmailVerification({ token: `made-up-${e2ePrefix()}` })).rejects.toMatchObject({
        code: 'AUTH_RECOVERY_TOKEN_INVALID',
      })
    })

    it('a verification token cannot be spent as a password reset', async () => {
      // Different kinds must not be interchangeable, or the weaker flow becomes a
      // way into the stronger one. The code is the same one a token that never existed gets, deliberately:
      // telling the two apart would confirm the token is real to whoever is holding it.
      const user = await newUser('verify-crosskind')
      const channel = new AuthTestChannel()
      await auth.flows.requestEmailVerification({ channels: { email: channel }, identityId: user.id })
      const token = tokenFrom(channel)

      await expect(auth.flows.completePasswordReset({ newPassword: NEW_PASSWORD, token })).rejects.toMatchObject({
        code: 'AUTH_RECOVERY_TOKEN_INVALID',
      })
    })

    it('a reset token cannot be spent as an email verification', async () => {
      const user = await newUser('reset-crosskind')
      const { token } = await requestReset(user.email)
      await expect(auth.flows.completeEmailVerification({ token })).rejects.toMatchObject({
        code: 'AUTH_RECOVERY_TOKEN_INVALID',
      })
    })
  })

  describe('account deletion and its grace period', () => {
    it('hides the account on completion and restores it on cancel', async () => {
      const user = await newUser('delete-restore')
      const channel = new AuthTestChannel()
      await auth.flows.requestAccountDeletion({ channels: { email: channel }, identityId: user.id })
      const token = tokenFrom(channel)

      await auth.flows.completeAccountDeletion({ token })
      expect(await stores.identities.find({ id: user.id })).toBeNull()

      await auth.flows.cancelAccountDeletion({ authorize: async () => true, identityId: user.id })
      expect(await stores.identities.find({ id: user.id })).not.toBeNull()
    })

    it('refuses the deletion token a second time', async () => {
      const user = await newUser('delete-replay')
      const channel = new AuthTestChannel()
      await auth.flows.requestAccountDeletion({ channels: { email: channel }, identityId: user.id })
      const token = tokenFrom(channel)

      await auth.flows.completeAccountDeletion({ token })
      await expect(auth.flows.completeAccountDeletion({ token })).rejects.toMatchObject({
        code: 'AUTH_RECOVERY_TOKEN_INVALID',
      })
      // Leave it restored so the afterAll cleanup can still find it.
      await auth.flows.cancelAccountDeletion({ authorize: async () => true, identityId: user.id })
    })

    it('a deleted account cannot sign in, and can again once restored', async () => {
      const user = await newUser('delete-signin')
      const channel = new AuthTestChannel()
      await auth.flows.requestAccountDeletion({ channels: { email: channel }, identityId: user.id })
      await auth.flows.completeAccountDeletion({ token: tokenFrom(channel) })

      await expect(signIn(user.email)).rejects.toMatchObject({ code: 'AUTH_INVALID_CREDENTIALS' })

      await auth.flows.cancelAccountDeletion({ authorize: async () => true, identityId: user.id })
      expect((await signIn(user.email)).sid).toBeTruthy()
    })

    it('keeps the address while deleted, so the grace window is worth having', async () => {
      // `uq_auth_identities_email` is unconditional: a hidden row holds its address until it is erased.
      // A partial index would free it the moment the delete landed, and cancelling would then restore an
      // account whose address someone else had already taken and verified.
      const user = await newUser('delete-keeps')
      const channel = new AuthTestChannel()
      await auth.flows.requestAccountDeletion({ channels: { email: channel }, identityId: user.id })
      await auth.flows.completeAccountDeletion({ token: tokenFrom(channel) })

      await expect(
        auth.identities.create({ profile: { email: user.email, username: `${user.email}-again` } }),
      ).rejects.toMatchObject({ code: 'AUTH_EMAIL_TAKEN' })
    })
  })

  describe('signup, on the schema that used to reject it', () => {
    // F27. `beginSignUp` built `{ ...initialProfile, email }` and cast it past a
    // type that requires `username`. Postgres is the only place that ever said
    // so - the sqlite conformance DDL states in its own comment that it omits
    // CHECK constraints, and memory and Redis have no schema - so the documented
    // happy path produced an INSERT the library's own adapter refused, and every
    // suite in the repo passed anyway.
    it('accepts an email-only begin, which the profile CHECK used to refuse', async () => {
      const email = `signup-${e2ePrefix()}@test.local`
      const { flow, flowToken } = await auth.flows.beginSignUp({ email })
      planted.push(flow.identityId)
      expect(flowToken).toBeTruthy()

      const row = await stores.identities.find({ id: flow.identityId })
      expect(row?.profile.username).toBe(email)
      expect(row?.emailVerified).toBe(false)
    })

    it('keeps a username the caller did supply', async () => {
      const email = `signup-named-${e2ePrefix()}@test.local`
      const username = `handle-${e2ePrefix()}`
      const { flow } = await auth.flows.beginSignUp({ email, initialProfile: { username } })
      planted.push(flow.identityId)
      expect((await stores.identities.find({ id: flow.identityId }))?.profile.username).toBe(username)
    })

    it('carries the flow through to a session', async () => {
      const email = `signup-full-${e2ePrefix()}@test.local`
      const { flow, flowToken } = await auth.flows.beginSignUp({ email, required: ['email-verified'] })
      planted.push(flow.identityId)
      await auth.flows.advanceSignUp({ flowToken, stage: 'email-verified' })
      const done = await auth.flows.completeSignUp({ flowToken })
      expect(done.session?.identityId).toBe(flow.identityId)
    })

    it('the flow-state row is a recovery credential the other flows can tell apart', async () => {
      // F8/F9. One `kind` holds four different token types; `metadata.purpose` is
      // the only thing separating them, and this row used to write `metadata.kind`
      // instead - invisible to every helper that reads the discriminator.
      const email = `signup-purpose-${e2ePrefix()}@test.local`
      const { flow } = await auth.flows.beginSignUp({ email })
      planted.push(flow.identityId)
      const rows = await stores.credentials.listByIdentity(flow.identityId, 'recovery', {})
      expect(rows.map((r) => getCredentialPurpose(r))).toEqual(['signup-flow'])
    })

    it('an email verification request does not void an in-flight signup', async () => {
      const email = `signup-survives-${e2ePrefix()}@test.local`
      const { flow, flowToken } = await auth.flows.beginSignUp({ email, required: ['email-verified'] })
      planted.push(flow.identityId)

      await auth.flows.requestEmailVerification({
        channels: { email: new AuthTestChannel() },
        identityId: flow.identityId,
      })

      // `deleteByKind(identityId, 'recovery')` used to take the signup row with it,
      // stranding the user mid-signup with a token that no longer resolves.
      expect(await auth.flows.getSignUpFlow(flowToken)).not.toBeNull()
    })
  })

  describe('what the C6 fixes claim, on real rows', () => {
    it('a release hands the operator back a working session rather than clearing the cookie', async () => {
      const admin = await newUser('imp-admin')
      const target = await newUser('imp-target')
      const { sid: adminSid } = await signIn(admin.email)

      const started = await auth.flows.impersonate({
        authorize: async () => true,
        realSid: adminSid,
        reason: 'support ticket 1',
        targetIdentityId: target.id,
      })
      // The impersonation session is the target's, at no assurance of its own.
      expect(started.session.identityId).toBe(target.id)
      expect(started.session.aal).toBe(1)
      expect(started.session.factors).toEqual([])

      const released = await auth.flows.releaseImpersonation(started.sid)
      expect(released.session?.identityId).toBe(admin.id)
      // The sid it answers with resolves against the real store, and the one it
      // replaced does not.
      expect((await auth.resolveSession(cookie(released.sid)))?.session.identityId).toBe(admin.id)
      expect(await auth.resolveSession(cookie(started.sid))).toBeNull()
    })

    it('a reset by a signed-in caller rotates them into a new session instead of stranding them', async () => {
      const user = await newUser('reset-rotate')
      const { sid } = await signIn(user.email)
      const { token } = await requestReset(user.email)

      const out = await auth.flows.completePasswordReset({ currentSid: sid, newPassword: NEW_PASSWORD, token })
      expect(out.intents.length).toBeGreaterThan(0)
      // The session they arrived on is gone with the rest.
      expect(await auth.resolveSession(cookie(sid))).toBeNull()
      // And the new password is the one that works.
      expect((await auth.passwords.verify(user.id, NEW_PASSWORD, stores.credentials)).ok).toBe(true)
    })

    it('a reset row on a real table carries a purpose and no address', async () => {
      const user = await newUser('reset-meta')
      await requestReset(user.email)
      const rows = await stores.credentials.listByIdentity(user.id, 'recovery', {})
      const reset = rows.filter((r) => getCredentialPurpose(r) === 'password-reset')
      expect(reset).toHaveLength(1)
      expect(reset[0]?.metadata).toEqual({ purpose: 'password-reset' })
    })

    it('advancing a signup patches the row in place, leaving one live token', async () => {
      const email = `advance-${e2ePrefix()}@test.local`
      const { flow, flowToken } = await auth.flows.beginSignUp({ email, required: ['terms-accepted'] })
      planted.push(flow.identityId)
      await auth.flows.advanceSignUp({ flowToken, profilePatch: { username: email }, stage: 'terms-accepted' })

      const rows = await stores.credentials.listByIdentity(flow.identityId, 'recovery', {})
      expect(rows).toHaveLength(1)
      expect(rows[0]?.revokedAt).toBeNull()
      // The same token still reads the advanced state back out of Postgres.
      expect((await auth.flows.getSignUpFlow(flowToken))?.completed).toContain('terms-accepted')
      const out = await auth.flows.completeSignUp({ flowToken })
      expect(out.session?.identityId).toBe(flow.identityId)
    })
  })

  describe('sign-in refuses what it should', () => {
    it('refuses the wrong password', async () => {
      const user = await newUser('wrong-pw')
      await expect(
        auth.flows.signIn({ input: { email: user.email, password: 'not-it' }, providerId: 'password' }),
      ).rejects.toMatchObject({ code: 'AUTH_INVALID_CREDENTIALS' })
    })

    it('refuses an unknown address with the same error as a wrong password', async () => {
      // Distinguishable errors here are an account-enumeration oracle.
      await expect(
        auth.flows.signIn({
          input: { email: `ghost-${e2ePrefix()}@test.local`, password: PASSWORD },
          providerId: 'password',
        }),
      ).rejects.toMatchObject({ code: 'AUTH_INVALID_CREDENTIALS' })
    })

    it('refuses an unknown provider id', async () => {
      const user = await newUser('bad-provider')
      await expect(
        auth.flows.signIn({ input: { email: user.email, password: PASSWORD }, providerId: 'telepathy' }),
      ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
    })

    it('finds the account whatever the case of the address', async () => {
      // The unique index is on lower(email), so the lookup has to match it or an
      // address registered with capitals can never sign in again.
      const email = `MiXeD-${e2ePrefix()}@Test.Local`
      const identity = await auth.identities.create({ profile: { email, username: email } })
      planted.push(identity.id)
      await auth.passwords.set(identity.id, PASSWORD, stores.credentials)

      expect((await signIn(email.toLowerCase())).sid).toBeTruthy()
      expect((await signIn(email)).sid).toBeTruthy()
    })
  })
})
