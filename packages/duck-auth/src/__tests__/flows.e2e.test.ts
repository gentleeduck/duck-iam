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
import { drizzlePgStorage } from '~/adapters/drizzle/pg'
import { type ValkeyClient, valkeyAdapter } from '~/adapters/valkey'
import { AuthTestChannel } from '~/channels/console'
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
  let stores: ReturnType<typeof drizzlePgStorage<Profile>>
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

  const findByEmail = async (email: string) => stores.identities.findByEmail(email)

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
    stores = drizzlePgStorage<Profile>(PG_URL as string)

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

      const verified = await stores.identities.findById(user.id)
      expect(verified?.emailVerified).toBe(true)

      await expect(auth.flows.completeEmailVerification({ token })).rejects.toBeTruthy()
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

      const row = await stores.identities.findById(user.id)
      expect(row?.emailVerified).toBe(true)
      expect((row?.profile as { emailVerified?: boolean }).emailVerified).toBeUndefined()
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

      const verified = await stores.identities.findById(user.id)
      expect(verified?.emailVerified).toBe(true)

      await expect(auth.flows.completeEmailVerification({ token })).rejects.toBeTruthy()
    })

    it('writes the column and leaves no flag in the profile for a caller to set', async () => {
      const user = await newUser('verify-column')
      const channel = new AuthTestChannel()
      await auth.flows.requestEmailVerification({ channels: { email: channel }, identityId: user.id })
      await auth.flows.completeEmailVerification({ token: tokenFrom(channel) })

      const row = await stores.identities.findById(user.id)
      expect(row?.emailVerified).toBe(true)
      expect((row?.profile as { emailVerified?: boolean }).emailVerified).toBeUndefined()
    })
    it('refuses a token that was never issued', async () => {
      await expect(auth.flows.completeEmailVerification({ token: `made-up-${e2ePrefix()}` })).rejects.toBeTruthy()
    })

    it('a verification token cannot be spent as a password reset', async () => {
      // Different kinds must not be interchangeable, or the weaker flow becomes a
      // way into the stronger one.
      const user = await newUser('verify-crosskind')
      const channel = new AuthTestChannel()
      await auth.flows.requestEmailVerification({ channels: { email: channel }, identityId: user.id })
      const token = tokenFrom(channel)

      await expect(auth.flows.completePasswordReset({ newPassword: NEW_PASSWORD, token })).rejects.toBeTruthy()
    })

    it('a reset token cannot be spent as an email verification', async () => {
      const user = await newUser('reset-crosskind')
      const { token } = await requestReset(user.email)
      await expect(auth.flows.completeEmailVerification({ token })).rejects.toBeTruthy()
    })
  })

  describe('account deletion and its grace period', () => {
    it('hides the account on completion and restores it on cancel', async () => {
      const user = await newUser('delete-restore')
      const channel = new AuthTestChannel()
      await auth.flows.requestAccountDeletion({ channels: { email: channel }, identityId: user.id })
      const token = tokenFrom(channel)

      await auth.flows.completeAccountDeletion({ token })
      expect(await stores.identities.findById(user.id)).toBeNull()

      await auth.flows.cancelAccountDeletion({ identityId: user.id })
      expect(await stores.identities.findById(user.id)).not.toBeNull()
    })

    it('refuses the deletion token a second time', async () => {
      const user = await newUser('delete-replay')
      const channel = new AuthTestChannel()
      await auth.flows.requestAccountDeletion({ channels: { email: channel }, identityId: user.id })
      const token = tokenFrom(channel)

      await auth.flows.completeAccountDeletion({ token })
      await expect(auth.flows.completeAccountDeletion({ token })).rejects.toBeTruthy()
      // Leave it restored so the afterAll cleanup can still find it.
      await auth.flows.cancelAccountDeletion({ identityId: user.id })
    })

    it('a deleted account cannot sign in, and can again once restored', async () => {
      const user = await newUser('delete-signin')
      const channel = new AuthTestChannel()
      await auth.flows.requestAccountDeletion({ channels: { email: channel }, identityId: user.id })
      await auth.flows.completeAccountDeletion({ token: tokenFrom(channel) })

      await expect(signIn(user.email)).rejects.toBeTruthy()

      await auth.flows.cancelAccountDeletion({ identityId: user.id })
      expect((await signIn(user.email)).sid).toBeTruthy()
    })

    it('frees the address while deleted, because the unique index is partial', async () => {
      const user = await newUser('delete-frees')
      const channel = new AuthTestChannel()
      await auth.flows.requestAccountDeletion({ channels: { email: channel }, identityId: user.id })
      await auth.flows.completeAccountDeletion({ token: tokenFrom(channel) })

      const replacement = await auth.identities.create({
        profile: { email: user.email, username: `${user.email}-again` },
      })
      planted.push(replacement.id)
      expect(replacement.id).not.toBe(user.id)
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
      // The partial unique index is on lower(email), so the lookup has to match it
      // or an address registered with capitals can never sign in again.
      const email = `MiXeD-${e2ePrefix()}@Test.Local`
      const identity = await auth.identities.create({ profile: { email, username: email } })
      planted.push(identity.id)
      await auth.passwords.set(identity.id, PASSWORD, stores.credentials)

      expect((await signIn(email.toLowerCase())).sid).toBeTruthy()
      expect((await signIn(email)).sid).toBeTruthy()
    })
  })
})
