/** E2E: passkeys and WebAuthn MFA against REAL Postgres, signed by a software authenticator and checked by the
 *  real `@simplewebauthn/server` verifier. */
import { randomBytes } from 'node:crypto'
import { Pool } from 'pg'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { DrizzlePgAdapter } from '~/adapters/drizzle/pg'
import { orNull } from '~/core/answer'
import { AuthEngine } from '~/core/engine'
import { InMemoryEvents } from '~/core/events'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { MfaImpl } from '~/providers/mfa/mfa'
import { DEFAULT_MFA_CONFIG } from '~/providers/mfa/mfa.constants'
import { applyPgSchema, databaseUrl, e2ePrefix } from '~/test/e2e-env'
import { type SoftAuthenticator, softAuthenticator } from '~/test/soft-authenticator'
import {
  AuthMemoryPasskeyChallengeStore,
  beginPasskeyRegistration,
  completePasskeyRegistration,
  passkey,
} from '../index'
import type { Passkey } from '../passkey.types'

const PG_URL = databaseUrl()
const suite = PG_URL ? describe : describe.skip

type Profile = { username: string; email: string }

const key = (id?: string): SoftAuthenticator => softAuthenticator('app.test', 'https://app.test', { id })

suite('E2E passkeys on real Postgres, with the real verifier', () => {
  let pool: Pool
  let stores: DrizzlePgAdapter
  let auth: AuthEngine<Profile>
  let opts: Passkey.Options
  let mfa: MfaImpl
  let challenge = ''
  const challenges = new AuthMemoryPasskeyChallengeStore()
  const events = new InMemoryEvents()
  const seen: unknown[] = []
  const planted: string[] = []

  async function newUser(label: string): Promise<{ id: string; email: string }> {
    const tag = `${label}-${e2ePrefix()}`
    const email = `${tag}@test.local`
    const identity = await auth.identities.create({ profile: { email, username: tag } })
    planted.push(identity.id)
    return { email, id: identity.id }
  }

  async function register(identityId: string, authenticator: SoftAuthenticator): Promise<string> {
    const input = { credentialStore: stores.credentials, identityId, sessionId: `reg-${e2ePrefix()}`, tenant: {} }
    await beginPasskeyRegistration(opts, { ...input, userName: identityId })
    return completePasskeyRegistration(opts, { ...input, response: authenticator.register(challenge) })
  }

  async function signIn(
    email: string,
    authenticator: SoftAuthenticator,
    count: number,
    opts?: { forged?: boolean; verified?: boolean },
  ) {
    const sessionId = `login-${e2ePrefix()}`
    await auth.flows.beginProvider('passkey', { email, sessionId })
    const response = authenticator.assert(challenge, count, opts)
    return auth.flows.signIn({ input: { email, response, sessionId }, providerId: 'passkey' })
  }

  async function enrollMfa(identityId: string, authenticator: SoftAuthenticator): Promise<{ credentialId: string }> {
    const common = {
      challengeKey: `mfa-${e2ePrefix()}`,
      challengeStore: challenges,
      expectedOrigins: 'https://app.test',
    }
    const options = await mfa.beginWebauthnMfaEnrollment(identityId, {
      ...common,
      rpID: 'app.test',
      rpName: 'Test App',
      userName: identityId,
    })
    return mfa.confirmWebauthnMfaEnrollment(identityId, {
      ...common,
      response: authenticator.register(options.challenge),
      rpID: 'app.test',
    })
  }

  async function verifyMfa(identityId: string, authenticator: SoftAuthenticator, count: number): Promise<boolean> {
    const common = { challengeKey: `mfa-${e2ePrefix()}`, challengeStore: challenges, rpID: 'app.test' }
    const options = await mfa.beginWebauthnMfaVerify(identityId, common)
    return mfa.verifyWebauthnMfa(identityId, {
      ...common,
      expectedOrigins: 'https://app.test',
      response: authenticator.assert(options.challenge, count),
    })
  }

  beforeAll(async () => {
    pool = new Pool({ connectionString: PG_URL })
    await applyPgSchema(pool)
    stores = new DrizzlePgAdapter(PG_URL)
    opts = {
      challengeStore: {
        put: (k, value, ttlMs) => {
          challenge = value
          return challenges.put(k, value, ttlMs)
        },
        take: (k) => challenges.take(k),
      },
      expectedOrigins: 'https://app.test',
      findIdentityByEmail: async (email) => orNull(stores.identities.find({ email })),
      rpID: 'app.test',
      rpName: 'Test App',
    }
    auth = new AuthEngine<Profile>({
      baseUrl: 'https://app.test',
      events,
      limiter: new MemoryLimiter({ max: 5000, windowMs: 60_000 }),
      stores: { credentials: stores.credentials, identities: stores.identities, sessions: stores.sessions },
      transport: new CookieTransport({ name: 'duck-sid', secure: false }),
    })
    auth.providers.register(passkey<Profile>(opts))
    mfa = new MfaImpl(stores.credentials, events, DEFAULT_MFA_CONFIG)
    events.on('suspicious', (payload) => {
      seen.push(payload)
    })
  }, 60_000)

  beforeEach(() => {
    seen.length = 0
  })

  afterAll(async () => {
    if (pool && planted.length > 0) {
      await pool.query('DELETE FROM auth_identities WHERE id = ANY($1::uuid[])', [planted])
    }
    await pool?.end()
  })

  describe('passkey sign-in', () => {
    it('signs the owner in and records the count on the row', async () => {
      const user = await newUser('pk-happy')
      const authenticator = key()
      await register(user.id, authenticator)

      expect((await signIn(user.email, authenticator, 7)).session?.identityId).toBe(user.id)
      const [row] = await stores.credentials.listByIdentity(user.id, 'passkey', {})
      expect(row?.metadata).toMatchObject({ counter: 7 })
    })

    it('refuses a signed count that went backwards, and reports it', async () => {
      const user = await newUser('pk-rollback')
      const authenticator = key()
      await register(user.id, authenticator)
      await signIn(user.email, authenticator, 7)

      await expect(signIn(user.email, authenticator, 3)).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
      expect(seen).toEqual([
        expect.objectContaining({
          identityId: user.id,
          meta: expect.objectContaining({ newCounter: 3, oldCounter: 7 }),
        }),
      ])
    })

    it('refuses a forged assertion without reporting or recording it', async () => {
      const user = await newUser('pk-forged')
      const authenticator = key()
      await register(user.id, authenticator)
      await signIn(user.email, authenticator, 7)

      const forged = { forged: true }
      await expect(signIn(user.email, authenticator, 3, forged)).rejects.toMatchObject({
        code: 'AUTH_PASSKEY_MISMATCH',
      })
      await expect(signIn(user.email, authenticator, 90, forged)).rejects.toMatchObject({
        code: 'AUTH_PASSKEY_MISMATCH',
      })
      expect(seen).toEqual([])
      expect((await signIn(user.email, authenticator, 8)).session?.identityId).toBe(user.id)
    })

    it('opens an AAL 1 session on presence alone, which a step-up to AAL 2 refuses', async () => {
      const user = await newUser('pk-presence')
      const authenticator = key()
      await register(user.id, authenticator)

      expect((await signIn(user.email, authenticator, 1)).session?.aal).toBe(2)
      const { session } = await signIn(user.email, authenticator, 2, { verified: false })
      if (!session) throw new Error('presence alone opened no session')
      expect(session).toMatchObject({ aal: 1, identityId: user.id })
      expect(await auth.flows.checkStepUp(session, { aal: 2 })).toMatchObject({ satisfied: false })
    })

    it('refuses a credential id another account registered, so its owner still signs in', async () => {
      const owner = await newUser('pk-owner')
      const other = await newUser('pk-other')
      const authenticator = key()
      await register(owner.id, authenticator)

      await expect(register(other.id, key(authenticator.id))).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
      await expect(register(other.id, key())).resolves.toBeTruthy()
      expect((await signIn(owner.email, authenticator, 1)).session?.identityId).toBe(owner.id)
    })

    it('refuses a null or missing response as a mismatch, then signs the owner in', async () => {
      const user = await newUser('pk-no-response')
      const authenticator = key()
      await register(user.id, authenticator)
      for (const response of [null, undefined]) {
        const sessionId = `login-${e2ePrefix()}`
        await auth.flows.beginProvider('passkey', { email: user.email, sessionId })
        await expect(
          auth.flows.signIn({ input: { email: user.email, response, sessionId }, providerId: 'passkey' }),
        ).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
      }
      expect((await signIn(user.email, authenticator, 1)).session?.identityId).toBe(user.id)
    })

    it('stores a credential id of 1023 bytes, which then signs in, and refuses one of 1024 without a row', async () => {
      const user = await newUser('pk-long-id')
      await expect(register(user.id, key(randomBytes(1024).toString('base64url')))).rejects.toMatchObject({
        code: 'AUTH_PASSKEY_MISMATCH',
      })
      expect(await stores.credentials.listByIdentity(user.id, 'passkey', {})).toEqual([])
      const longest = key(randomBytes(1023).toString('base64url'))
      await register(user.id, longest)
      expect((await signIn(user.email, longest, 1)).session?.identityId).toBe(user.id)
    })

    it('refuses a key under an algorithm registration did not offer, and writes no row', async () => {
      const user = await newUser('pk-alg')
      const es512 = softAuthenticator('app.test', 'https://app.test', { curve: 'P-521' })
      await expect(register(user.id, es512)).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
      expect(await stores.credentials.listByIdentity(user.id, 'passkey', {})).toEqual([])
      await register(user.id, key())
      expect(await stores.credentials.listByIdentity(user.id, 'passkey', {})).toHaveLength(1)
    })
  })

  describe('WebAuthn MFA', () => {
    it('verifies the enrolled key, and refuses a signed rollback with a report', async () => {
      const user = await newUser('wa-mfa')
      const authenticator = key()
      await enrollMfa(user.id, authenticator)

      expect(await verifyMfa(user.id, authenticator, 4)).toBe(true)
      expect(await verifyMfa(user.id, authenticator, 2)).toBe(false)
      expect(seen).toEqual([expect.objectContaining({ identityId: user.id, signal: 'webauthn-mfa-counter-rollback' })])
      expect(await verifyMfa(user.id, authenticator, 5)).toBe(true)
    })

    it('refuses a credential id another identity enrolled, so its owner keeps the factor', async () => {
      const owner = await newUser('wa-owner')
      const other = await newUser('wa-other')
      const authenticator = key()
      await enrollMfa(owner.id, authenticator)

      await expect(enrollMfa(other.id, key(authenticator.id))).rejects.toMatchObject({ code: 'AUTH_PASSKEY_MISMATCH' })
      await expect(enrollMfa(other.id, key())).resolves.toBeDefined()
      expect(await verifyMfa(owner.id, authenticator, 1)).toBe(true)
    })

    it('enrolls a credential id of 1023 bytes, which then verifies, and refuses one of 1024', async () => {
      const user = await newUser('wa-long-id')
      await expect(enrollMfa(user.id, key(randomBytes(1024).toString('base64url')))).rejects.toMatchObject({
        code: 'AUTH_PASSKEY_MISMATCH',
      })
      const longest = key(randomBytes(1023).toString('base64url'))
      await enrollMfa(user.id, longest)
      expect(await verifyMfa(user.id, longest, 1)).toBe(true)
    })
  })
})
