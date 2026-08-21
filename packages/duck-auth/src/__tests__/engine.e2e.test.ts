/**
 * E2E: the whole engine on REAL Postgres and REAL Redis.
 *
 * Every other suite exercises one seam. This one wires an `AuthEngine` the way an
 * app does - drizzle/pg stores, a Redis limiter, a Redis idempotency store, the
 * cookie transport - and drives sign-in to sign-out through it.
 *
 * The two questions it exists to answer cannot be asked of a mock:
 *   - does the CSRF token handed out at sign-in still match the hash that is on
 *     the row when a later request is verified, after a JSON/SQL round trip?
 *   - does the auth guard, reading through the shipped queries, actually refuse a
 *     session whose row is gone?
 *
 * Skips when DUCKAUTH_E2E_DATABASE_URL or DUCKAUTH_E2E_REDIS_URL is unset;
 * `globalSetup` provisions both when docker is available.
 */
import Redis from 'ioredis'
import { Pool } from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { drizzlePgStorage } from '~/adapters/drizzle/pg'
import { verifyCsrf } from '~/core/csrf'
import { AuthEngine } from '~/core/engine'
import { redisIdempotency } from '~/core/idempotency'
import { RedisIdempotency } from '~/core/idempotency/idempotency.redis'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { RedisLimiter } from '~/limiters/redis'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { makeGuard } from '~/server/nestjs'
import { applyPgSchema, databaseUrl, dropPrefix, e2ePrefix, redisUrl } from '~/test/e2e-env'
import { toRedisLike } from '~/test/e2e-redis'

const PG_URL = databaseUrl()
const REDIS_URL = redisUrl()
const suite = PG_URL && REDIS_URL ? describe : describe.skip

type Profile = { username: string; email: string }

suite('E2E AuthEngine on real Postgres + Redis', () => {
  let pool: Pool
  let raw: Redis
  let prefix: string
  let auth: AuthEngine<Profile>
  let stores: ReturnType<typeof drizzlePgStorage<Profile>>

  /** Everything a Nest guard reads off the request, from a cookie header. */
  const requestFor = (cookie: string, method = 'GET') => ({
    headers: { cookie } as Record<string, string | string[] | undefined>,
    identity: null,
    method,
    session: null,
  })

  const ctxFor = (req: ReturnType<typeof requestFor>) => ({
    switchToHttp: () => ({ getRequest: <T>(): T => req as T }),
  })

  /**
   * The CSRF token only ever reaches a client on a Set-Cookie intent, so read it
   * the way the browser would rather than from a return value.
   */
  function csrfTokenFrom(intents: Array<{ type: string; name?: string; value?: string }>): string | undefined {
    return intents.find((i) => i.type === 'setCookie' && i.name === '__Host-duck-csrf')?.value
  }

  /** Every identity this suite plants, so afterAll can take them away again. */
  const planted: string[] = []

  async function signUp(email: string, password: string): Promise<string> {
    const identity = await auth.identities.create({ profile: { email, username: email } })
    await auth.passwords.set(identity.id, password, stores.credentials)
    planted.push(identity.id)
    return identity.id
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
      idempotency: redisIdempotency({ prefix, redis: toRedisLike(raw) }),
      limiter: new RedisLimiter({ max: 50, prefix, redis: toRedisLike(raw), windowMs: 60_000 }),
      providers: [],
      stores: {
        credentials: stores.credentials,
        identities: stores.identities,
        sessions: stores.sessions,
      },
      transport: new CookieTransport({ name: 'duck-sid', secure: false }),
    })
    auth.providers.register(passwords<Profile>({ hasher: new ScryptHasher({ keylen: 32, N: 1 << 10 }) }))
  }, 60_000)

  afterAll(async () => {
    if (raw) {
      await dropPrefix(raw, prefix)
      await raw.quit()
    }
    // This suite shares the default e2e database with the other pg suites, and
    // `.env.test` is documented as a way to point it at your own. Leaving rows
    // behind would make repeated local runs accumulate junk in someone's database.
    // The FK cascades, so removing the identity takes its sessions and credentials.
    if (pool && planted.length > 0) {
      await pool.query('DELETE FROM auth_identities WHERE id = ANY($1::uuid[])', [planted])
    }
    await pool?.end()
  })

  it('signs in, resolves the session, and signs out again', async () => {
    const email = `flow-${e2ePrefix()}@test.local`
    await signUp(email, 'correct-horse-battery')

    const { session, sid } = await auth.flows.signIn({
      input: { email, password: 'correct-horse-battery' },
      providerId: 'password',
    })
    expect(session?.identityId).toBeTruthy()

    const resolved = await auth.resolveSession({ headers: new Headers({ cookie: `duck-sid=${sid}` }) })
    expect(resolved?.identity?.profile.email).toBe(email)

    await auth.flows.signOut(sid)
    expect(await auth.resolveSession({ headers: new Headers({ cookie: `duck-sid=${sid}` }) })).toBeNull()
  })

  it('the CSRF token issued at sign-in verifies against the hash on the stored row', async () => {
    // The round trip a mock cannot cover: the hash goes into Postgres, comes back
    // through the adapter, and has to still match the token the client kept.
    const email = `csrf-${e2ePrefix()}@test.local`
    await signUp(email, 'correct-horse-battery')

    const { intents, session } = await auth.flows.signIn({
      input: { email, password: 'correct-horse-battery' },
      providerId: 'password',
    })
    const csrfToken = csrfTokenFrom(intents)
    expect(csrfToken).toBeTypeOf('string')

    const stored = await stores.sessions.getByHash(session?.id as string)
    expect(stored?.csrfHash).toBeTruthy()

    // Re-read from the database, not from the in-memory object we just minted.
    expect(() =>
      verifyCsrf({
        headers: new Headers({ 'x-csrf-token': csrfToken as string }),
        method: 'POST',
        sessionCsrfHash: stored?.csrfHash as string,
      }),
    ).not.toThrow()
  })

  it('a tampered CSRF token is refused against the stored hash', async () => {
    const email = `csrf-bad-${e2ePrefix()}@test.local`
    await signUp(email, 'correct-horse-battery')
    const { session } = await auth.flows.signIn({
      input: { email, password: 'correct-horse-battery' },
      providerId: 'password',
    })
    const stored = await stores.sessions.getByHash(session?.id as string)

    expect(() =>
      verifyCsrf({
        headers: new Headers({ 'x-csrf-token': 'not-the-token' }),
        method: 'POST',
        sessionCsrfHash: stored?.csrfHash as string,
      }),
    ).toThrow()
  })

  it('makeGuard admits a live session and populates the request', async () => {
    const email = `guard-${e2ePrefix()}@test.local`
    const identityId = await signUp(email, 'correct-horse-battery')
    const { sid } = await auth.flows.signIn({
      input: { email, password: 'correct-horse-battery' },
      providerId: 'password',
    })

    const req = requestFor(`duck-sid=${sid}`)
    expect(await makeGuard(auth as never).canActivate(ctxFor(req))).toBe(true)
    expect((req.session as { identityId?: string } | null)?.identityId).toBe(identityId)
  })

  it('makeGuard refuses once the session row is gone', async () => {
    const email = `guard-revoked-${e2ePrefix()}@test.local`
    await signUp(email, 'correct-horse-battery')
    const { sid } = await auth.flows.signIn({
      input: { email, password: 'correct-horse-battery' },
      providerId: 'password',
    })

    await auth.sessions.revoke(sid)

    await expect(makeGuard(auth as never).canActivate(ctxFor(requestFor(`duck-sid=${sid}`)))).rejects.toMatchObject({
      code: 'AUTH_UNAUTHENTICATED',
    })
  })

  it('credential-change revokes every other session for the identity', async () => {
    // The revocation that has to reach rows written by other requests, which is
    // exactly what an in-process store cannot put at risk.
    const email = `revoke-all-${e2ePrefix()}@test.local`
    const identityId = await signUp(email, 'correct-horse-battery')
    const first = await auth.flows.signIn({
      input: { email, password: 'correct-horse-battery' },
      providerId: 'password',
    })
    const second = await auth.flows.signIn({
      input: { email, password: 'correct-horse-battery' },
      providerId: 'password',
    })

    await auth.sessions.rotateOrCreate({
      aal: 1,
      factors: [],
      identityId,
      kind: 'user',
      purpose: 'credential-change',
    })

    expect(await auth.resolveSession({ headers: new Headers({ cookie: `duck-sid=${first.sid}` }) })).toBeNull()
    expect(await auth.resolveSession({ headers: new Headers({ cookie: `duck-sid=${second.sid}` }) })).toBeNull()
  })

  it('the Redis limiter throttles repeated failures for one identity', async () => {
    const email = `limit-${e2ePrefix()}@test.local`
    await signUp(email, 'correct-horse-battery')
    const attempt = () =>
      auth.flows
        .signIn({ input: { email, password: 'wrong-password' }, providerId: 'password' })
        .then(() => 'ok' as const)
        .catch((err: { code?: string }) => err.code ?? 'unknown')

    const codes: string[] = []
    for (let i = 0; i < 60; i++) codes.push(await attempt())

    expect(codes.every((c) => c !== 'ok')).toBe(true)
    expect(codes).toContain('AUTH_RATE_LIMITED')
  })
})
