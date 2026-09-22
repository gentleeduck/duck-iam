/** E2E: the session rules that only mean anything against a real store. */
import Redis from 'ioredis'
import { Pool } from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DrizzlePgAdapter } from '~/adapters/drizzle/pg'
import { type ValkeyClient, valkeyAdapter } from '~/adapters/valkey'
import { AuthEngine } from '~/core/engine'
import { redisIdempotency } from '~/core/idempotency'
import { RedisIdempotency } from '~/core/idempotency/idempotency.redis'
import { resolveBySid } from '~/core/sessions'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { RedisLimiter } from '~/limiters/redis'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { applyPgSchema, databaseUrl, dropPrefix, e2ePrefix, redisUrl } from '~/test/e2e-env'

const PG_URL = databaseUrl()
const REDIS_URL = redisUrl()
const suite = PG_URL && REDIS_URL ? describe : describe.skip

type Profile = { username: string; email: string }
const PASSWORD = 'correct-horse-battery'

suite('E2E session security rules on real Postgres + Redis', () => {
  let pool: Pool
  let raw: Redis
  let prefix: string
  let auth: AuthEngine<Profile>
  let stores: DrizzlePgAdapter
  const planted: string[] = []

  const cookie = (sid: string) => ({ headers: new Headers({ cookie: `duck-sid=${sid}` }) })

  /** `signIn` types `session` as nullable; a successful sign-in always has one. */
  function rowId(result: { session: { id: string } | null }): string {
    if (!result.session) throw new Error('expected a session on a successful sign-in')
    return result.session.id
  }

  /**
   * Idle a session out. `created_at` moves too because Postgres enforces
   * `expires_at >= created_at`; backdating only the expiry is rejected by the
   * schema rather than producing the expired row the test wants.
   */
  const idledOut = () => ({
    absoluteExpiresAt: new Date(Date.now() + 86_400_000),
    createdAt: new Date(Date.now() - 120_000),
    expiresAt: new Date(Date.now() - 1000),
    rotatedAt: new Date(Date.now() - 120_000),
  })

  async function newUser(label: string): Promise<{ id: string; email: string }> {
    const email = `${label}-${e2ePrefix()}@test.local`
    const identity = await auth.identities.create({ profile: { email, username: email } })
    await auth.passwords.set(identity.id, PASSWORD, stores.credentials)
    planted.push(identity.id)
    return { email, id: identity.id }
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
        max: 200,
        prefix,
        redis: valkeyAdapter(raw as unknown as ValkeyClient.Me),
        windowMs: 60_000,
      }),
      stores: { credentials: stores.credentials, identities: stores.identities, sessions: stores.sessions },
      transport: new CookieTransport({ name: 'duck-sid', secure: false }),
    })
    auth.providers.register(passwords<Profile>({ hasher: new ScryptHasher({ keylen: 32, N: 1 << 10 }) }))
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

  describe('session fixation: the identifier changes on every privilege change', () => {
    it('signing in from a guest session issues a new sid and kills the old one', async () => {
      // The fixation attack: an attacker plants a known guest sid, the victim signs
      // in, and the attacker's sid is now authenticated. The old row has to go.
      const user = await newUser('fixation')
      const guest = await auth.sessions.createGuest()

      const signedIn = await auth.flows.signIn({
        input: { email: user.email, password: PASSWORD },
        previousSid: guest.sid,
        providerId: 'password',
      })

      expect(signedIn.sid).not.toBe(guest.sid)
      await expect(auth.resolveSession(cookie(guest.sid))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
      expect((await auth.resolveSession(cookie(signedIn.sid))).identity?.id).toBe(user.id)
    })

    it('promoteGuest carries no identifier across the boundary', async () => {
      const user = await newUser('promote')
      const guest = await auth.sessions.createGuest()

      const promoted = await auth.sessions.promoteGuest({
        aal: 1,
        factors: [{ completedAt: new Date(), method: 'password' }],
        guestSid: guest.sid,
        identityId: user.id,
      })

      expect(promoted.sid).not.toBe(guest.sid)
      await expect(stores.sessions.getByHash(guest.session.id)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
      expect(promoted.session.kind).toBe('user')
    })

    it('a step-up issues a new sid rather than upgrading the old one in place', async () => {
      const user = await newUser('stepup')
      const first = await auth.flows.signIn({
        input: { email: user.email, password: PASSWORD },
        providerId: 'password',
      })

      const stepped = await auth.sessions.rotateOrCreate({
        aal: 2,
        factors: [
          { completedAt: new Date(), method: 'password' },
          { completedAt: new Date(), method: 'totp' },
        ],
        identityId: user.id,
        kind: 'user',
        previousSid: first.sid,
        purpose: 'step-up',
      })

      expect(stepped.sid).not.toBe(first.sid)
      expect(stepped.session.aal).toBe(2)
      // The old sid survives a step-up by design, but demoted: still readable, no
      // longer fresh, and still at the lower AAL.
      const old = await auth.resolveSession(cookie(first.sid))
      expect(old?.session.fresh).toBe(false)
      expect(old?.session.aal).toBe(1)
    })

    it('a re-auth replaces the identifier outright', async () => {
      const user = await newUser('reauth')
      const first = await auth.flows.signIn({
        input: { email: user.email, password: PASSWORD },
        providerId: 'password',
      })
      const second = await auth.flows.signIn({
        input: { email: user.email, password: PASSWORD },
        previousSid: first.sid,
        providerId: 'password',
      })

      expect(second.sid).not.toBe(first.sid)
      await expect(auth.resolveSession(cookie(first.sid))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    })

    it('every sign-in produces a distinct identifier', async () => {
      const user = await newUser('distinct')
      const sids = new Set<string>()
      for (let i = 0; i < 5; i++) {
        const s = await auth.flows.signIn({
          input: { email: user.email, password: PASSWORD },
          providerId: 'password',
        })
        sids.add(s.sid)
      }
      expect(sids.size).toBe(5)
    })
  })

  describe('idle and absolute timeouts are two separate deadlines', () => {
    it('a session past its idle deadline is refused and the row is deleted', async () => {
      const user = await newUser('idle')
      const signedIn = await auth.flows.signIn({
        input: { email: user.email, password: PASSWORD },
        providerId: 'password',
      })
      // Idle out, but leave the absolute cap far in the future: only the sliding
      // deadline has passed, and it alone must be enough.
      await stores.sessions.update(rowId(signedIn), idledOut())

      await expect(auth.resolveSession(cookie(signedIn.sid))).rejects.toMatchObject({ code: 'AUTH_SESSION_EXPIRED' })
      await expect(stores.sessions.getByHash(rowId(signedIn))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    })

    it('the schema refuses a row whose absolute cap precedes its sliding expiry', async () => {
      // `chk_auth_sessions_absolute_expires_after_expires`. It means the two
      // deadlines can never invert: the hard cap always lands at or after the idle
      // one, so "absolute passed while still idle-fresh" is not a reachable state.
      const user = await newUser('invert')
      const signedIn = await auth.flows.signIn({
        input: { email: user.email, password: PASSWORD },
        providerId: 'password',
      })
      await expect(
        stores.sessions.update(rowId(signedIn), {
          absoluteExpiresAt: new Date(Date.now() - 1000),
          createdAt: new Date(Date.now() - 120_000),
          expiresAt: new Date(Date.now() + 86_400_000),
          rotatedAt: new Date(Date.now() - 120_000),
        }),
      ).rejects.toMatchObject({ code: 'AUTH_INVALID_PARAMETERS' })
    })

    it('a session at its absolute cap is refused and the row is deleted', async () => {
      const user = await newUser('absolute')
      const signedIn = await auth.flows.signIn({
        input: { email: user.email, password: PASSWORD },
        providerId: 'password',
      })
      // One clock read for both deadlines. Taken separately they straddle a
      // millisecond tick often enough to matter, and `absoluteExpiresAt` landing
      // 1ms before `expiresAt` trips chk_auth_sessions_absolute_expires_after_expires
      // - the write fails for the wrong reason and the test reads as a product bug.
      const past = Date.now() - 1000
      await stores.sessions.update(rowId(signedIn), {
        absoluteExpiresAt: new Date(past),
        createdAt: new Date(past - 119_000),
        expiresAt: new Date(past),
        rotatedAt: new Date(past - 119_000),
      })

      await expect(auth.resolveSession(cookie(signedIn.sid))).rejects.toMatchObject({ code: 'AUTH_SESSION_EXPIRED' })
      await expect(stores.sessions.getByHash(rowId(signedIn))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    })

    it('touch() will not revive a session that idled out', async () => {
      const user = await newUser('revive')
      const signedIn = await auth.flows.signIn({
        input: { email: user.email, password: PASSWORD },
        providerId: 'password',
      })
      await stores.sessions.update(rowId(signedIn), idledOut())

      await expect(auth.sessions.touch(signedIn.sid)).rejects.toMatchObject({ code: 'AUTH_SESSION_EXPIRED' })
      await expect(stores.sessions.getByHash(rowId(signedIn))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    })

    it('touch() never pushes the idle deadline past the absolute cap', async () => {
      const user = await newUser('cap')
      const signedIn = await auth.flows.signIn({
        input: { email: user.email, password: PASSWORD },
        providerId: 'password',
      })
      const cap = new Date(Date.now() + 5_000)
      await stores.sessions.update(rowId(signedIn), {
        absoluteExpiresAt: cap,
        createdAt: new Date(Date.now() - 60_000),
        // Kept under the cap: the schema refuses expires_at above it.
        expiresAt: cap,
        rotatedAt: new Date(Date.now() - 60_000),
      })

      const touched = await auth.sessions.touch(signedIn.sid)
      expect(touched.expiresAt.getTime()).toBeLessThanOrEqual(cap.getTime())
    })

    it('gc removes the idled-out rows and leaves the live ones', async () => {
      const user = await newUser('gc')
      const dead = await auth.flows.signIn({
        input: { email: user.email, password: PASSWORD },
        providerId: 'password',
      })
      const live = await auth.flows.signIn({
        input: { email: user.email, password: PASSWORD },
        providerId: 'password',
      })
      // Same single clock read as above, for the same constraint.
      const past = Date.now() - 1
      await stores.sessions.update(rowId(dead), {
        absoluteExpiresAt: new Date(past),
        createdAt: new Date(past - 120_000),
        expiresAt: new Date(past),
        rotatedAt: new Date(past - 120_000),
      })

      await auth.sessions.gc()
      await expect(stores.sessions.getByHash(rowId(dead))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
      await expect(stores.sessions.getByHash(rowId(live))).resolves.toBeTruthy()
    })
  })

  describe('revocation reaches the row, not just the cache', () => {
    it('signing out deletes the row rather than marking it', async () => {
      const user = await newUser('signout')
      const signedIn = await auth.flows.signIn({
        input: { email: user.email, password: PASSWORD },
        providerId: 'password',
      })
      await auth.flows.signOut(signedIn.sid)
      await expect(stores.sessions.getByHash(rowId(signedIn))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    })

    it('revokeAllForIdentity clears every device and spares other users', async () => {
      const victim = await newUser('victim')
      const bystander = await newUser('bystander')
      const a = await auth.flows.signIn({ input: { email: victim.email, password: PASSWORD }, providerId: 'password' })
      const b = await auth.flows.signIn({ input: { email: victim.email, password: PASSWORD }, providerId: 'password' })
      const other = await auth.flows.signIn({
        input: { email: bystander.email, password: PASSWORD },
        providerId: 'password',
      })

      await auth.sessions.revokeAllForIdentity(victim.id)

      await expect(auth.resolveSession(cookie(a.sid))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
      await expect(auth.resolveSession(cookie(b.sid))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
      await expect(auth.resolveSession(cookie(other.sid))).resolves.toBeDefined()
    })

    it('erasing the identity takes its sessions with it, via the foreign key', async () => {
      // On Postgres `ON DELETE CASCADE` removes the session rows outright, so the
      // dangling-row case the facet throws AUTH_SESSION_REVOKED for cannot arise
      // here at all. Soft delete is the path that produces it, covered below.
      const user = await newUser('erased')
      const signedIn = await auth.flows.signIn({
        input: { email: user.email, password: PASSWORD },
        providerId: 'password',
      })
      await stores.identities.erase(user.id)

      await expect(stores.sessions.getByHash(rowId(signedIn))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
      await expect(resolveBySid(signedIn.sid, stores.sessions, stores.identities)).rejects.toMatchObject({
        code: 'AUTH_SESSION_REVOKED',
      })
    })

    it('a soft-deleted identity stops resolving without erasing the row', async () => {
      const user = await newUser('soft')
      const signedIn = await auth.flows.signIn({
        input: { email: user.email, password: PASSWORD },
        providerId: 'password',
      })
      await stores.identities.softDelete(user.id, 60_000)

      // The row is still there, so this is the erasure code and not absence - and it stays outside the
      // absent set so a caller reading it through `orNull()` cannot mistake it for a sign-out.
      await expect(resolveBySid(signedIn.sid, stores.sessions, stores.identities)).rejects.toMatchObject({
        code: 'AUTH_SESSION_IDENTITY_ERASED',
      })
    })
  })

  describe('impersonation is bounded', () => {
    it('stops resolving once the actingAs window closes', async () => {
      const admin = await newUser('admin')
      const target = await newUser('target')
      const impersonation = await auth.sessions.rotateOrCreate({
        aal: 2,
        actingAs: {
          expiresAt: new Date(Date.now() + 60_000),
          realIdentityId: admin.id,
          reason: 'support-ticket-1',
          startedAt: new Date(),
        },
        factors: [{ completedAt: new Date(), method: 'password' }],
        identityId: target.id,
        kind: 'user',
        purpose: 'impersonate-start',
      })

      expect((await auth.resolveSession(cookie(impersonation.sid))).session.actingAs?.realIdentityId).toBe(admin.id)

      // Close the window; the session row itself is still well inside its own TTL.
      await stores.sessions.update(impersonation.session.id, {
        actingAs: {
          expiresAt: new Date(Date.now() - 1000),
          realIdentityId: admin.id,
          reason: 'support-ticket-1',
          startedAt: new Date(Date.now() - 60_000),
        },
      })

      await expect(auth.resolveSession(cookie(impersonation.sid))).rejects.toMatchObject({
        code: 'AUTH_SESSION_REVOKED',
      })
    })

    it('leaves the admin’s own session untouched', async () => {
      const admin = await newUser('admin-keeps')
      const target = await newUser('target-keeps')
      const adminSession = await auth.flows.signIn({
        input: { email: admin.email, password: PASSWORD },
        providerId: 'password',
      })

      await auth.sessions.rotateOrCreate({
        aal: 2,
        actingAs: {
          expiresAt: new Date(Date.now() + 60_000),
          realIdentityId: admin.id,
          reason: 'support-ticket-2',
          startedAt: new Date(),
        },
        factors: [{ completedAt: new Date(), method: 'password' }],
        identityId: target.id,
        kind: 'user',
        previousSid: adminSession.sid,
        purpose: 'impersonate-start',
      })

      await expect(auth.resolveSession(cookie(adminSession.sid))).resolves.toBeDefined()
    })
  })

  describe('tenant scoping', () => {
    it('refuses a session belonging to another tenant', async () => {
      const user = await newUser('tenant')
      const scoped = await auth.sessions.create({
        aal: 1,
        factors: [{ completedAt: new Date(), method: 'password' }],
        identityId: user.id,
        kind: 'user',
        tenantId: 'tenant-a',
      })

      expect((await auth.resolveSession(cookie(scoped.sid), { expectedTenantId: 'tenant-a' })).session.tenantId).toBe(
        'tenant-a',
      )
      await expect(auth.resolveSession(cookie(scoped.sid), { expectedTenantId: 'tenant-b' })).rejects.toMatchObject({
        code: 'AUTH_SESSION_REVOKED',
      })
    })
  })

  describe('concurrency', () => {
    it('parallel sign-ins for one identity all resolve independently', async () => {
      const user = await newUser('parallel')
      const results = await Promise.all(
        Array.from({ length: 5 }, () =>
          auth.flows.signIn({ input: { email: user.email, password: PASSWORD }, providerId: 'password' }),
        ),
      )
      const sids = results.map((r) => r.sid)
      expect(new Set(sids).size).toBe(5)
      for (const sid of sids) {
        await expect(auth.resolveSession(cookie(sid))).resolves.toBeDefined()
      }
    })

    it('a credential-change during concurrent activity leaves nothing resolvable', async () => {
      const user = await newUser('credchange')
      const sessions = await Promise.all(
        Array.from({ length: 5 }, () =>
          auth.flows.signIn({ input: { email: user.email, password: PASSWORD }, providerId: 'password' }),
        ),
      )

      await auth.sessions.rotateOrCreate({
        aal: 1,
        factors: [],
        identityId: user.id,
        kind: 'user',
        purpose: 'credential-change',
      })

      for (const s of sessions) {
        await expect(auth.resolveSession(cookie(s.sid))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
      }
    })
  })
})
