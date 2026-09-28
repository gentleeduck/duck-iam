/** E2E: hostile and merely stupid input, against REAL Postgres and REAL Redis. */
import Redis from 'ioredis'
import { Pool } from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DrizzlePgAdapter } from '~/adapters/drizzle/pg'
import { valkeyAdapter } from '~/adapters/valkey'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { RedisLimiter } from '~/limiters/redis'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { applyPgSchema, databaseUrl, dropPrefix, e2ePrefix, redisUrl } from '~/test/e2e-env'

const PG_URL = databaseUrl()
const REDIS_URL = redisUrl()
const suite = PG_URL && REDIS_URL ? describe : describe.skip

type Profile = { username: string; email: string }
const PASSWORD = 'correct-horse-battery'

/** Strings chosen to break a parser, a query, or a column. */
const NASTY = {
  emoji: '🦆'.repeat(64),
  injection: `'; DROP TABLE auth_identities; --`,
  jsonBreaker: '{"a": "b"} }} \\" \\\\',
  nul: 'before\u0000after',
  rtl: 'admin‮gnp.exe',
  script: '<script>alert(1)</script>',
  zalgo: 'é́́́́́́́',
}

suite('E2E hostile input on real Postgres + Redis', () => {
  let pool: Pool
  let raw: Redis
  let prefix: string
  let auth: AuthEngine<Profile>
  let stores: DrizzlePgAdapter
  const planted: string[] = []

  const cookie = (sid: string) => ({ headers: new Headers({ cookie: `duck-sid=${sid}` }) })

  /** Create an identity, remembering it for cleanup. Returns null if the store refused. */
  async function tryCreate(profile: Profile & Record<string, unknown>): Promise<{ id: string } | null> {
    try {
      const identity = await auth.identities.create({ profile })
      planted.push(identity.id)
      return identity
    } catch {
      return null
    }
  }

  beforeAll(async () => {
    pool = new Pool({ connectionString: PG_URL })
    await applyPgSchema(pool)
    raw = new Redis(REDIS_URL, { lazyConnect: true, maxRetriesPerRequest: 2 })
    await raw.connect()
    prefix = e2ePrefix()
    stores = new DrizzlePgAdapter(PG_URL)
    auth = new AuthEngine<Profile>({
      baseUrl: 'https://app.test',
      limiter: new RedisLimiter({
        max: 5000,
        prefix,
        redis: valkeyAdapter(raw),
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

  describe('injection payloads are data, not code', () => {
    it('stores a DROP TABLE string verbatim and the table survives', async () => {
      const created = await tryCreate({ email: `inj-${e2ePrefix()}@x.com`, username: NASTY.injection })
      expect(created).not.toBeNull()

      const read = await stores.identities.find({ id: String(created?.id) })
      expect(read.profile).toMatchObject({ username: NASTY.injection })
      // If the payload had executed, this count would throw instead of answering.
      const { rows } = await pool.query('SELECT count(*)::int AS n FROM auth_identities')
      expect(rows[0].n).toBeGreaterThan(0)
    })

    it('survives an injection payload in the email lookup path', async () => {
      await expect(stores.identities.find({ email: NASTY.injection })).rejects.toMatchObject({
        code: 'AUTH_IDENTITY_NOT_FOUND',
      })
    })

    it('survives a payload that tries to break out of the json literal', async () => {
      const created = await tryCreate({ email: `json-${e2ePrefix()}@x.com`, username: NASTY.jsonBreaker })
      const read = await stores.identities.find({ id: String(created?.id) })
      expect(read.profile).toMatchObject({ username: NASTY.jsonBreaker })
    })

    it('survives a payload in a session id lookup', async () => {
      await expect(stores.sessions.getByHash(NASTY.injection)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    })
  })

  describe('prototype-pollution keys are treated as ordinary data', () => {
    it('a __proto__ key in the profile does not reach Object.prototype', async () => {
      const created = await tryCreate({
        __proto__: { polluted: true },
        email: `proto-${e2ePrefix()}@x.com`,
        username: `proto-${e2ePrefix()}`,
      })
      expect(created).not.toBeNull()
      expect(Reflect.get({}, 'polluted')).toBeUndefined()
    })

    it('a constructor key survives a round trip without becoming a constructor', async () => {
      const created = await tryCreate({
        constructor: 'not-a-function',
        email: `ctor-${e2ePrefix()}@x.com`,
        username: `ctor-${e2ePrefix()}`,
      })
      const read = await stores.identities.find({ id: String(created?.id) })
      expect(typeof read.profile).toBe('object')
    })
  })

  describe('unicode the column may not like', () => {
    it('round-trips four-byte emoji', async () => {
      const created = await tryCreate({ email: `emoji-${e2ePrefix()}@x.com`, username: NASTY.emoji })
      const read = await stores.identities.find({ id: String(created?.id) })
      expect(read.profile).toMatchObject({ username: NASTY.emoji })
    })

    it('round-trips combining marks without mangling them', async () => {
      const created = await tryCreate({ email: `zalgo-${e2ePrefix()}@x.com`, username: NASTY.zalgo })
      const read = await stores.identities.find({ id: String(created?.id) })
      expect(read.profile).toMatchObject({ username: NASTY.zalgo })
    })

    it('round-trips a right-to-left override, which display layers may render deceptively', async () => {
      const created = await tryCreate({ email: `rtl-${e2ePrefix()}@x.com`, username: NASTY.rtl })
      const read = await stores.identities.find({ id: String(created?.id) })
      expect(read.profile).toMatchObject({ username: NASTY.rtl })
    })

    it('a NUL byte in a username is refused as invalid input', async () => {
      // Postgres cannot store U+0000 in text or jsonb. The write is refused, and
      // the adapter names it rather than handing back a 500 with SQL in the
      // message: a username field that meets one now reads as a validation failure.
      await expect(
        auth.identities.create({
          profile: { email: `nul-${e2ePrefix()}@x.com`, username: NASTY.nul },
        }),
      ).rejects.toMatchObject({ code: 'AUTH_INVALID_PARAMETERS' })
    })

    it('caps an oversize profile at the facet, before the database sees it', async () => {
      // The facet enforces profileMaxBytes and throws a typed error. Worth pinning
      // next to the NUL case above: that one reaches the driver because it is a
      // shape the size cap does not describe, this one never leaves the process.
      await expect(
        auth.identities.create({
          profile: { email: `mb-${e2ePrefix()}@x.com`, username: 'x'.repeat(1_000_000) },
        }),
      ).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
    })

    it('the same oversize profile is left to the database when the store is called directly', async () => {
      // Only the facet has the cap. An app wiring `stores.identities` straight into
      // its own code, which the adapters make easy, gets the index limit instead.
      await expect(
        stores.identities.create({
          emailVerified: false,
          profile: { email: `mb2-${e2ePrefix()}@x.com`, username: 'x'.repeat(1_000_000) },
          providers: [],
        }),
      ).rejects.toMatchObject({ code: 'AUTH_INVALID_PARAMETERS' })
    })

    it('NFC and NFD spellings of one address are one account', async () => {
      // `lower()` folds case in every dialect and composition in none of them, so the address is
      // normalised on the way in. Without that the unique index sees two byte strings where a
      // human sees one name, and both rows exist.
      const tag = e2ePrefix()
      const nfc = `caf\u00e9-${tag}@x.com`
      const nfd = `cafe\u0301-${tag}@x.com`
      const first = await tryCreate({ email: nfc, username: `nfc-${tag}` })
      const second = await tryCreate({ email: nfd, username: `nfd-${tag}` })

      expect(first).not.toBeNull()
      expect(second).toBeNull()
    })

    it('finds the one account under either spelling', async () => {
      const tag = e2ePrefix()
      const created = await tryCreate({ email: `cafe\u0301-find-${tag}@x.com`, username: `find-${tag}` })

      expect((await auth.identities.getByEmail(`caf\u00e9-find-${tag}@x.com`)).id).toBe(created?.id)
      expect((await auth.identities.getByEmail(`cafe\u0301-find-${tag}@x.com`)).id).toBe(created?.id)
    })
  })

  describe('size limits', () => {
    it('caps ip and user agent on the session row however long the header was', async () => {
      const { session } = await auth.sessions.create({
        aal: 1,
        factors: [],
        identityId: null,
        ip: 'x'.repeat(10_000),
        kind: 'guest',
        userAgent: 'y'.repeat(10_000),
      })
      expect(session.ip?.length).toBe(64)
      expect(session.userAgent?.length).toBe(512)
    })

    it('caps the fingerprint too', async () => {
      const { session } = await auth.sessions.create({
        aal: 1,
        factors: [],
        fingerprint: 'z'.repeat(10_000),
        identityId: null,
        kind: 'guest',
      })
      expect(session.fingerprint?.length).toBe(256)
    })

    it('refuses an absurd sid rather than hashing it', async () => {
      await expect(auth.sessions.getBySid('s'.repeat(100_000))).rejects.toMatchObject({
        code: 'AUTH_INVALID_PARAMETERS',
      })
      await expect(auth.sessions.touch('s'.repeat(100_000))).rejects.toMatchObject({
        code: 'AUTH_INVALID_PARAMETERS',
      })
    })

    it('refuses more than sixteen factors', async () => {
      await expect(
        auth.sessions.create({
          aal: 1,
          factors: Array.from({ length: 17 }, () => ({ completedAt: new Date(), method: 'password' as const })),
          identityId: null,
          kind: 'guest',
        }),
      ).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
    })
  })

  describe('what the profile shape check does and does not cover', () => {
    // The shape check once asked only whether the keys were there, so any of these registered and then
    // answered to whatever `lower(profile->>'email')` stringified it to - 12345 became the address "12345".
    it.each([
      ['an empty email', ''],
      ['a numeric email', 12345],
      ['an array email', ['a@x.com']],
      ['an object email', { nested: true }],
    ])('refuses %s', async (label, email) => {
      await expect(
        // @ts-expect-error an email that is not a string
        auth.identities.create({ profile: { email, username: `${label}-${e2ePrefix()}` } }),
      ).rejects.toMatchObject({ code: 'AUTH_INVALID_PARAMETERS' })
    })

    it('a missing email is refused by the profile shape check, as a typed error', async () => {
      await expect(
        // @ts-expect-error no email at all
        auth.identities.create({ profile: { username: `noemail-${e2ePrefix()}` } }),
      ).rejects.toMatchObject({ code: 'AUTH_INVALID_PARAMETERS' })
    })

    it('deeply nested profile json survives a round trip', async () => {
      const deep: unknown = JSON.parse(`${'{"a":'.repeat(200)}1${'}'.repeat(200)}`)
      const created = await tryCreate({ deep, email: `deep-${e2ePrefix()}@x.com`, username: `deep-${e2ePrefix()}` })
      expect(created).not.toBeNull()
    })
  })

  describe('wrong types where a string was expected', () => {
    it('refuses a numeric sid', async () => {
      // @ts-expect-error not a string
      await expect(auth.sessions.getBySid(12345)).rejects.toMatchObject({
        code: 'AUTH_INVALID_PARAMETERS',
      })
    })

    it('refuses an array sid', async () => {
      // @ts-expect-error not a string
      await expect(auth.sessions.getBySid(['a', 'b'])).rejects.toMatchObject({
        code: 'AUTH_INVALID_PARAMETERS',
      })
    })

    it('refuses a null sid', async () => {
      // @ts-expect-error not a string
      await expect(auth.sessions.getBySid(null)).rejects.toMatchObject({
        code: 'AUTH_INVALID_PARAMETERS',
      })
    })

    it('refuses an object where a factor belongs', async () => {
      await expect(
        auth.sessions.create({
          aal: 1,
          // @ts-expect-error not a factor
          factors: [{ nonsense: true }],
          identityId: null,
          kind: 'guest',
        }),
      ).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
    })

    it('refuses a factor whose completedAt is a string', async () => {
      await expect(
        auth.sessions.create({
          aal: 1,
          // @ts-expect-error a string where the Date belongs
          factors: [{ completedAt: '2026-01-01', method: 'password' }],
          identityId: null,
          kind: 'guest',
        }),
      ).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
    })

    it('refuses factors that are not an array at all', async () => {
      await expect(
        auth.sessions.create({
          aal: 1,
          // @ts-expect-error not an array
          factors: 'password',
          identityId: null,
          kind: 'guest',
        }),
      ).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
    })
  })

  describe('empty and blank where a value was expected', () => {
    it('refuses an empty sid', async () => {
      // An empty sid is a malformed argument, not a session that is missing.
      await expect(auth.sessions.getBySid('')).rejects.toMatchObject({ code: 'AUTH_INVALID_PARAMETERS' })
      await expect(auth.sessions.touch('')).rejects.toMatchObject({ code: 'AUTH_INVALID_PARAMETERS' })
    })

    it('refuses an empty password at sign-in', async () => {
      const tag = `blank-${e2ePrefix()}`
      const identity = await tryCreate({ email: `${tag}@x.com`, username: tag })
      await auth.passwords.set(String(identity?.id), PASSWORD, stores.credentials)

      await expect(
        auth.flows.signIn({ input: { email: `${tag}@x.com`, password: '' }, providerId: 'password' }),
      ).rejects.toBeTruthy()
    })

    it('does not match an account with a whitespace-only address', async () => {
      await expect(stores.identities.find({ email: '   ' })).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
    })
  })

  describe('the limiter under a stampede', () => {
    it('never admits more than the configured budget, however many arrive at once', async () => {
      const limiter = new RedisLimiter({
        max: 7,
        prefix: `${prefix}:stampede`,
        redis: valkeyAdapter(raw),
        windowMs: 60_000,
      })
      const key = `hammer-${e2ePrefix()}`
      const results = await Promise.all(Array.from({ length: 200 }, () => limiter.consume(key)))
      expect(results.filter((r) => r.ok)).toHaveLength(7)
    })

    it('a hostile key does not escape its own bucket', async () => {
      const limiter = new RedisLimiter({
        max: 1,
        prefix: `${prefix}:esc`,
        redis: valkeyAdapter(raw),
        windowMs: 60_000,
      })
      // A key containing the separator must not collide with another bucket.
      await limiter.consume('a:b')
      expect((await limiter.consume('a:b')).ok).toBe(false)
      expect((await limiter.consume('a')).ok).toBe(true)
    })

    it('refuses an absurdly long key instead of hashing it', async () => {
      const limiter = new RedisLimiter({
        max: 5,
        prefix: `${prefix}:big`,
        redis: valkeyAdapter(raw),
        windowMs: 60_000,
      })
      expect((await limiter.consume('k'.repeat(5000))).ok).toBe(false)
    })
  })

  describe('sessions under concurrent abuse', () => {
    it('a hundred simultaneous guest sessions all get distinct identifiers', async () => {
      const created = await Promise.all(Array.from({ length: 100 }, () => auth.sessions.createGuest()))
      expect(new Set(created.map((c) => c.sid)).size).toBe(100)
      expect(new Set(created.map((c) => c.session.id)).size).toBe(100)
    })

    it('repeated revocation of the same session is harmless', async () => {
      const guest = await auth.sessions.createGuest()
      // Exactly one of the ten finds the row; the nine that lose read their rejection as the no-op it is.
      await Promise.all(Array.from({ length: 10 }, () => auth.sessions.revoke(guest.sid).orNull()))
      await expect(auth.resolveSession(cookie(guest.sid))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    })

    it('revoking a session that never existed rejects, and orNull reads that as null', async () => {
      // Still not a silent success: `orNull` is how a revocation that matched nothing says so.
      const ghost = `ghost-${e2ePrefix()}`
      await expect(auth.sessions.revoke(ghost)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
      await expect(auth.sessions.revoke(ghost).orNull()).resolves.toBeNull()
    })

    it('touching a revoked session does not resurrect it', async () => {
      const guest = await auth.sessions.createGuest()
      await auth.sessions.revoke(guest.sid)
      await expect(auth.sessions.touch(guest.sid)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
      await expect(stores.sessions.getByHash(guest.session.id)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    })
  })

  describe('cookies a browser would never send', () => {
    it('ignores a malformed cookie header', async () => {
      await expect(
        auth.resolveSession({ headers: new Headers({ cookie: 'not=a=valid; ;; ===' }) }),
      ).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    })

    it('ignores a cookie header with no separator at all', async () => {
      await expect(auth.resolveSession({ headers: new Headers({ cookie: 'duck-sid' }) })).rejects.toMatchObject({
        code: 'AUTH_SESSION_REVOKED',
      })
    })

    it('ignores a session cookie carrying an injection payload', async () => {
      await expect(
        auth.resolveSession({ headers: new Headers({ cookie: `duck-sid=${NASTY.injection}` }) }),
      ).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    })

    it('ignores a request with no cookie header', async () => {
      await expect(auth.resolveSession({ headers: new Headers() })).rejects.toMatchObject({
        code: 'AUTH_SESSION_REVOKED',
      })
    })
  })
})
