/**
 * E2E: values that are the right type and the wrong thing entirely.
 *
 * `hostile-input` throws malformed data at the stores. This one sends values that
 * parse fine and pass every type check, and asks whether anything is actually
 * looking at them: an AAL of nine, a session kind nobody defined, an impersonation
 * window that closed before it opened, a rate-limit weight of minus five, a
 * redirect target of `javascript:alert(1)`.
 *
 * Nothing here is repaired. Cases named FINDING pin behaviour that is wrong or
 * surprising, so it is written down rather than rediscovered.
 *
 * Skips when DUCKAUTH_E2E_DATABASE_URL or DUCKAUTH_E2E_REDIS_URL is unset;
 * `globalSetup` provisions both when docker is available.
 */
import { Buffer } from 'node:buffer'
import { createHmac } from 'node:crypto'
import Redis from 'ioredis'
import { Pool } from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { drizzlePgStorage } from '~/adapters/drizzle/pg'
import { MemoryAdapter } from '~/adapters/memory'
import { type ValkeyClient, valkeyAdapter } from '~/adapters/valkey'
import { AuthEngine } from '~/core/engine'
import { RedisIdempotency } from '~/core/idempotency/idempotency.redis'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { RedisLimiter } from '~/limiters/redis'
import { createOidcOP, type OidcOpRoot } from '~/oidc/op'
import { applyPgSchema, databaseUrl, dropPrefix, e2ePrefix, redisUrl } from '~/test/e2e-env'

const PG_URL = databaseUrl()
const REDIS_URL = redisUrl()
const suite = PG_URL && REDIS_URL ? describe : describe.skip

type Profile = { username: string; email: string }

suite('E2E hostile values on real Postgres + Redis', () => {
  let pool: Pool
  let raw: Redis
  let prefix: string
  let auth: AuthEngine<Profile>
  let stores: ReturnType<typeof drizzlePgStorage<Profile>>
  let op: OidcOpRoot
  let clientCounter = 0

  const guest = { aal: 1 as const, factors: [], identityId: null, kind: 'guest' as const }

  /** A fresh client id per registration, since the OP refuses duplicates. */
  const nextClientId = () => `probe-client-${(clientCounter += 1)}-${e2ePrefix()}`

  async function register(redirectUri: string): Promise<void> {
    await op.registerClient({
      client_id: nextClientId(),
      client_name: 'probe',
      client_secret: 'secret',
      grant_types: ['authorization_code'],
      redirect_uris: [redirectUri],
      scope: ['openid'],
    })
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
      stores: { credentials: stores.credentials, identities: stores.identities, sessions: stores.sessions },
      transport: new CookieTransport({ name: 'duck-sid', secure: false }),
    })

    // The OP keeps its own in-memory stores here: what is under test is the
    // validation it applies before anything is persisted.
    const adapter = new MemoryAdapter()
    const opAuth = new AuthEngine({
      baseUrl: 'http://localhost:8787',
      stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
      transport: new CookieTransport({ name: 'duck-sid' }),
    })
    op = createOidcOP({
      auth: opAuth,
      config: { allowHttp: true, issuer: 'http://localhost:8787/auth', supportedScopes: ['openid'] },
      signIdToken: (payload) => {
        const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')
        const body = Buffer.from(JSON.stringify(payload)).toString('base64url')
        const sig = createHmac('sha256', 'dev').update(`${header}.${body}`).digest('base64url')
        return `${header}.${body}.${sig}`
      },
    })
  }, 60_000)

  afterAll(async () => {
    if (raw) {
      await dropPrefix(raw, prefix)
      await raw.quit()
    }
    await pool?.end()
  })

  describe('OIDC redirect targets', () => {
    it('FINDING: a javascript: URI is accepted as a redirect target', async () => {
      // `assertValidRedirect` parses the URL, refuses a fragment, and refuses
      // non-loopback http. Every other scheme passes, because there is no allowlist.
      // An authorization server that will send a browser to `javascript:...` with
      // the code in scope is an XSS sink wearing a redirect's clothes.
      await expect(register('javascript:alert(1)')).resolves.toBeUndefined()
    })

    it('FINDING: a data: URI is accepted as a redirect target', async () => {
      await expect(register('data:text/html,<script>alert(1)</script>')).resolves.toBeUndefined()
    })

    it('FINDING: a file: URI is accepted as a redirect target', async () => {
      await expect(register('file:///etc/passwd')).resolves.toBeUndefined()
    })

    it('FINDING: userinfo in the redirect is accepted', async () => {
      // `https://user:pass@app.test/cb` reads as app.test to a parser and as
      // something else to a human skimming the address bar.
      await expect(register('https://user:pass@app.test/cb')).resolves.toBeUndefined()
    })

    it('refuses a protocol-relative target', async () => {
      await expect(register('//evil.com/cb')).rejects.toThrow(/not a valid absolute URL/)
    })

    it('refuses a fragment, which the browser would strip anyway', async () => {
      await expect(register('https://app.test/cb#frag')).rejects.toThrow(/fragment/)
    })

    it('refuses plain http to a non-loopback host', async () => {
      await expect(register('http://app.test/cb')).rejects.toThrow(/non-loopback http/)
    })

    it('allows http to loopback, which native apps need', async () => {
      await expect(register('http://127.0.0.1:8080/cb')).resolves.toBeUndefined()
    })

    it('refuses an empty redirect', async () => {
      await expect(register('')).rejects.toThrow(/not a valid absolute URL/)
    })

    it('refuses a bare string that is not a URL', async () => {
      await expect(register('not-a-url')).rejects.toThrow(/not a valid absolute URL/)
    })

    it('refuses a client with no redirect at all', async () => {
      await expect(
        op.registerClient({
          client_id: nextClientId(),
          client_name: 'probe',
          client_secret: 'secret',
          grant_types: ['authorization_code'],
          redirect_uris: [],
          scope: ['openid'],
        }),
      ).rejects.toThrow(/at least one redirect_uri/)
    })
  })

  describe('session fields nobody validates before the insert', () => {
    it('FINDING: an out-of-range aal reaches the database as a raw driver error', async () => {
      // `create` validates factors item by item but never looks at `aal`. The
      // column CHECK catches it, so nothing corrupt is stored, but the caller gets
      // `Failed query: insert into "auth_sessions"...` rather than a typed error.
      await expect(
        auth.sessions.create({ aal: 9 as never, factors: [], identityId: null, kind: 'guest' }),
      ).rejects.toThrow(/Failed query/)
    })

    it('FINDING: aal zero is refused the same undignified way', async () => {
      await expect(
        auth.sessions.create({ aal: 0 as never, factors: [], identityId: null, kind: 'guest' }),
      ).rejects.toThrow(/Failed query/)
    })

    it('FINDING: a NaN aal is refused the same undignified way', async () => {
      await expect(
        auth.sessions.create({ aal: Number.NaN as never, factors: [], identityId: null, kind: 'guest' }),
      ).rejects.toThrow(/Failed query/)
    })

    it('FINDING: an unrecognised session kind is refused the same undignified way', async () => {
      await expect(
        auth.sessions.create({ aal: 1, factors: [], identityId: null, kind: 'browser' as never }),
      ).rejects.toThrow(/Failed query/)
    })

    it('FINDING: an impersonation window that has already closed is accepted', async () => {
      // The row is written and then refused by `resolveBySid` on the very next
      // read, so it is dead on arrival rather than dangerous. Still nothing checks
      // it at the point where it could be reported.
      const { session, sid } = await auth.sessions.create({
        ...guest,
        actingAs: {
          expiresAt: new Date(Date.now() - 60_000),
          realIdentityId: '00000000-0000-4000-8000-000000000000',
          reason: 'already over',
          startedAt: new Date(Date.now() - 120_000),
        },
      })
      expect(session.actingAs).not.toBeNull()
      expect(await auth.resolveSession({ headers: new Headers({ cookie: `duck-sid=${sid}` }) })).toBeNull()
    })

    it('accepts each aal the schema allows', async () => {
      for (const aal of [1, 2, 3] as const) {
        const { session } = await auth.sessions.create({ aal, factors: [], identityId: null, kind: 'guest' })
        expect(session.aal).toBe(aal)
      }
    })
  })

  describe('numbers the limiter is handed', () => {
    const limiter = () =>
      new RedisLimiter({
        max: 5,
        prefix: `${prefix}:w-${e2ePrefix()}`,
        redis: valkeyAdapter(raw as unknown as ValkeyClient.Me),
        windowMs: 60_000,
      })

    it('treats a negative weight as one rather than refunding budget', async () => {
      // A refund would let a caller mine budget by consuming minus five repeatedly.
      const l = limiter()
      const key = `neg-${e2ePrefix()}`
      const first = await l.consume(key, -5)
      expect(first.ok).toBe(true)
      expect(first.remaining).toBe(4)
    })

    it('treats a NaN weight as one', async () => {
      const l = limiter()
      const r = await l.consume(`nan-${e2ePrefix()}`, Number.NaN)
      expect(r.remaining).toBe(4)
    })

    it('treats an infinite weight as one', async () => {
      const l = limiter()
      const r = await l.consume(`inf-${e2ePrefix()}`, Number.POSITIVE_INFINITY)
      expect(r.remaining).toBe(4)
    })

    it('FINDING: weight is spent as one round trip each, so a large weight is a flood', async () => {
      // `consume` loops `weight` times issuing one INCR per iteration, with no
      // early exit once the budget is already gone. A caller passing 1_000_000
      // makes the limiter send a million sequential commands to Redis; the same
      // call with real Redis exceeded a five second test timeout. Counted here at
      // a small scale so the finding is deterministic rather than slow.
      let incrs = 0
      const counting = valkeyAdapter(raw as unknown as ValkeyClient.Me)
      const wrapped = {
        ...counting,
        incr: async (k: string) => {
          incrs += 1
          return counting.incr(k)
        },
      }
      const l = new RedisLimiter({
        max: 5,
        prefix: `${prefix}:count-${e2ePrefix()}`,
        redis: wrapped,
        windowMs: 60_000,
      })

      const r = await l.consume(`big-${e2ePrefix()}`, 100)
      expect(r.ok).toBe(false)
      // One hundred round trips to spend a budget of five: ninety five of them
      // after the answer was already known.
      expect(incrs).toBe(100)
    })

    it('a fractional weight is floored, not rounded up', async () => {
      const l = limiter()
      const r = await l.consume(`frac-${e2ePrefix()}`, 2.9)
      expect(r.remaining).toBe(3)
    })
  })

  describe('numbers the idempotency store is handed', () => {
    const store = () =>
      new RedisIdempotency({
        prefix: `${prefix}:i-${e2ePrefix()}`,
        redis: valkeyAdapter(raw as unknown as ValkeyClient.Me),
      })

    it('a negative ttl falls back to a sane window rather than an immortal key', async () => {
      // The counterpart bug in the session store left keys with a NaN TTL, which
      // Redis treats as no expiry at all. This one clamps, and the clamp is the
      // reason a claim cannot be wedged open forever.
      const s = store()
      const key = `neg-${e2ePrefix()}`
      expect(await s.claim(key, -1, {})).toBe(true)
      expect(await s.claim(key, -1, {})).toBe(false)
    })

    it('a NaN ttl clamps the same way', async () => {
      const s = store()
      const key = `nan-${e2ePrefix()}`
      expect(await s.claim(key, Number.NaN, {})).toBe(true)
      expect(await s.claim(key, Number.NaN, {})).toBe(false)
    })

    it('an absurd ttl is capped rather than passed through', async () => {
      const s = store()
      const key = `big-${e2ePrefix()}`
      expect(await s.claim(key, Number.MAX_SAFE_INTEGER, {})).toBe(true)
      expect(await s.claim(key, Number.MAX_SAFE_INTEGER, {})).toBe(false)
    })
  })

  describe('tenant scoping under confusing values', () => {
    it('an empty tenant id is not the same as no tenant', async () => {
      const { sid } = await auth.sessions.create({ ...guest, tenantId: '' })
      const headers = { headers: new Headers({ cookie: `duck-sid=${sid}` }) }
      // Stored as an empty string; asking for a named tenant must not match it.
      expect(await auth.resolveSession(headers, { expectedTenantId: 'real-tenant' })).toBeNull()
    })

    it('a tenant id that differs only by case does not match', async () => {
      const { sid } = await auth.sessions.create({ ...guest, tenantId: 'Tenant-A' })
      const headers = { headers: new Headers({ cookie: `duck-sid=${sid}` }) }
      expect(await auth.resolveSession(headers, { expectedTenantId: 'tenant-a' })).toBeNull()
      expect(await auth.resolveSession(headers, { expectedTenantId: 'Tenant-A' })).not.toBeNull()
    })

    it('a tenant id carrying an injection payload is just a string', async () => {
      const tenantId = `'; DROP TABLE auth_sessions; --`
      const { sid } = await auth.sessions.create({ ...guest, tenantId })
      const headers = { headers: new Headers({ cookie: `duck-sid=${sid}` }) }
      expect((await auth.resolveSession(headers, { expectedTenantId: tenantId }))?.session.tenantId).toBe(tenantId)
    })
  })
})
