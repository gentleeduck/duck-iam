/** E2E: who a write is attributed to, over real HTTP into real Postgres. */
import { Pool } from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DrizzlePgAdapter } from '~/adapters/drizzle/pg'
import { actorId, setDefaultActorResolver, withActor, withRequestActor } from '~/core/actor'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { applyPgSchema, databaseUrl, e2ePrefix, serve } from '~/test/e2e-env'

const PG_URL = databaseUrl()
const suite = PG_URL ? describe : describe.skip

type Profile = { username: string; email: string }

const PASSWORD = 'correct-horse-battery'

suite('E2E actor attribution over HTTP into real Postgres', () => {
  let pool: Pool
  let appPool: Pool
  let stores: DrizzlePgAdapter<Profile>
  let auth: AuthEngine<Profile>
  let app: Awaited<ReturnType<typeof serve>>
  const planted: string[] = []

  const email = (name: string) => `${name}-${e2ePrefix()}@actor.test`

  async function signUp(address: string): Promise<string> {
    const identity = await auth.identities.create({ profile: { email: address, username: address } })
    planted.push(identity.id)
    await auth.passwords.set(identity.id, PASSWORD, stores.credentials)
    return identity.id
  }

  async function signIn(address: string): Promise<string> {
    return (await auth.flows.signIn({ input: { email: address, password: PASSWORD }, providerId: 'password' })).sid
  }

  /** POST to the app; every route answers a string. */
  async function post(path: string, params: Record<string, string> = {}, sid?: string): Promise<string> {
    const res = await fetch(`${app.origin}${path}?${new URLSearchParams(params)}`, {
      headers: sid ? { cookie: `duck-sid=${sid}` } : {},
      method: 'POST',
    })
    const body: unknown = await res.json()
    if (!res.ok || typeof body !== 'string') throw new Error(`${path} answered ${res.status}: ${JSON.stringify(body)}`)
    return body
  }

  const rows = async (sql: string, id: string) => (await pool.query(sql, [id])).rows

  beforeAll(async () => {
    pool = new Pool({ connectionString: PG_URL })
    await applyPgSchema(pool)
    // One connection, so concurrent requests queue for it: where a pool can resume one request's work in another's
    // async context.
    appPool = new Pool({ connectionString: PG_URL, max: 1 })
    stores = new DrizzlePgAdapter<Profile>(appPool)
    auth = new AuthEngine<Profile>({
      baseUrl: 'https://app.test',
      limiter: new MemoryLimiter({ max: 1_000, windowMs: 60_000 }),
      stores: { credentials: stores.credentials, identities: stores.identities, sessions: stores.sessions },
      transport: new CookieTransport({ name: 'duck-sid', secure: false }),
    })
    auth.providers.register(passwords<Profile>({ hasher: new ScryptHasher({ keylen: 32, N: 1 << 10 }) }))

    // Started the way a boot script starts one, inside a scope of its own.
    app = await withActor('boot', () =>
      serve(async (req, headers) => {
        const url = new URL(req.url ?? '/', 'http://app.test')
        const param = (name: string) => url.searchParams.get(name) ?? ''
        if (url.pathname === '/actor') return actorId()
        return withRequestActor(auth, { headers }, async () => {
          if (url.pathname === '/sign-up') return signUp(param('email'))
          const id = param('id')
          if (url.pathname === '/profile') {
            const { version } = await auth.identities.getById(id)
            return (await auth.identities.updateProfile(id, { username: param('username') }, version)).id
          }
          return (await auth.identities.link(id, { providerId: 'github', providerSub: param('sub') })).id
        })
      }),
    )
  }, 60_000)

  afterAll(async () => {
    await app?.close()
    if (planted.length > 0) await pool.query('DELETE FROM auth_identities WHERE id = ANY($1::uuid[])', [planted])
    await appPool?.end()
    await pool?.end()
  })

  it('attributes an anonymous request to no one, not to the scope the server started in', async () => {
    // The control: a handler nothing wraps still runs as the scope the server was started in.
    expect(await post('/actor')).toBe('boot')

    const id = await post('/sign-up', { email: email('anon') })
    expect(await rows('SELECT created_by, updated_by FROM auth_identities WHERE id = $1', id)).toEqual([
      { created_by: null, updated_by: null },
    ])
    expect(await rows('SELECT created_by, updated_by FROM auth_credentials WHERE identity_id = $1', id)).toEqual([
      { created_by: null, updated_by: null },
    ])
  })

  it('attributes a signed-in request to its identity', async () => {
    const address = email('self')
    const self = await signUp(address)

    await post('/profile', { id: self, username: email('renamed') }, await signIn(address))
    expect(await rows('SELECT updated_by FROM auth_identities WHERE id = $1', self)).toEqual([{ updated_by: self }])
  })

  it('attributes an impersonated request to the operator, not to the identity it acts as', async () => {
    const address = email('operator')
    const operator = await signUp(address)
    const target = await signUp(email('target'))
    const { sid } = await auth.flows.impersonate({
      authorize: async (real, targetId) => real.identityId === operator && targetId === target,
      realSid: await signIn(address),
      reason: 'support ticket 42',
      targetIdentityId: target,
    })

    await post('/profile', { id: target, username: email('fixed') }, sid)
    expect(await rows('SELECT updated_by FROM auth_identities WHERE id = $1', target)).toEqual([
      { updated_by: operator },
    ])
  })

  it('keeps each request its own actor while they queue for one connection', async () => {
    const users = await Promise.all(
      Array.from({ length: 6 }, async (_, i) => {
        const address = email(`queued-${i}`)
        const id = await signUp(address)
        return { id, sid: await signIn(address) }
      }),
    )

    await Promise.all(users.map(({ id, sid }) => post('/link', { id, sub: id }, sid)))
    const { rows: links } = await pool.query(
      'SELECT identity_id, added_by FROM auth_identity_providers WHERE identity_id = ANY($1::uuid[])',
      [users.map((u) => u.id)],
    )
    expect(links.map((l) => [l.identity_id, l.added_by]).sort()).toEqual(users.map((u) => [u.id, u.id]).sort())
  })

  it("lets a request's own actor beat the process default, and falls to it for an anonymous one", async () => {
    const address = email('defaulted')
    const self = await signUp(address)
    const sid = await signIn(address)
    setDefaultActorResolver(() => 'cron')
    try {
      await post('/profile', { id: self, username: email('renamed') }, sid)
      const anon = await post('/sign-up', { email: email('anon-defaulted') })

      expect(await rows('SELECT updated_by FROM auth_identities WHERE id = $1', self)).toEqual([{ updated_by: self }])
      expect(await rows('SELECT created_by FROM auth_identities WHERE id = $1', anon)).toEqual([{ created_by: 'cron' }])
    } finally {
      setDefaultActorResolver(undefined)
    }
  })
})
