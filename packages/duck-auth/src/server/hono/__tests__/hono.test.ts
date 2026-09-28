import { Hono } from 'hono'
import { describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import type { Provider } from '~/core/provider/provider.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { postRequest, streamedMiB } from '~/test/adapter-fakes'
import { honoCsrf, type MountHono, mountHono, toHonoAdapterCtx } from '../index'

type MyProfile = { username: string; email: string }

/** A real Hono app with every route mounted. `a@x.com` signs in with `correct-pw`. */
async function mounted(opts?: MountHono.Options) {
  const adapter = new MemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'http://localhost',
    limiter: new MemoryLimiter({ max: 5, windowMs: 60_000 }),
    providers: [passwords<MyProfile>({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) })],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
  const app = new Hono()
  mountHono(app, auth, opts)
  const { id } = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a' } })
  await auth.passwords.set(id, 'correct-pw', adapter.credentials)
  return { adapter, app, auth, id }
}

async function signIn(app: Hono, password: string): Promise<Response> {
  return app.request('/auth/signin', {
    body: JSON.stringify({ input: { email: 'a@x.com', password }, providerId: 'password' }),
    headers: { 'content-type': 'application/json' },
    method: 'POST',
  })
}

/** The value a response sets for one cookie. The transport is not `secure`, so its CSRF cookie is `duck-csrf`. */
function cookieFrom(res: Response, name: string): string {
  for (const line of res.headers.getSetCookie()) {
    const pair = line.split(';')[0] ?? ''
    if (pair.startsWith(`${name}=`)) return decodeURIComponent(pair.slice(name.length + 1))
  }
  return ''
}

describe('the routes mountHono registers', () => {
  it('signs in with a session cookie', async () => {
    const { app } = await mounted()
    const res = await signIn(app, 'correct-pw')
    expect(res.status).toBe(200)
    expect(cookieFrom(res, 'duck-sid')).not.toBe('')
  })

  it('answers a wrong password with a 401 and sets no session', async () => {
    const { app } = await mounted()
    const res = await signIn(app, 'wrong')
    expect(res.status).toBe(401)
    expect(await res.json()).toMatchObject({ error: { code: 'AUTH_INVALID_CREDENTIALS' } })
    expect(cookieFrom(res, 'duck-sid')).toBe('')
  })

  it('answers the session it set, uncached and without the CSRF hash', async () => {
    const { app, id } = await mounted()
    const sid = cookieFrom(await signIn(app, 'correct-pw'), 'duck-sid')
    const res = await app.request('/auth/session', { headers: { cookie: `duck-sid=${sid}` } })
    expect(res.status).toBe(200)
    // One URL, a different body per cookie: a shared cache must not keep it.
    expect(res.headers.get('cache-control')).toBe('no-store')
    const body: unknown = await res.json()
    expect(body).toMatchObject({ identity: { id }, session: { id: expect.any(String) } })
    expect(body).not.toHaveProperty(['session', 'csrfHash'])
  })

  it('signs out, revoking the row and clearing the cookie', async () => {
    const { adapter, app, id } = await mounted()
    const signedIn = await signIn(app, 'correct-pw')
    const sid = cookieFrom(signedIn, 'duck-sid')
    const csrf = cookieFrom(signedIn, 'duck-csrf')
    expect(csrf).not.toBe('')
    expect(await adapter.sessions.listByIdentity(id)).toHaveLength(1)

    const res = await app.request('/auth/signout', {
      headers: { cookie: `duck-sid=${sid}; duck-csrf=${csrf}`, 'sec-fetch-site': 'same-origin', 'x-csrf-token': csrf },
      method: 'POST',
    })
    expect(res.status).toBe(200)
    expect(res.headers.get('set-cookie')).toContain('Max-Age=0')
    expect(await adapter.sessions.listByIdentity(id)).toEqual([])
  })
})

describe('honoCsrf', () => {
  async function run(method: string, headers: Record<string, string>): Promise<Response> {
    const { auth } = await mounted()
    const app = new Hono()
    app.use(honoCsrf(auth))
    app.on(['GET', 'POST'], '/orders', (c) => c.text('ran'))
    return app.request('/orders', { headers, method })
  }

  it('lets a safe method through even from a cross-site context', async () => {
    expect(await (await run('GET', { 'sec-fetch-site': 'cross-site' })).text()).toBe('ran')
  })

  it('refuses a cross-site mutation with a 403, before the route runs', async () => {
    const res = await run('POST', { 'sec-fetch-site': 'cross-site' })
    expect(res.status).toBe(403)
    expect(await res.text()).toContain('AUTH_CSRF')
  })

  it('lets a Bearer request through: no ambient cookie to forge', async () => {
    const res = await run('POST', { authorization: 'Bearer tok', 'sec-fetch-site': 'cross-site' })
    expect(await res.text()).toBe('ran')
  })

  it('lets an ordinary same-origin mutation through', async () => {
    expect(await (await run('POST', { 'sec-fetch-site': 'same-origin' })).text()).toBe('ran')
  })
})

describe('the mounted oauth callback', () => {
  /** An app whose `oauth:stub` provider signs nobody in and remembers what the route handed it. */
  async function recording() {
    const { app, auth } = await mounted()
    const seen: { input?: unknown } = {}
    const provider: Provider.Me<unknown, unknown> = {
      async begin() {
        return []
      },
      async complete(_ctx, input) {
        seen.input = input
        return []
      },
      id: 'oauth:stub',
      kind: 'oauth',
    }
    auth.providers.register(provider)
    return { app, seen }
  }

  it('forwards the Cookie header, which is what binds the callback to one browser', async () => {
    const { app, seen } = await recording()
    await app.request('/auth/providers/oauth:stub/callback?code=c&state=s', {
      headers: { cookie: '__Host-duck-oauth=browser-value' },
    })
    expect(seen.input).toEqual({ code: 'c', cookieHeader: '__Host-duck-oauth=browser-value', state: 's' })
  })

  it('forwards an empty header rather than nothing when the browser sent no cookie', async () => {
    const { app, seen } = await recording()
    await app.request('/auth/providers/oauth:stub/callback?code=c&state=s')
    expect(seen.input).toEqual({ code: 'c', cookieHeader: '', state: 's' })
  })

  it('reads a form_post callback out of its urlencoded body', async () => {
    const { app, seen } = await recording()
    await app.request('/auth/providers/oauth:stub/callback', {
      body: 'code=c&state=s',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: '__Host-duck-oauth=browser-value' },
      method: 'POST',
    })
    expect(seen.input).toEqual({ code: 'c', cookieHeader: '__Host-duck-oauth=browser-value', state: 's' })
  })

  it("forwards Apple's posted user field, the only place its name arrives", async () => {
    const { app, seen } = await recording()
    const user = '{"name":{"firstName":"Ada"}}'
    await app.request('/auth/providers/oauth:stub/callback', {
      body: new URLSearchParams({ code: 'c', state: 's', user }).toString(),
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      method: 'POST',
    })
    expect(seen.input).toEqual({ code: 'c', cookieHeader: '', state: 's', user })
  })
})

describe('toHonoAdapterCtx', () => {
  it('answers a named header only as a string, and every header when unnamed', () => {
    const raw = new Request('https://x/', { headers: { 'x-a': '1' } })
    const ctx = toHonoAdapterCtx({
      req: {
        header: (n) => (n === 'x-a' ? '1' : ['not', 'a', 'string']),
        method: 'GET',
        param: () => undefined,
        raw,
        url: raw.url,
      },
    })
    expect(ctx.req.header('x-a')).toBe('1')
    expect(ctx.req.header('x-b')).toBeUndefined()
    expect(ctx.req.header()).toEqual({ 'x-a': '1' })
  })
})

describe('what mountHono hands each sign-in', () => {
  const routes: [string, string, string?][] = [
    [
      'POST',
      '/auth/signin',
      JSON.stringify({ input: { email: 'a@x.com', password: 'correct-pw' }, providerId: 'password' }),
    ],
    ['GET', '/auth/providers/oauth:stub/callback?code=c&state=s'],
    ['POST', '/auth/providers/oauth:stub/callback', 'code=c&state=s'],
    ['GET', '/auth/magic-link/verify?token=t'],
    ['POST', '/auth/passkey/complete', '{}'],
  ]

  async function seenBy(
    opts: MountHono.Options,
    [method, path, body]: [string, string, string?],
    headers: Record<string, string> = {},
  ) {
    const { app, auth } = await mounted(opts)
    auth.providers.register({
      async begin() {
        return []
      },
      async complete() {
        return []
      },
      id: 'oauth:stub',
      kind: 'oauth',
    })
    const signIn = vi.spyOn(auth.flows, 'signIn')
    await app.request(path, { headers, method, ...(body !== undefined && { body }) })
    expect(signIn).toHaveBeenCalledOnce()
    return signIn.mock.calls[0]?.[0]
  }

  it.each(routes)('%s %s passes the address the app resolved', async (...route) => {
    expect(await seenBy({ ip: () => '203.0.113.9' }, route)).toMatchObject({ ip: '203.0.113.9' })
  })

  it.each(routes)('%s %s passes none when the app resolves none', async (...route) => {
    expect(await seenBy({}, route)).not.toHaveProperty('ip')
  })

  it.each(routes)('%s %s passes the session the request carries, so the sign-in ends it', async (...route) => {
    const headers = { cookie: 'duck-sid=prior; duck-csrf=t', 'x-csrf-token': 't' }
    expect(await seenBy({}, route, headers)).toMatchObject({ previousSid: 'prior' })
  })
})

describe('the body cap on every route that reads one', () => {
  it.each([
    '/auth/signin',
    '/auth/providers/password/begin',
    '/auth/providers/oauth:stub/callback',
    '/auth/passkey/begin',
    '/auth/passkey/complete',
    '/auth/mfa/totp/begin',
    '/auth/mfa/totp/confirm',
    '/auth/mfa/totp/verify',
  ])('POST %s stops reading a body past 100 KiB', async (path) => {
    const { app, auth } = await mounted()
    auth.providers.register({ begin: async () => [], complete: async () => [], id: 'oauth:stub', kind: 'oauth' })
    const session = await signIn(app, 'correct-pw')
    const csrf = cookieFrom(session, 'duck-csrf')
    const { body, pulled } = streamedMiB()
    const cookie = `duck-sid=${encodeURIComponent(cookieFrom(session, 'duck-sid'))}; duck-csrf=${encodeURIComponent(csrf)}`
    const headers = { cookie, 'sec-fetch-site': 'same-origin', 'x-csrf-token': csrf }
    await app.request(postRequest(`http://localhost${path}`, body, headers))
    expect(pulled()).toBeLessThanOrEqual(7)
  })

  it('signs in with a body padded to just under the cap', async () => {
    const { app } = await mounted()
    const body = JSON.stringify({ input: { email: 'a@x.com', password: 'correct-pw' }, providerId: 'password' })
    const res = await app.request(postRequest('http://localhost/auth/signin', body.padEnd(100 * 1024)))
    expect(res.status).toBe(200)
  })
})
