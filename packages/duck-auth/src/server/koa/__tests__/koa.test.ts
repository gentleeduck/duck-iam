import { createServer } from 'node:http'
import Koa from 'koa'
import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { identityInput } from '~/test/store-inputs'
import {
  type KoaAdapter,
  koaApplyIntents,
  koaCsrf,
  koaProviderBegin,
  koaProviderCallback,
  koaSession,
  koaSignIn,
  koaSignOut,
} from '../index'

function makeCtx(
  overrides: Partial<KoaAdapter.Context['request']> & { params?: Record<string, string> } = {},
): KoaAdapter.Context & {
  _headers: Map<string, string[]>
} {
  const headers = new Map<string, string[]>()
  const ctx: KoaAdapter.Context & { _headers: Map<string, string[]> } = {
    request: {
      method: overrides.method ?? 'POST',
      url: overrides.url ?? '/AUTH/x',
      headers: overrides.headers ?? {},
      body: overrides.body,
    },
    status: 200,
    body: undefined,
    set(key, value) {
      const k = key.toLowerCase()
      const arr = Array.isArray(value) ? value : [value]
      headers.set(k, arr)
    },
    append(key, value) {
      const k = key.toLowerCase()
      const existing = headers.get(k) ?? []
      const arr = Array.isArray(value) ? value : [value]
      headers.set(k, [...existing, ...arr])
    },
    _headers: headers,
  }
  if (overrides.params) ctx.params = overrides.params
  return ctx
}

type MyProfile = {
  username: string
  email: string
}

function buildAuth() {
  const adapter = new MemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app',
    transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new MemoryLimiter({ max: 20, windowMs: 60_000 }),
    providers: [],
  })
  auth.providers.register(
    passwords({
      hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }),
    }),
  )
  return { auth, adapter }
}

describe('Koa adapter', () => {
  let auth: ReturnType<typeof buildAuth>['auth']
  let adapter: ReturnType<typeof buildAuth>['adapter']

  beforeEach(() => {
    ;({ auth, adapter } = buildAuth())
  })

  it('signIn rejects missing providerId with 400 + AUTH_INVALID_CREDENTIALS body', async () => {
    const ctx = makeCtx({ body: {} })
    await koaSignIn(auth)(ctx)
    expect(ctx.status).toBe(400)
    expect(String(ctx.body)).toContain('AUTH_INVALID_CREDENTIALS')
  })

  it('signIn happy path sets cookie + 200', async () => {
    const ident = await adapter.identities.create(
      identityInput({ profile: { username: 'user', email: 'user@x.com' }, providers: [] }),
    )
    await auth.passwords.set(ident.id, 'correcthorsebatterystaple', adapter.credentials)
    const ctx = makeCtx({
      body: {
        providerId: 'password',
        input: { email: 'user@x.com', password: 'correcthorsebatterystaple' },
      },
    })
    await koaSignIn(auth)(ctx)
    expect(ctx.status).toBe(200)
    const cookies = ctx._headers.get('set-cookie') ?? []
    expect(cookies.length).toBeGreaterThan(0)
    expect(cookies[0]).toContain('duck-sid=')
  })

  it('session returns null body when no cookie', async () => {
    const ctx = makeCtx({ method: 'GET', body: undefined })
    await koaSession(auth)(ctx)
    expect(ctx.status).toBe(200)
    expect(JSON.parse(String(ctx.body))).toEqual({ session: null, identity: null })
  })

  it('signOut clears the cookie even without a session', async () => {
    const ctx = makeCtx({ body: undefined })
    await koaSignOut(auth)(ctx)
    const cookies = ctx._headers.get('set-cookie') ?? []
    expect(cookies.length).toBeGreaterThan(0)
    expect(cookies[0]).toMatch(/Max-Age=0/i)
  })

  it('providerBegin requires :id', async () => {
    const ctx = makeCtx({ body: {}, params: {} })
    await koaProviderBegin(auth)(ctx)
    expect(ctx.status).toBe(400)
    expect(String(ctx.body)).toContain('AUTH_PROVIDER_FAILED')
  })
})

describe('koaCsrf', () => {
  async function run(method: string, headers: Record<string, string>) {
    const { auth } = buildAuth()
    const ctx = makeCtx({ headers, method })
    let nexted = false
    await koaCsrf(auth)(ctx, async () => {
      nexted = true
    })
    return { ctx, nexted }
  }

  it('lets a safe method through even from a cross-site context', async () => {
    expect((await run('GET', { 'sec-fetch-site': 'cross-site' })).nexted).toBe(true)
  })

  it('rejects a cross-site mutation with 403 and never calls next', async () => {
    const { ctx, nexted } = await run('POST', { 'sec-fetch-site': 'cross-site' })
    expect(nexted).toBe(false)
    expect(ctx.status).toBe(403)
    expect(String(ctx.body)).toContain('AUTH_CSRF')
  })

  it('lets a Bearer request through: no ambient cookie to forge', async () => {
    expect((await run('POST', { authorization: 'Bearer tok', 'sec-fetch-site': 'cross-site' })).nexted).toBe(true)
  })

  it('lets an ordinary same-origin mutation through', async () => {
    expect((await run('POST', { 'sec-fetch-site': 'same-origin' })).nexted).toBe(true)
  })
})

describe('Koa adapter - route CSRF', () => {
  it('koaSignIn rejects a cross-site POST before touching the provider', async () => {
    const { auth } = buildAuth()
    const ctx = makeCtx({ body: {}, headers: { 'sec-fetch-site': 'cross-site' }, method: 'POST' })
    await koaSignIn(auth)(ctx)
    expect(ctx.status).toBe(403)
    expect(String(ctx.body)).toContain('AUTH_CSRF')
  })
})

describe('koaProviderCallback', () => {
  /** An engine whose `oauth:stub` signs nobody in and remembers what the route handed it. */
  function recording() {
    const { auth } = buildAuth()
    const seen: { input?: unknown } = {}
    auth.providers.register({
      async begin() {
        return []
      },
      async complete(_ctx, input) {
        seen.input = input
        return []
      },
      id: 'oauth:stub',
      kind: 'oauth',
    })
    return { auth, seen }
  }

  it('reads a redirect callback out of its query', async () => {
    const { auth, seen } = recording()
    const ctx = makeCtx({
      headers: { cookie: 'duck-oauth=v' },
      method: 'GET',
      params: { id: 'oauth:stub' },
      url: '/auth/providers/oauth:stub/callback?code=c&state=s',
    })
    await koaProviderCallback(auth)(ctx)
    expect(ctx.status).toBe(200)
    expect(seen.input).toEqual({ code: 'c', cookieHeader: 'duck-oauth=v', state: 's' })
  })

  it("reads a form post out of the parsed body, Apple's user field included", async () => {
    const { auth, seen } = recording()
    const ctx = makeCtx({
      body: { code: 'c', state: 's', user: '{"name":{"firstName":"Ada"}}' },
      method: 'POST',
      params: { id: 'oauth:stub' },
      url: '/auth/providers/oauth:stub/callback',
    })
    await koaProviderCallback(auth)(ctx)
    expect(seen.input).toEqual({ code: 'c', cookieHeader: '', state: 's', user: '{"name":{"firstName":"Ada"}}' })
  })

  it('refuses a provider that is not oauth, before it runs', async () => {
    const { auth } = recording()
    const ctx = makeCtx({ method: 'GET', params: { id: 'password' }, url: '/auth/providers/password/callback?code=c' })
    await koaProviderCallback(auth)(ctx)
    expect(ctx.status).toBe(400)
  })
})

describe('koaProviderBegin', () => {
  /** An engine whose `oauth:stub` begins by setting its cookie and redirecting to `url`. */
  function redirectingTo(url: string) {
    const { auth } = buildAuth()
    auth.providers.register({
      async begin() {
        return [
          { name: 'duck-oauth', options: {}, type: 'setCookie', value: 'v' },
          { status: 302, type: 'redirect', url },
        ]
      },
      async complete() {
        return []
      },
      id: 'oauth:stub',
      kind: 'oauth',
    })
    return auth
  }

  async function begin(url: string, accept: string) {
    const ctx = makeCtx({ body: {}, headers: { accept }, params: { id: 'oauth:stub' } })
    await koaProviderBegin(redirectingTo(url))(ctx)
    return ctx
  }

  it('redirects a navigation', async () => {
    const ctx = await begin('https://idp.test/authorize', 'text/html')
    expect(ctx.status).toBe(302)
    expect(ctx._headers.get('location')).toEqual(['https://idp.test/authorize'])
  })

  it('answers a script, which cannot follow the redirect, with the URL and the same cookie', async () => {
    const ctx = await begin('https://idp.test/authorize', 'application/json')
    expect(ctx.status).toBe(200)
    expect(JSON.parse(String(ctx.body))).toEqual({ url: 'https://idp.test/authorize' })
    expect(ctx._headers.get('set-cookie')).toEqual([expect.stringMatching(/^duck-oauth=v/)])
  })

  it('never hands a script a URL it would refuse to redirect to', async () => {
    const ctx = await begin('javascript:alert(1)', 'application/json')
    expect(ctx.status).toBe(500)
    expect(String(ctx.body)).not.toContain('javascript:')
  })
})

describe('koaApplyIntents', () => {
  it('answers a host route on real Koa with one Set-Cookie header per cookie', async () => {
    const app = new Koa()
    app.use((ctx) =>
      koaApplyIntents(
        [
          { name: 'a', options: {}, type: 'setCookie', value: '1' },
          { name: 'b', options: {}, type: 'setCookie', value: '2' },
          { body: { ok: true }, status: 201, type: 'json' },
        ],
        ctx,
      ),
    )
    const server = createServer(app.callback())
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    const address = server.address()
    if (typeof address !== 'object' || address === null) throw new Error('the server has no port')
    try {
      const res = await fetch(`http://127.0.0.1:${address.port}/`)
      expect(res.status).toBe(201)
      expect(res.headers.getSetCookie()).toEqual(['a=1', 'b=2'])
      expect(await res.json()).toEqual({ ok: true })
    } finally {
      server.close()
    }
  })
})
