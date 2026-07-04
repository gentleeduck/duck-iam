import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '../../../adapters/memory'
import { AuthEngine } from '../../../core/engine'
import { AuthScryptHasher } from '../../../core/password/scrypt'
import { AuthCookieTransport } from '../../../core/transport/cookie'
import { AuthMemoryLimiter } from '../../../limiters/memory'
import { authPassword } from '../../../providers/password'
import { type KoaAdapter, koaProviderBegin, koaSession, koaSignIn, koaSignOut } from '../index'

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
    transport: new AuthCookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new AuthMemoryLimiter({ max: 20, windowMs: 60_000 }),
    passwords: { hasher: new AuthScryptHasher({ N: 1 << 10, keylen: 32 }) },
  })
  auth.providers.register(
    authPassword({
      passwords: auth.passwords,
      findIdentityByEmail: async (email) => (await adapter.identities.findByEmail(email, {})) as { id: string } | null,
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

  it('signIn rejects missing providerId with 400 + AUTH/INVALID_CREDENTIALS body', async () => {
    const ctx = makeCtx({ body: {} })
    await koaSignIn(auth)(ctx)
    expect(ctx.status).toBe(400)
    expect(String(ctx.body)).toContain('AUTH_INVALID_CREDENTIALS')
  })

  it('signIn happy path sets cookie + 200', async () => {
    const ident = await adapter.identities.create(
      { profile: { username: 'user', email: 'user@x.com' }, providers: [] },
      {},
    )
    await auth.passwords.set(ident.id, 'correcthorsebatterystaple', {})
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
