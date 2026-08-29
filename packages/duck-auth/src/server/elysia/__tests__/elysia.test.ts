import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { identityInput } from '~/test/store-inputs'
import {
  type ElysiaAdapter,
  elysiaCsrf,
  elysiaProviderBegin,
  elysiaSession,
  elysiaSignIn,
  elysiaSignOut,
} from '../index'

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
  })
  auth.providers.register(
    passwords({
      hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }),
    }),
  )
  return { auth, adapter }
}

function ctx(
  body: unknown = {},
  params: Record<string, string> = {},
  headers: HeadersInit = {},
): ElysiaAdapter.Context {
  return {
    request: new Request('https://app/AUTH/x', { method: 'POST', headers }),
    body,
    params,
  }
}

describe('Elysia adapter', () => {
  let auth: ReturnType<typeof buildAuth>['auth']
  let adapter: ReturnType<typeof buildAuth>['adapter']

  beforeEach(() => {
    ;({ auth, adapter } = buildAuth())
  })

  it('signIn rejects missing providerId with 400', async () => {
    const res = await elysiaSignIn(auth)(ctx({}))
    expect(res.status).toBe(400)
    expect(await res.text()).toContain('AUTH_INVALID_CREDENTIALS')
  })

  it('signIn happy path sets cookie + 200', async () => {
    const ident = await adapter.identities.create(
      identityInput({ profile: { username: 'user', email: 'user@x.com' }, providers: [] }),
    )
    await auth.passwords.set(ident.id, 'correcthorsebatterystaple', adapter.credentials)
    const res = await elysiaSignIn(auth)(
      ctx({
        providerId: 'password',
        input: { email: 'user@x.com', password: 'correcthorsebatterystaple' },
      }),
    )
    expect(res.status).toBe(200)
    const setCookie = res.headers.get('set-cookie') ?? ''
    expect(setCookie).toContain('duck-sid=')
  })

  it('session returns null body without cookie', async () => {
    const res = await elysiaSession(auth)(ctx())
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ session: null, identity: null })
  })

  it('signOut clears cookie without session', async () => {
    const res = await elysiaSignOut(auth)(ctx())
    const setCookie = res.headers.get('set-cookie') ?? ''
    expect(setCookie).toMatch(/Max-Age=0/i)
  })

  it('providerBegin requires :id', async () => {
    const res = await elysiaProviderBegin(auth)(ctx({}, {}))
    expect(res.status).toBe(400)
    expect(await res.text()).toContain('AUTH_PROVIDER_FAILED')
  })
})

describe('elysiaCsrf', () => {
  async function run(method: string, headers: Record<string, string>) {
    const { auth } = buildAuth()
    const request = new Request('https://app/orders', { headers, method })
    return elysiaCsrf(auth)({ request })
  }

  it('lets a safe method through even from a cross-site context', async () => {
    expect(await run('GET', { 'sec-fetch-site': 'cross-site' })).toBeUndefined()
  })

  it('short-circuits a cross-site mutation with a 403 Response', async () => {
    const res = await run('POST', { 'sec-fetch-site': 'cross-site' })
    expect(res?.status).toBe(403)
    expect(await res?.text()).toContain('AUTH_CSRF')
  })

  it('lets a Bearer request through: no ambient cookie to forge', async () => {
    expect(await run('POST', { authorization: 'Bearer tok', 'sec-fetch-site': 'cross-site' })).toBeUndefined()
  })

  it('lets an ordinary same-origin mutation through', async () => {
    expect(await run('POST', { 'sec-fetch-site': 'same-origin' })).toBeUndefined()
  })
})

describe('Elysia adapter - route CSRF', () => {
  it('elysiaSignIn rejects a cross-site POST before touching the provider', async () => {
    const { auth } = buildAuth()
    const res = await elysiaSignIn(auth)(ctx({}, {}, { 'sec-fetch-site': 'cross-site' }))
    expect(res.status).toBe(403)
    expect(await res.text()).toContain('AUTH_CSRF')
  })
})
