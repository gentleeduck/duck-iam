import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { identityInput } from '~/test/store-inputs'
import { makeGuard, type NestAdapter, nestProviderBegin, nestSession, nestSignIn, nestSignOut } from '../index'

function makeReply(): NestAdapter.Response & {
  _status?: number
  _headers: Map<string, string[]>
  _body?: string
} {
  const headers = new Map<string, string[]>()
  const reply: NestAdapter.Response & {
    _status?: number
    _headers: Map<string, string[]>
    _body?: string
  } = {
    _headers: headers,
    status(code) {
      this._status = code
      return this
    },
    setHeader(name, value) {
      const k = name.toLowerCase()
      const existing = headers.get(k) ?? []
      const arr = Array.isArray(value) ? value : [value]
      headers.set(k, [...existing, ...arr])
      return this
    },
    send(payload) {
      this._body = typeof payload === 'string' ? payload : JSON.stringify(payload)
      return this
    },
  }
  return reply
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

describe('NestJS adapter - handlers', () => {
  let auth: ReturnType<typeof buildAuth>['auth']
  let adapter: ReturnType<typeof buildAuth>['adapter']

  beforeEach(() => {
    ;({ auth, adapter } = buildAuth())
  })

  it('signIn missing providerId -> 400 + AUTH/INVALID_CREDENTIALS', async () => {
    const reply = makeReply()
    await nestSignIn(auth)({ method: 'POST', url: '/AUTH/signin', headers: {}, body: {} } as NestAdapter.Request, reply)
    expect(reply._status).toBe(400)
    expect(reply._body).toContain('AUTH_INVALID_CREDENTIALS')
  })

  it('signIn happy path sets cookie + 200', async () => {
    const ident = await adapter.identities.create(
      identityInput({ profile: { username: 'user', email: 'user@x.com' }, providers: [] }),
    )
    await auth.passwords.set(ident.id, 'correcthorsebatterystaple', adapter.credentials)
    const reply = makeReply()
    await nestSignIn(auth)(
      {
        method: 'POST',
        url: '/AUTH/signin',
        headers: {},
        body: {
          providerId: 'password',
          input: { email: 'user@x.com', password: 'correcthorsebatterystaple' },
        },
      } as NestAdapter.Request,
      reply,
    )
    expect(reply._status).toBe(200)
    const cookies = reply._headers.get('set-cookie') ?? []
    expect(cookies.length).toBeGreaterThan(0)
    expect(cookies[0]).toContain('duck-sid=')
  })

  it('session returns null body without cookie', async () => {
    const reply = makeReply()
    await nestSession(auth)({ method: 'GET', headers: {}, session: null, identity: null } as NestAdapter.Request, reply)
    expect(JSON.parse(reply._body!)).toEqual({ session: null, identity: null })
  })

  it('signOut clears cookie even without session', async () => {
    const reply = makeReply()
    await nestSignOut(auth)({ method: 'POST', headers: {} } as NestAdapter.Request, reply)
    const cookies = reply._headers.get('set-cookie') ?? []
    expect(cookies[0]).toMatch(/Max-Age=0/i)
  })

  it('providerBegin requires :id', async () => {
    const reply = makeReply()
    await nestProviderBegin(auth)({ method: 'POST', headers: {}, body: {}, params: {} } as NestAdapter.Request, reply)
    expect(reply._status).toBe(400)
    expect(reply._body).toContain('AUTH_PROVIDER_FAILED')
  })
})

describe('NestJS adapter - makeGuard', () => {
  let auth: ReturnType<typeof buildAuth>['auth']

  beforeEach(() => {
    ;({ auth } = buildAuth())
  })

  it('required:true + no cookie -> throws AUTH/UNAUTHENTICATED', async () => {
    const guard = makeGuard(auth)
    const req: NestAdapter.Request = { method: 'GET', headers: {}, session: null, identity: null }
    await expect(
      guard.canActivate({ switchToHttp: () => ({ getRequest: <T>(): T => req as T }) }),
    ).rejects.toMatchObject({ code: 'AUTH_UNAUTHENTICATED' })
  })

  it('required:false + no cookie -> passes, no mutation', async () => {
    const guard = makeGuard(auth, { required: false })
    const req: NestAdapter.Request = { method: 'GET', headers: {}, session: null, identity: null }
    const ok = await guard.canActivate({ switchToHttp: () => ({ getRequest: <T>(): T => req as T }) })
    expect(ok).toBe(true)
    expect(req.session).toBeNull()
  })
})
