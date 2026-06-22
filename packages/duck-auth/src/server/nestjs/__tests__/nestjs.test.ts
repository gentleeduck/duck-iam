import { beforeEach, describe, expect, it } from 'vitest'
import { AuthMemoryAdapter } from '../../../adapters/memory'
import { AuthEngine } from '../../../core/auth'
import { AuthScryptHasher } from '../../../core/password/scrypt'
import { AuthCookieTransport } from '../../../core/transport/cookie'
import { AuthMemoryLimiter } from '../../../limiters/memory'
import { authPassword } from '../../../providers/password'
import { authMakeGuard, type AuthNestAdapter, authNestProviderBegin, authNestSession, authNestSignIn, authNestSignOut } from '../index'

function makeReply(): AuthNestAdapter.IReply & {
  _status?: number
  _headers: Map<string, string[]>
  _body?: string
} {
  const headers = new Map<string, string[]>()
  const reply: AuthNestAdapter.IReply & {
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

interface MyProfile {
  email: string
}

function buildAuth() {
  const adapter = new AuthMemoryAdapter<MyProfile>()
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

describe('NestJS adapter - handlers', () => {
  let auth: ReturnType<typeof buildAuth>['auth']
  let adapter: ReturnType<typeof buildAuth>['adapter']

  beforeEach(() => {
    ;({ auth, adapter } = buildAuth())
  })

  it('signIn missing providerId -> 400 + AUTH/INVALID_CREDENTIALS', async () => {
    const reply = makeReply()
    await authNestSignIn(auth)(
      { method: 'POST', url: '/auth/signin', headers: {}, body: {} } as AuthNestAdapter.IRequest,
      reply,
    )
    expect(reply._status).toBe(400)
    expect(reply._body).toContain('AUTH/INVALID_CREDENTIALS')
  })

  it('signIn happy path sets cookie + 200', async () => {
    const ident = await adapter.identities.create({ profile: { email: 'user@x.com' }, providers: [] }, {})
    await auth.passwords.set(ident.id, 'correcthorsebatterystaple', {})
    const reply = makeReply()
    await authNestSignIn(auth)(
      {
        method: 'POST',
        url: '/auth/signin',
        headers: {},
        body: {
          providerId: 'password',
          input: { email: 'user@x.com', password: 'correcthorsebatterystaple' },
        },
      } as AuthNestAdapter.IRequest,
      reply,
    )
    expect(reply._status).toBe(200)
    const cookies = reply._headers.get('set-cookie') ?? []
    expect(cookies.length).toBeGreaterThan(0)
    expect(cookies[0]).toContain('duck-sid=')
  })

  it('session returns null body without cookie', async () => {
    const reply = makeReply()
    await authNestSession(auth)({ method: 'GET', headers: {} } as AuthNestAdapter.IRequest, reply)
    expect(JSON.parse(reply._body!)).toEqual({ session: null, identity: null })
  })

  it('signOut clears cookie even without session', async () => {
    const reply = makeReply()
    await authNestSignOut(auth)({ method: 'POST', headers: {} } as AuthNestAdapter.IRequest, reply)
    const cookies = reply._headers.get('set-cookie') ?? []
    expect(cookies[0]).toMatch(/Max-Age=0/i)
  })

  it('providerBegin requires :id', async () => {
    const reply = makeReply()
    await authNestProviderBegin(auth)({ method: 'POST', headers: {}, body: {}, params: {} } as AuthNestAdapter.IRequest, reply)
    expect(reply._status).toBe(400)
    expect(reply._body).toContain('AUTH/PROVIDER_FAILED')
  })
})

describe('NestJS adapter - authMakeGuard', () => {
  let auth: ReturnType<typeof buildAuth>['auth']

  beforeEach(() => {
    ;({ auth } = buildAuth())
  })

  it('required:true + no cookie -> throws AUTH/UNAUTHENTICATED', async () => {
    const guard = authMakeGuard(auth)
    const req: AuthNestAdapter.IRequest = { method: 'GET', headers: {} }
    await expect(
      guard.canActivate({ switchToHttp: () => ({ getRequest: <T>(): T => req as T }) }),
    ).rejects.toMatchObject({ code: 'AUTH/UNAUTHENTICATED' })
  })

  it('required:false + no cookie -> passes, no mutation', async () => {
    const guard = authMakeGuard(auth, { required: false })
    const req: AuthNestAdapter.IRequest = { method: 'GET', headers: {} }
    const ok = await guard.canActivate({ switchToHttp: () => ({ getRequest: <T>(): T => req as T }) })
    expect(ok).toBe(true)
    expect(req.session).toBeUndefined()
  })
})
