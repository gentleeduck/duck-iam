import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAuthAdapter } from '../../../adapters/memory'
import { AuthRoot } from '../../../core/auth'
import { ScryptHasher } from '../../../core/password/scrypt'
import { CookieTransport } from '../../../core/transport/cookie'
import { MemoryLimiter } from '../../../limiters/memory'
import { password } from '../../../providers/password'
import { makeAuthGuard, type NestAdapter, nestProviderBegin, nestSession, nestSignIn, nestSignOut } from '../index'

function makeReply(): NestAdapter.IReply & {
  _status?: number
  _headers: Map<string, string[]>
  _body?: string
} {
  const headers = new Map<string, string[]>()
  const reply: NestAdapter.IReply & {
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
  const adapter = new MemoryAuthAdapter<MyProfile>()
  const auth = new AuthRoot<MyProfile>({
    baseUrl: 'https://app',
    transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new MemoryLimiter({ max: 20, windowMs: 60_000 }),
    passwords: { hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) },
  })
  auth.providers.register(
    password({
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
    await nestSignIn(auth)(
      { method: 'POST', url: '/auth/signin', headers: {}, body: {} } as NestAdapter.IRequest,
      reply,
    )
    expect(reply._status).toBe(400)
    expect(reply._body).toContain('AUTH/INVALID_CREDENTIALS')
  })

  it('signIn happy path sets cookie + 200', async () => {
    const ident = await adapter.identities.create({ profile: { email: 'user@x.com' }, providers: [] }, {})
    await auth.passwords.set(ident.id, 'correcthorsebatterystaple', {})
    const reply = makeReply()
    await nestSignIn(auth)(
      {
        method: 'POST',
        url: '/auth/signin',
        headers: {},
        body: {
          providerId: 'password',
          input: { email: 'user@x.com', password: 'correcthorsebatterystaple' },
        },
      } as NestAdapter.IRequest,
      reply,
    )
    expect(reply._status).toBe(200)
    const cookies = reply._headers.get('set-cookie') ?? []
    expect(cookies.length).toBeGreaterThan(0)
    expect(cookies[0]).toContain('duck-sid=')
  })

  it('session returns null body without cookie', async () => {
    const reply = makeReply()
    await nestSession(auth)({ method: 'GET', headers: {} } as NestAdapter.IRequest, reply)
    expect(JSON.parse(reply._body!)).toEqual({ session: null, identity: null })
  })

  it('signOut clears cookie even without session', async () => {
    const reply = makeReply()
    await nestSignOut(auth)({ method: 'POST', headers: {} } as NestAdapter.IRequest, reply)
    const cookies = reply._headers.get('set-cookie') ?? []
    expect(cookies[0]).toMatch(/Max-Age=0/i)
  })

  it('providerBegin requires :id', async () => {
    const reply = makeReply()
    await nestProviderBegin(auth)({ method: 'POST', headers: {}, body: {}, params: {} } as NestAdapter.IRequest, reply)
    expect(reply._status).toBe(400)
    expect(reply._body).toContain('AUTH/PROVIDER_FAILED')
  })
})

describe('NestJS adapter - makeAuthGuard', () => {
  let auth: ReturnType<typeof buildAuth>['auth']

  beforeEach(() => {
    ;({ auth } = buildAuth())
  })

  it('required:true + no cookie -> throws AUTH/UNAUTHENTICATED', async () => {
    const guard = makeAuthGuard(auth)
    const req: NestAdapter.IRequest = { method: 'GET', headers: {} }
    await expect(
      guard.canActivate({ switchToHttp: () => ({ getRequest: <T>(): T => req as T }) }),
    ).rejects.toMatchObject({ code: 'AUTH/UNAUTHENTICATED' })
  })

  it('required:false + no cookie -> passes, no mutation', async () => {
    const guard = makeAuthGuard(auth, { required: false })
    const req: NestAdapter.IRequest = { method: 'GET', headers: {} }
    const ok = await guard.canActivate({ switchToHttp: () => ({ getRequest: <T>(): T => req as T }) })
    expect(ok).toBe(true)
    expect(req.session).toBeUndefined()
  })
})
