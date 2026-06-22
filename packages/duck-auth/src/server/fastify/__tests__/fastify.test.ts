import { beforeEach, describe, expect, it, vi } from 'vitest'
import { AuthMemoryAdapter } from '../../../adapters/memory'
import { AuthEngine } from '../../../core/engine'
import { AuthScryptHasher } from '../../../core/password/scrypt'
import { AuthCookieTransport } from '../../../core/transport/cookie'
import { AuthMemoryLimiter } from '../../../limiters/memory'
import { authPassword } from '../../../providers/password'
import {
  type AuthFastifyAdapter,
  authFastifyProviderBegin,
  authFastifySession,
  authFastifySignIn,
  authFastifySignOut,
  authRegisterFastify,
} from '../index'

function makeReply(): AuthFastifyAdapter.IReply & {
  _status?: number
  _headers: Map<string, string[]>
  _body?: string
} {
  const headers = new Map<string, string[]>()
  const reply: AuthFastifyAdapter.IReply & {
    _status?: number
    _headers: Map<string, string[]>
    _body?: string
  } = {
    _headers: headers,
    status(code) {
      this._status = code
      return this
    },
    header(key, value) {
      const k = key.toLowerCase()
      const existing = this._headers.get(k) ?? []
      existing.push(value)
      this._headers.set(k, existing)
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

describe('Fastify adapter', () => {
  let auth: ReturnType<typeof buildAuth>['auth']
  let adapter: ReturnType<typeof buildAuth>['adapter']

  beforeEach(() => {
    ;({ auth, adapter } = buildAuth())
  })

  it('signIn rejects missing providerId with INVALID_CREDENTIALS 400', async () => {
    const handler = authFastifySignIn(auth)
    const reply = makeReply()
    await handler({ method: 'POST', url: '/auth/signin', headers: {}, body: {} } as AuthFastifyAdapter.IRequest, reply)
    expect(reply._status).toBe(400)
    expect(reply._body).toContain('AUTH/INVALID_CREDENTIALS')
  })

  it('signIn -> startSession sets the cookie + replies 200 OK', async () => {
    const ident = await adapter.identities.create({ profile: { email: 'user@x.com' }, providers: [] }, {})
    await auth.passwords.set(ident.id, 'correcthorsebatterystaple', {})
    const handler = authFastifySignIn(auth)
    const reply = makeReply()
    await handler(
      {
        method: 'POST',
        url: '/auth/signin',
        headers: {},
        body: {
          providerId: 'password',
          input: { email: 'user@x.com', password: 'correcthorsebatterystaple' },
        },
      } as AuthFastifyAdapter.IRequest,
      reply,
    )
    expect(reply._status).toBe(200)
    const cookies = reply._headers.get('set-cookie') ?? []
    expect(cookies.length).toBeGreaterThan(0)
    expect(cookies[0]).toContain('duck-sid=')
  })

  it('session returns null body when no cookie', async () => {
    const handler = authFastifySession(auth)
    const reply = makeReply()
    await handler({ method: 'GET', url: '/auth/session', headers: {} } as AuthFastifyAdapter.IRequest, reply)
    expect(reply._status).toBe(200)
    expect(JSON.parse(reply._body!)).toEqual({ session: null, identity: null })
  })

  it('signOut clears the cookie even without a session', async () => {
    const handler = authFastifySignOut(auth)
    const reply = makeReply()
    await handler({ method: 'POST', url: '/auth/signout', headers: {} } as AuthFastifyAdapter.IRequest, reply)
    const cookies = reply._headers.get('set-cookie') ?? []
    expect(cookies.length).toBeGreaterThan(0)
    expect(cookies[0]).toMatch(/Max-Age=0/i)
  })

  it('providerBegin requires :id param', async () => {
    const handler = authFastifyProviderBegin(auth)
    const reply = makeReply()
    await handler(
      {
        method: 'POST',
        url: '/auth/providers//begin',
        headers: {},
        body: {},
        params: {},
      } as AuthFastifyAdapter.IRequest,
      reply,
    )
    expect(reply._status).toBe(400)
    expect(reply._body).toContain('AUTH/PROVIDER_FAILED')
  })

  it('authRegisterFastify mounts all four routes under the prefix', () => {
    const post = vi.fn()
    const get = vi.fn()
    authRegisterFastify({ post, get }, auth)
    expect(post).toHaveBeenCalledWith('/auth/signin', expect.any(Function))
    expect(post).toHaveBeenCalledWith('/auth/signout', expect.any(Function))
    expect(get).toHaveBeenCalledWith('/auth/session', expect.any(Function))
    expect(post).toHaveBeenCalledWith('/auth/providers/:id/begin', expect.any(Function))
  })

  it('authRegisterFastify honors custom prefix', () => {
    const post = vi.fn()
    const get = vi.fn()
    authRegisterFastify({ post, get }, auth, { prefix: '/api/v2/auth' })
    expect(post).toHaveBeenCalledWith('/api/v2/auth/signin', expect.any(Function))
    expect(get).toHaveBeenCalledWith('/api/v2/auth/session', expect.any(Function))
  })
})
