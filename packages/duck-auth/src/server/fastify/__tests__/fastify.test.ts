import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { AuthMemoryLimiter } from '~/limiters/memory'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { identityInput } from '~/test/store-inputs'
import {
  type FastifyAdapter,
  fastifyProviderBegin,
  fastifySession,
  fastifySignIn,
  fastifySignOut,
  registerFastify,
} from '../index'

function makeReply(): FastifyAdapter.Reply & {
  _status?: number
  _headers: Map<string, string[]>
  _body?: string
} {
  const headers = new Map<string, string[]>()
  const reply: FastifyAdapter.Reply & {
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
    limiter: new AuthMemoryLimiter({ max: 20, windowMs: 60_000 }),
  })
  auth.providers.register(
    passwords({
      hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }),
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
    const handler = fastifySignIn(auth)
    const reply = makeReply()
    await handler({ method: 'POST', url: '/AUTH/signin', headers: {}, body: {} } as FastifyAdapter.Request, reply)
    expect(reply._status).toBe(400)
    expect(reply._body).toContain('AUTH_INVALID_CREDENTIALS')
  })

  it('signIn -> startSession sets the cookie + replies 200 OK', async () => {
    const ident = await adapter.identities.create(
      identityInput({ profile: { username: 'user', email: 'user@x.com' }, providers: [] }),
    )
    await auth.passwords.set(ident.id, 'correcthorsebatterystaple', adapter.credentials)
    const handler = fastifySignIn(auth)
    const reply = makeReply()
    await handler(
      {
        method: 'POST',
        url: '/AUTH/signin',
        headers: {},
        body: {
          providerId: 'password',
          input: { email: 'user@x.com', password: 'correcthorsebatterystaple' },
        },
      } as FastifyAdapter.Request,
      reply,
    )
    expect(reply._status).toBe(200)
    const cookies = reply._headers.get('set-cookie') ?? []
    expect(cookies.length).toBeGreaterThan(0)
    expect(cookies[0]).toContain('duck-sid=')
  })

  it('session returns null body when no cookie', async () => {
    const handler = fastifySession(auth)
    const reply = makeReply()
    await handler({ method: 'GET', url: '/AUTH/session', headers: {} } as FastifyAdapter.Request, reply)
    expect(reply._status).toBe(200)
    expect(JSON.parse(reply._body!)).toEqual({ session: null, identity: null })
  })

  it('signOut clears the cookie even without a session', async () => {
    const handler = fastifySignOut(auth)
    const reply = makeReply()
    await handler({ method: 'POST', url: '/AUTH/signout', headers: {} } as FastifyAdapter.Request, reply)
    const cookies = reply._headers.get('set-cookie') ?? []
    expect(cookies.length).toBeGreaterThan(0)
    expect(cookies[0]).toMatch(/Max-Age=0/i)
  })

  it('providerBegin requires :id param', async () => {
    const handler = fastifyProviderBegin(auth)
    const reply = makeReply()
    await handler(
      {
        method: 'POST',
        url: '/AUTH/providers//begin',
        headers: {},
        body: {},
        params: {},
      } as FastifyAdapter.Request,
      reply,
    )
    expect(reply._status).toBe(400)
    expect(reply._body).toContain('AUTH_PROVIDER_FAILED')
  })

  it('registerFastify mounts all four routes under the prefix', () => {
    const post = vi.fn()
    const get = vi.fn()
    registerFastify({ post, get }, auth)
    expect(post).toHaveBeenCalledWith('/auth/signin', expect.any(Function))
    expect(post).toHaveBeenCalledWith('/auth/signout', expect.any(Function))
    expect(get).toHaveBeenCalledWith('/auth/session', expect.any(Function))
    expect(post).toHaveBeenCalledWith('/auth/providers/:id/begin', expect.any(Function))
  })

  it('registerFastify honors custom prefix', () => {
    const post = vi.fn()
    const get = vi.fn()
    registerFastify({ post, get }, auth, { prefix: '/api/v2/auth' })
    expect(post).toHaveBeenCalledWith('/api/v2/auth/signin', expect.any(Function))
    expect(get).toHaveBeenCalledWith('/api/v2/auth/session', expect.any(Function))
  })
})
