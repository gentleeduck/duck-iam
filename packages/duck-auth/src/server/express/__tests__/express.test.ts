import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '../../../adapters/memory'
import { AuthEngine } from '../../../core/auth'
import { ScryptHasher } from '../../../core/password/scrypt'
import { AuthCookieTransport } from '../../../core/transport/cookie'
import { AuthMemoryLimiter } from '../../../limiters/memory'
import { authPassword } from '../../../providers/password'
import { authApplyIntents, authMountSession, authMountSignIn, authMountSignOut, authToHeaders } from '../index'

interface MyProfile {
  email: string
}

function mockRes() {
  const headers: Record<string, string[]> = {}
  let statusCode = 200
  let jsonBody: unknown = undefined
  let redirected: { status: number; location: string } | undefined
  const res = {
    status: vi.fn((c: number) => {
      statusCode = c
      return res
    }),
    setHeader: vi.fn((n: string, v: string) => {
      headers[n.toLowerCase()] = [String(v)]
      return res
    }),
    append: vi.fn((n: string, v: string) => {
      const key = n.toLowerCase()
      ;(headers[key] ??= []).push(v)
      return res
    }),
    json: vi.fn((b: unknown) => {
      jsonBody = b
      return res
    }),
    redirect: vi.fn((status: number, location: string) => {
      redirected = { status, location }
    }),
    end: vi.fn(),
  }
  return {
    res,
    get status() {
      return statusCode
    },
    get body() {
      return jsonBody
    },
    get redirected() {
      return redirected
    },
    headers,
  }
}

function buildAuth() {
  const adapter = new MemoryAdapter<MyProfile>()
  const fastHasher = new ScryptHasher({ N: 1 << 10, keylen: 32 })
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://x',
    transport: new AuthCookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new AuthMemoryLimiter({ max: 5, windowMs: 60_000 }),
    passwords: { hasher: fastHasher },
  })
  auth.providers.register(
    authPassword<MyProfile>({
      findIdentityByEmail: (email) => adapter.identities.findByEmail(email, {}),
      passwords: auth.passwords,
    }),
  )
  return { auth, adapter }
}

describe('authToHeaders', () => {
  it('converts flat object to Headers + handles arrays + undefined', () => {
    const h = authToHeaders({
      'content-type': 'text/plain',
      'set-cookie': ['a=1', 'b=2'],
      'x-empty': undefined,
    })
    expect(h.get('content-type')).toBe('text/plain')
    // Headers normalises set-cookie comma-joined; just verify both values are accessible.
    const sc = h.get('set-cookie')
    expect(sc).toBeTruthy()
    expect(h.get('x-empty')).toBeNull()
  })
})

describe('authApplyIntents', () => {
  it('writes setCookie as Set-Cookie header', () => {
    const r = mockRes()
    authApplyIntents(
      [
        {
          type: 'setCookie',
          name: 'duck-sid',
          value: 'abc',
          options: { httpOnly: true, secure: true, sameSite: 'lax', path: '/' },
        },
      ],
      r.res,
    )
    expect(r.headers['set-cookie']?.[0]).toMatch(/^duck-sid=abc/)
    expect(r.headers['set-cookie']?.[0]).toContain('HttpOnly')
    expect(r.headers['set-cookie']?.[0]).toContain('Secure')
    expect(r.headers['set-cookie']?.[0]).toContain('SameSite=Lax')
  })

  it('json intent writes status + body', () => {
    const r = mockRes()
    authApplyIntents([{ type: 'json', status: 200, body: { ok: true } }], r.res)
    expect(r.status).toBe(200)
    expect(r.body).toEqual({ ok: true })
  })

  it('redirect intent calls res.redirect', () => {
    const r = mockRes()
    authApplyIntents([{ type: 'redirect', url: '/foo', status: 303 }], r.res)
    expect(r.redirected).toEqual({ status: 303, location: '/foo' })
  })

  it('startSession + requireMfa intents reaching the executor surface AUTH/MISCONFIGURED 500', () => {
    const r = mockRes()
    authApplyIntents([{ type: 'startSession', identityId: 'x', aal: 1, factors: [] }], r.res)
    expect(r.status).toBe(500)
    expect(r.body).toMatchObject({ code: 'AUTH/MISCONFIGURED' })
  })
})

describe('mounted handlers - end-to-end', () => {
  it('authMountSignIn happy path: cookie set, 200 body', async () => {
    const { auth } = buildAuth()
    const identity = await auth.identities.create({ profile: { email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'correct-pw')

    const handler = authMountSignIn(auth)
    const r = mockRes()
    await handler(
      {
        method: 'POST',
        url: '/auth/signin',
        headers: {},
        body: { providerId: 'password', input: { email: 'a@x.com', password: 'correct-pw' } },
      },
      r.res,
    )
    expect(r.status).toBe(200)
    expect(r.headers['set-cookie']?.[0]).toMatch(/^duck-sid=/)
  })

  it('authMountSignIn missing providerId returns 400', async () => {
    const { auth } = buildAuth()
    const handler = authMountSignIn(auth)
    const r = mockRes()
    await handler({ method: 'POST', url: '/auth/signin', headers: {}, body: {} }, r.res)
    expect(r.status).toBe(400)
  })

  it('authMountSignIn wrong password returns 401 with AUTH/INVALID_CREDENTIALS body', async () => {
    const { auth } = buildAuth()
    const identity = await auth.identities.create({ profile: { email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'correct-pw')
    const handler = authMountSignIn(auth)
    const r = mockRes()
    await handler(
      {
        method: 'POST',
        url: '/auth/signin',
        headers: {},
        body: { providerId: 'password', input: { email: 'a@x.com', password: 'wrong-pw' } },
      },
      r.res,
    )
    expect(r.status).toBe(401)
    expect((r.body as { code: string }).code).toBe('AUTH/INVALID_CREDENTIALS')
  })

  it('authMountSession after signin returns the resolved session shape', async () => {
    const { auth } = buildAuth()
    const identity = await auth.identities.create({ profile: { email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'correct-pw')

    const signinR = mockRes()
    await authMountSignIn(auth)(
      {
        method: 'POST',
        url: '/auth/signin',
        headers: {},
        body: { providerId: 'password', input: { email: 'a@x.com', password: 'correct-pw' } },
      },
      signinR.res,
    )
    const setCookie = signinR.headers['set-cookie']?.[0] ?? ''
    const sidMatch = setCookie.match(/^duck-sid=([^;]+)/)
    const sid = sidMatch ? decodeURIComponent(sidMatch[1] ?? '') : ''

    const sessR = mockRes()
    await authMountSession(auth)(
      {
        method: 'GET',
        url: '/auth/session',
        headers: { cookie: `duck-sid=${sid}` },
      },
      sessR.res,
    )
    expect(sessR.status).toBe(200)
    const body = sessR.body as { identity: { id: string } | null }
    expect(body.identity?.id).toBe(identity.id)
  })

  it('authMountSignOut clears cookie + revokes session', async () => {
    const { auth, adapter } = buildAuth()
    const identity = await auth.identities.create({ profile: { email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'correct-pw')
    const r = mockRes()
    await authMountSignIn(auth)(
      {
        method: 'POST',
        url: '/auth/signin',
        headers: {},
        body: { providerId: 'password', input: { email: 'a@x.com', password: 'correct-pw' } },
      },
      r.res,
    )
    const sid = decodeURIComponent((r.headers['set-cookie']?.[0]?.match(/^duck-sid=([^;]+)/)?.[1] ?? '') as string)
    // signin emits __Host-duck-csrf alongside the session cookie;
    // replay both on signout + attach the matching x-csrf-token header
    // to satisfy the double-submit check on the now-authenticated route.
    const csrfCookieSetHeader = r.headers['set-cookie']?.find((h) => h.startsWith('__Host-duck-csrf='))
    const csrfToken = decodeURIComponent(csrfCookieSetHeader?.match(/^__Host-duck-csrf=([^;]+)/)?.[1] ?? '')
    expect(csrfToken).not.toBe('')
    const sessionsBefore = await adapter.sessions.listByIdentity(identity.id)
    expect(sessionsBefore).toHaveLength(1)

    const outR = mockRes()
    await authMountSignOut(auth)(
      {
        method: 'POST',
        url: '/auth/signout',
        headers: {
          cookie: `duck-sid=${sid}; __Host-duck-csrf=${csrfToken}`,
          'x-csrf-token': csrfToken,
          'sec-fetch-site': 'same-origin',
        },
      },
      outR.res,
    )
    expect(outR.status).toBe(200)
    expect(outR.headers['set-cookie']?.[0]).toMatch(/^duck-sid=/)
    expect(outR.headers['set-cookie']?.[0]).toContain('Max-Age=0')
    const sessionsAfter = await adapter.sessions.listByIdentity(identity.id)
    expect(sessionsAfter).toHaveLength(0)
  })
})
