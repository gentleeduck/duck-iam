import { describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { AuthMemoryLimiter } from '~/limiters/memory'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { applyIntents, mountSession, mountSignIn, mountSignOut, toHeaders } from '../index'

type MyProfile = {
  username: string
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
    transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new AuthMemoryLimiter({ max: 5, windowMs: 60_000 }),
  })
  auth.providers.register(
    passwords({
      hasher: fastHasher,
    }),
  )
  return { auth, adapter }
}

describe('toHeaders', () => {
  it('converts flat object to Headers + handles arrays + undefined', () => {
    const h = toHeaders({
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

describe('applyIntents', () => {
  it('writes setCookie as Set-Cookie header', () => {
    const r = mockRes()
    applyIntents(
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
    applyIntents([{ type: 'json', status: 200, body: { ok: true } }], r.res)
    expect(r.status).toBe(200)
    expect(r.body).toEqual({ ok: true })
  })

  it('redirect intent calls res.redirect', () => {
    const r = mockRes()
    applyIntents([{ type: 'redirect', url: '/foo', status: 303 }], r.res)
    expect(r.redirected).toEqual({ status: 303, location: '/foo' })
  })
})

describe('mounted handlers - end-to-end', () => {
  it('mountSignIn happy path: cookie set, 200 body', async () => {
    const { auth, adapter } = buildAuth()
    const identity = await auth.identities.create({ profile: { username: 'user', email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'correct-pw', adapter.credentials)

    const handler = mountSignIn(auth)
    const r = mockRes()
    await handler(
      {
        method: 'POST',
        url: '/AUTH/signin',
        headers: {},
        body: { providerId: 'password', input: { email: 'a@x.com', password: 'correct-pw' } },
      },
      r.res,
    )
    expect(r.status).toBe(200)
    expect(r.headers['set-cookie']?.[0]).toMatch(/^duck-sid=/)
  })

  it('mountSignIn missing providerId returns 400', async () => {
    const { auth } = buildAuth()
    const handler = mountSignIn(auth)
    const r = mockRes()
    await handler({ method: 'POST', url: '/AUTH/signin', headers: {}, body: {} }, r.res)
    expect(r.status).toBe(400)
  })

  it('mountSignIn wrong password returns 401 with AUTH/INVALID_CREDENTIALS body', async () => {
    const { auth, adapter } = buildAuth()
    const identity = await auth.identities.create({ profile: { username: 'user', email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'correct-pw', adapter.credentials)
    const handler = mountSignIn(auth)
    const r = mockRes()
    await handler(
      {
        method: 'POST',
        url: '/AUTH/signin',
        headers: {},
        body: { providerId: 'password', input: { email: 'a@x.com', password: 'wrong-pw' } },
      },
      r.res,
    )
    expect(r.status).toBe(401)
    expect((r.body as { error: { code: string } }).error.code).toBe('AUTH_INVALID_CREDENTIALS')
  })

  it('mountSession after signin returns the resolved session shape', async () => {
    const { auth, adapter } = buildAuth()
    const identity = await auth.identities.create({ profile: { username: 'user', email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'correct-pw', adapter.credentials)

    const signinR = mockRes()
    await mountSignIn(auth)(
      {
        method: 'POST',
        url: '/AUTH/signin',
        headers: {},
        body: { providerId: 'password', input: { email: 'a@x.com', password: 'correct-pw' } },
      },
      signinR.res,
    )
    const setCookie = signinR.headers['set-cookie']?.[0] ?? ''
    const sidMatch = setCookie.match(/^duck-sid=([^;]+)/)
    const sid = sidMatch ? decodeURIComponent(sidMatch[1] ?? '') : ''

    const sessR = mockRes()
    await mountSession(auth)(
      {
        method: 'GET',
        url: '/AUTH/session',
        headers: { cookie: `duck-sid=${sid}` },
      },
      sessR.res,
    )
    expect(sessR.status).toBe(200)
    const body = sessR.body as { identity: { id: string } | null }
    expect(body.identity?.id).toBe(identity.id)
  })

  it('mountSignOut clears cookie + revokes session', async () => {
    const { auth, adapter } = buildAuth()
    const identity = await auth.identities.create({ profile: { username: 'user', email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'correct-pw', adapter.credentials)
    const r = mockRes()
    await mountSignIn(auth)(
      {
        method: 'POST',
        url: '/AUTH/signin',
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
    await mountSignOut(auth)(
      {
        method: 'POST',
        url: '/AUTH/signout',
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
