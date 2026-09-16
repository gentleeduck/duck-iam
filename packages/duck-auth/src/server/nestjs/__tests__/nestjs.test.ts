import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { identityInput } from '~/test/store-inputs'
import {
  makeCsrfGuard,
  makeGuard,
  type NestAdapter,
  nestProviderBegin,
  nestSession,
  nestSignIn,
  nestSignOut,
} from '../index'

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

describe('NestJS adapter - CSRF', () => {
  function ctxFor(req: NestAdapter.Request) {
    return { switchToHttp: () => ({ getRequest: <T>(): T => req as T }) }
  }

  function req(method: string, headers: Record<string, string>): NestAdapter.Request {
    return { headers, identity: null, method, session: null }
  }

  it('makeGuard verifies CSRF by default: a cross-site mutation is rejected', async () => {
    const { auth } = buildAuth()
    await expect(
      makeGuard(auth, { required: false }).canActivate(ctxFor(req('POST', { 'sec-fetch-site': 'cross-site' }))),
    ).rejects.toMatchObject({ code: 'AUTH_CSRF' })
  })

  it('makeGuard with csrf:false skips the check', async () => {
    const { auth } = buildAuth()
    const ok = await makeGuard(auth, { csrf: false, required: false }).canActivate(
      ctxFor(req('POST', { 'sec-fetch-site': 'cross-site' })),
    )
    expect(ok).toBe(true)
  })

  it('makeCsrfGuard rejects a cross-site mutation and allows a safe method', async () => {
    const { auth } = buildAuth()
    const guard = makeCsrfGuard(auth)
    await expect(guard.canActivate(ctxFor(req('POST', { 'sec-fetch-site': 'cross-site' })))).rejects.toMatchObject({
      code: 'AUTH_CSRF',
    })
    expect(await guard.canActivate(ctxFor(req('GET', { 'sec-fetch-site': 'cross-site' })))).toBe(true)
  })

  it('makeCsrfGuard lets a Bearer request through', async () => {
    const { auth } = buildAuth()
    const allowed = await makeCsrfGuard(auth).canActivate(
      ctxFor(req('POST', { authorization: 'Bearer tok', 'sec-fetch-site': 'cross-site' })),
    )
    expect(allowed).toBe(true)
  })
})

describe('NestJS adapter - route CSRF', () => {
  it('nestSignIn rejects a cross-site POST before touching the provider', async () => {
    const { auth } = buildAuth()
    const reply = makeReply()
    const req: NestAdapter.Request = {
      body: {},
      headers: { 'sec-fetch-site': 'cross-site' },
      identity: null,
      method: 'POST',
      session: null,
    }
    await expect(nestSignIn(auth)(req, reply)).rejects.toMatchObject({ code: 'AUTH_CSRF' })
    expect(reply._status).toBe(403)
  })
})

describe('NestJS adapter - nestSignIn onAuthenticated', () => {
  let auth: ReturnType<typeof buildAuth>['auth']
  let adapter: ReturnType<typeof buildAuth>['adapter']

  beforeEach(() => {
    ;({ auth, adapter } = buildAuth())
  })

  async function seedIdentity(): Promise<string> {
    const ident = await adapter.identities.create(
      identityInput({ profile: { email: 'user@x.com', username: 'user' }, providers: [] }),
    )
    await auth.passwords.set(ident.id, 'correcthorsebatterystaple', adapter.credentials)
    return ident.id
  }

  function signInReq(): NestAdapter.Request {
    return {
      body: {
        input: { email: 'user@x.com', password: 'correcthorsebatterystaple' },
        providerId: 'password',
      },
      headers: {},
      method: 'POST',
      url: '/AUTH/signin',
    } as NestAdapter.Request
  }

  /** Is the SID the flow just minted still good? */
  async function sessionAlive(sid: string): Promise<boolean> {
    const resolved = await auth.resolveSession({ headers: new Headers({ cookie: `duck-sid=${sid}` }) })
    return resolved !== null
  }

  it('a hook returning nothing leaves the happy path untouched', async () => {
    await seedIdentity()
    const reply = makeReply()
    let sid = ''
    await nestSignIn(auth, {
      onAuthenticated: (outcome) => {
        sid = outcome.sid
      },
    })(signInReq(), reply)

    expect(reply._status).toBe(200)
    expect((reply._headers.get('set-cookie') ?? [])[0]).toContain('duck-sid=')
    expect(await sessionAlive(sid)).toBe(true)
  })

  it('the hook sees the identity behind the session it is gating', async () => {
    const identityId = await seedIdentity()
    const seen: (string | null | undefined)[] = []
    await nestSignIn(auth, {
      onAuthenticated: (outcome) => {
        seen.push(outcome.session?.identityId)
      },
    })(signInReq(), makeReply())

    expect(seen).toEqual([identityId])
  })

  it('a denial answers with the code and revokes the session it just created', async () => {
    await seedIdentity()
    const reply = makeReply()
    let sid = ''
    await nestSignIn(auth, {
      onAuthenticated: (outcome) => {
        sid = outcome.sid
        return { code: 'AUTH_NOT_PERMITTED_ON_HOST', detail: 'wrong host', status: 403 }
      },
    })(signInReq(), reply)

    expect(reply._status).toBe(403)
    expect(JSON.parse(reply._body!)).toEqual({
      error: { code: 'AUTH_NOT_PERMITTED_ON_HOST', detail: 'wrong host', status: 403 },
      ok: false,
    })
    // The one that matters: a 403 with a live session behind it is the bypass.
    expect(await sessionAlive(sid)).toBe(false)
  })

  it('a denial clears the cookie instead of leaving it on a dead session', async () => {
    await seedIdentity()
    const reply = makeReply()
    await nestSignIn(auth, {
      onAuthenticated: () => ({ code: 'AUTH_NOT_PERMITTED_ON_HOST', status: 403 }),
    })(signInReq(), reply)

    // `transport.revoke()` clears the SID and the CSRF cookie, so there is more than one.
    const cookies = reply._headers.get('set-cookie') ?? []
    expect(cookies.length).toBeGreaterThan(0)
    for (const cookie of cookies) expect(cookie).toMatch(/Max-Age=0/i)
    // No cookie may carry a value: a denial that ships a SID is the bug.
    expect(cookies.some((c) => /duck-sid=[^;]/.test(c))).toBe(false)
  })

  it('a denial the adapter cannot read still denies, at 403', async () => {
    await seedIdentity()
    const reply = makeReply()
    let sid = ''
    await nestSignIn(auth, {
      onAuthenticated: (outcome) => {
        sid = outcome.sid
        // A consumer bug: a 2xx would render the refusal as a success.
        return { code: '  ', status: 200 }
      },
    })(signInReq(), reply)

    expect(reply._status).toBe(403)
    expect(reply._body).toContain('AUTH_DENIED')
    expect(await sessionAlive(sid)).toBe(false)
  })

  it('a hook that throws does not leave the session behind', async () => {
    await seedIdentity()
    const reply = makeReply()
    let sid = ''
    await expect(
      nestSignIn(auth, {
        onAuthenticated: (outcome) => {
          sid = outcome.sid
          throw new Error('lookup exploded')
        },
      })(signInReq(), reply),
    ).rejects.toThrow('lookup exploded')

    expect(reply._status).toBe(500)
    expect(await sessionAlive(sid)).toBe(false)
  })

  it('the hook is never consulted when the credentials themselves fail', async () => {
    const reply = makeReply()
    let ran = false
    // No identity seeded: the password provider throws before any session exists, so there is
    // nothing for the hook to gate - and nothing for it to leak about who does exist.
    await expect(
      nestSignIn(auth, {
        onAuthenticated: () => {
          ran = true
        },
      })(signInReq(), reply),
    ).rejects.toMatchObject({ code: 'AUTH_INVALID_CREDENTIALS' })

    expect(ran).toBe(false)
    expect(reply._status).toBe(401)
  })
})
