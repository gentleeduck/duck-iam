import type { CanActivate, MiddlewareConsumer } from '@nestjs/common'
import { ROUTE_ARGS_METADATA } from '@nestjs/common/constants'
import { ExecutionContextHost } from '@nestjs/core/helpers/execution-context-host'
import { beforeEach, describe, expect, expectTypeOf, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { actorId } from '~/core/actor'
import { AuthEngine } from '~/core/engine'
import { AuthError } from '~/core/errors'
import { isRecord } from '~/core/predicates'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { fastifyReply, nestCtx } from '~/test/adapter-fakes'
import { identityInput } from '~/test/store-inputs'
import {
  CurrentIdentity,
  CurrentSession,
  makeCsrfGuard,
  makeGuard,
  type NestAdapter,
  NestExceptionFilter,
  nestActorContext,
  nestCaller,
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

  it('signIn missing providerId -> 400 + AUTH_INVALID_CREDENTIALS', async () => {
    const reply = makeReply()
    await nestSignIn(auth)({ body: {}, headers: {}, identity: null, method: 'POST', url: '/AUTH/signin' }, reply)
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
        identity: null,
      },
      reply,
    )
    expect(reply._status).toBe(200)
    const cookies = reply._headers.get('set-cookie') ?? []
    expect(cookies.length).toBeGreaterThan(0)
    expect(cookies[0]).toContain('duck-sid=')
  })

  it('session returns null body without cookie', async () => {
    const reply = makeReply()
    await nestSession(auth)({ headers: {}, identity: null, method: 'GET' }, reply)
    expect(JSON.parse(reply._body!)).toEqual({ session: null, identity: null })
  })

  it('signOut clears cookie even without session', async () => {
    const reply = makeReply()
    await nestSignOut(auth)({ headers: {}, identity: null, method: 'POST' }, reply)
    const cookies = reply._headers.get('set-cookie') ?? []
    expect(cookies[0]).toMatch(/Max-Age=0/i)
  })

  it('providerBegin requires :id', async () => {
    const reply = makeReply()
    await nestProviderBegin(auth)({ body: {}, headers: {}, identity: null, method: 'POST', params: {} }, reply)
    expect(reply._status).toBe(400)
    expect(reply._body).toContain('AUTH_PROVIDER_FAILED')
  })
})

describe('NestJS adapter - makeGuard', () => {
  let auth: ReturnType<typeof buildAuth>['auth']

  beforeEach(() => {
    ;({ auth } = buildAuth())
  })

  it('required:true + no cookie -> throws AUTH_UNAUTHENTICATED', async () => {
    const guard = makeGuard(auth)
    const req: NestAdapter.Request = { method: 'GET', headers: {}, identity: null }
    await expect(guard.canActivate(nestCtx(req))).rejects.toMatchObject({ code: 'AUTH_UNAUTHENTICATED' })
  })

  it('required:false + no cookie -> passes, no mutation', async () => {
    const guard = makeGuard(auth, { required: false })
    const req: NestAdapter.Request = { method: 'GET', headers: {}, identity: null }
    const ok = await guard.canActivate(nestCtx(req))
    expect(ok).toBe(true)
    expect(req).toEqual({ headers: {}, identity: null, method: 'GET' })
  })
})

describe('NestJS adapter - the Nest slot each export is documented for', () => {
  it('the guards are a CanActivate, the middleware what `apply` keeps', () => {
    const { auth } = buildAuth()
    expectTypeOf(makeGuard(auth)).toExtend<CanActivate>()
    expectTypeOf(makeCsrfGuard(auth)).toExtend<CanActivate>()
    // `apply` drops anything but a function or a class without a word.
    expectTypeOf(nestActorContext(auth)).toExtend<Parameters<MiddlewareConsumer['apply']>[number]>()
  })
})

describe('NestJS adapter - CSRF', () => {
  function req(method: string, headers: Record<string, string>): NestAdapter.Request {
    return { headers, identity: null, method }
  }

  it('makeGuard verifies CSRF by default: a cross-site mutation is rejected', async () => {
    const { auth } = buildAuth()
    await expect(
      makeGuard(auth, { required: false }).canActivate(nestCtx(req('POST', { 'sec-fetch-site': 'cross-site' }))),
    ).rejects.toMatchObject({ code: 'AUTH_CSRF' })
  })

  it('makeGuard with csrf:false skips the check', async () => {
    const { auth } = buildAuth()
    const ok = await makeGuard(auth, { csrf: false, required: false }).canActivate(
      nestCtx(req('POST', { 'sec-fetch-site': 'cross-site' })),
    )
    expect(ok).toBe(true)
  })

  it('makeCsrfGuard rejects a cross-site mutation and allows a safe method', async () => {
    const { auth } = buildAuth()
    const guard = makeCsrfGuard(auth)
    await expect(guard.canActivate(nestCtx(req('POST', { 'sec-fetch-site': 'cross-site' })))).rejects.toMatchObject({
      code: 'AUTH_CSRF',
    })
    expect(await guard.canActivate(nestCtx(req('GET', { 'sec-fetch-site': 'cross-site' })))).toBe(true)
  })

  it('makeCsrfGuard lets a Bearer request through', async () => {
    const { auth } = buildAuth()
    const allowed = await makeCsrfGuard(auth).canActivate(
      nestCtx(req('POST', { authorization: 'Bearer tok', 'sec-fetch-site': 'cross-site' })),
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
      identity: null,
      method: 'POST',
      url: '/AUTH/signin',
    }
  }

  /** Is the SID the flow just minted still good? */
  async function sessionAlive(sid: string): Promise<boolean> {
    const resolved = await auth.resolveSession({ headers: new Headers({ cookie: `duck-sid=${sid}` }) }).orNull()
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

describe('NestJS adapter - a `req.session` duck-auth did not put there', () => {
  /** What express-session assigns to every request that arrives without its own cookie. */
  const hostSession = { cookie: { httpOnly: true, originalMaxAge: null, path: '/' } }

  /** A request as Nest hands it over once a host session middleware ran ahead of duck-auth. */
  function hosted(headers: Record<string, string> = {}): NestAdapter.Request {
    return Object.assign({ headers, identity: null, method: 'GET' }, { session: hostSession })
  }

  async function signedIn() {
    const { auth } = buildAuth()
    const identity = await auth.identities.create({ emailVerified: true, profile: { email: 'u@x.com', username: 'u' } })
    const { sid } = await auth.sessions.create({ aal: 1, factors: [], identityId: identity.id, kind: 'user' })
    return { auth, cookie: { cookie: `duck-sid=${sid}` }, identityId: identity.id }
  }

  /** What a param decorator hands the handler for `req`, through the factory Nest stores in route metadata. */
  function paramFor(decorator: () => ParameterDecorator, req: NestAdapter.Request): unknown {
    class Route {
      handle(_: unknown): void {}
    }
    decorator()(Route.prototype, 'handle', 0)
    const [arg] = Object.values(Reflect.getMetadata(ROUTE_ARGS_METADATA, Route, 'handle'))
    if (!isRecord(arg) || typeof arg.factory !== 'function') throw new Error('Nest stored no param factory')
    return arg.factory(undefined, nestCtx(req))
  }

  it('the guard refuses a request carrying no duck-auth session', async () => {
    const { auth, cookie } = await signedIn()
    await expect(makeGuard(auth).canActivate(nestCtx(hosted()))).rejects.toMatchObject({ code: 'AUTH_UNAUTHENTICATED' })
    expect(await makeGuard(auth).canActivate(nestCtx(hosted(cookie)))).toBe(true)
  })

  it('never writes `req.session`, filled or empty, and sets `req.identity`', async () => {
    const { auth, cookie, identityId } = await signedIn()
    const guarded = hosted(cookie)
    await makeGuard(auth).canActivate(nestCtx(guarded))
    const bound = hosted(cookie)
    await nestActorContext(auth)(bound, {}, () => undefined)
    const plain: NestAdapter.Request = { headers: cookie, identity: null, method: 'GET' }
    await makeGuard(auth).canActivate(nestCtx(plain))
    const boundPlain: NestAdapter.Request = { headers: cookie, identity: null, method: 'GET' }
    await nestActorContext(auth)(boundPlain, {}, () => undefined)
    for (const req of [guarded, bound]) {
      expect(req).toMatchObject({ identity: { id: identityId }, session: hostSession })
    }
    for (const req of [plain, boundPlain]) {
      expect(req).not.toHaveProperty('session')
      expect(req.identity).toMatchObject({ id: identityId })
      expect(paramFor(CurrentSession, req)).toMatchObject({ identityId })
    }
  })

  it('the middleware binds the duck-auth session, not the host one', async () => {
    const { auth, cookie, identityId } = await signedIn()
    const seen: Array<string | null> = []
    for (const req of [hosted(), hosted(cookie)]) {
      await nestActorContext(auth)(req, {}, () => void seen.push(actorId()))
    }
    expect(seen).toEqual([null, identityId])
  })

  it('the middleware still runs the detectors', async () => {
    const { auth, cookie } = await signedIn()
    const next = vi.fn()
    const middleware = nestActorContext(auth, { getCaller: nestCaller })
    await middleware(hosted(cookie), {}, next)
    expect(next).toHaveBeenLastCalledWith()
    auth.anomaly.register({ evaluate: async () => [{ evidence: {}, kind: 'x', score: 1 }], id: 'deny-all' })
    await middleware(hosted(cookie), {}, next)
    expect(next).toHaveBeenLastCalledWith(expect.objectContaining({ code: 'AUTH_ANOMALY_DENIED' }))
  })

  it('the param decorators answer what duck-auth resolved, never the host object', async () => {
    const { auth, cookie, identityId } = await signedIn()
    const anonymous = hosted()
    await makeGuard(auth, { required: false }).canActivate(nestCtx(anonymous))
    expect(paramFor(CurrentSession, anonymous)).toBeUndefined()
    expect(paramFor(CurrentIdentity, anonymous)).toBeUndefined()

    const signed = hosted(cookie)
    await makeGuard(auth).canActivate(nestCtx(signed))
    expect(paramFor(CurrentSession, signed)).toMatchObject({ identityId })
    expect(paramFor(CurrentIdentity, signed)).toMatchObject({ id: identityId })
  })
})

describe('NestJS adapter - the response it writes to', () => {
  it('throws on a reply with no setHeader, which a Fastify one was answered through without a header', async () => {
    const { auth } = buildAuth()
    const req: NestAdapter.Request = { headers: {}, identity: null, method: 'GET' }
    // @ts-expect-error Nest on Fastify hands over a reply with `header`, not `setHeader`
    await expect(nestSession(auth)(req, fastifyReply)).rejects.toThrow(TypeError)

    const reply = makeReply()
    await nestSession(auth)(req, reply)
    expect(reply._headers.get('cache-control')).toEqual(['no-store'])
  })

  /** What the exception filter wrote to a response whose `headersSent` is `sent`. */
  function filtered(
    sent: boolean,
    err: AuthError = new AuthError('AUTH_UNAUTHENTICATED'),
  ): { body?: unknown; status?: number } {
    const seen: { body?: unknown; status?: number } = {}
    const res = {
      headersSent: sent,
      status: (status: number) => {
        seen.status = status
        return {
          json: (body: unknown) => {
            seen.body = body
          },
        }
      },
    }
    new NestExceptionFilter().catch(err, new ExecutionContextHost([{}, res]))
    return seen
  }

  it('the exception filter answers an AuthError, and leaves a response a handler answered alone', () => {
    expect(filtered(false)).toEqual({
      body: { error: { code: 'AUTH_UNAUTHENTICATED', status: 401 }, ok: false },
      status: 401,
    })
    expect(filtered(true)).toEqual({})
  })

  it('the exception filter logs the cause of a 5xx it answers', () => {
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const fault = new AuthError('AUTH_MISCONFIGURED', { detail: 'the database is missing the auth schema' })
      expect(filtered(false, fault).status).toBe(500)
      expect(filtered(false).status).toBe(401)
      expect(logged.mock.calls).toEqual([['[@gentleduck/auth] request failed:', fault]])
    } finally {
      logged.mockRestore()
    }
  })
})
