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
import { nestCtx } from '~/test/adapter-fakes'
import {
  CurrentIdentity,
  CurrentSession,
  makeCsrfGuard,
  makeGuard,
  type NestAdapter,
  NestExceptionFilter,
  nestActorContext,
  nestCaller,
} from '../index'

function buildAuth() {
  const adapter = new MemoryAdapter<{ username: string; email: string }>()
  const auth = new AuthEngine<{ username: string; email: string }>({
    baseUrl: 'https://app',
    limiter: new MemoryLimiter({ max: 20, windowMs: 60_000 }),
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
  return { auth }
}

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

describe('NestJS adapter - the exception filter', () => {
  /** What the exception filter wrote to a response whose `headersSent` is `sent`. */
  function filtered(
    sent: boolean,
    err: AuthError = new AuthError('AUTH_UNAUTHENTICATED'),
  ): { body?: unknown; cache?: string; status?: number } {
    const seen: { body?: unknown; cache?: string; status?: number } = {}
    const res = {
      headersSent: sent,
      setHeader: (name: string, value: string) => {
        if (name === 'cache-control') seen.cache = value
      },
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
      cache: 'no-store',
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
