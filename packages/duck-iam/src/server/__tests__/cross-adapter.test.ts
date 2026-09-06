import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../adapters/memory'
import { IamEngine } from '../../core/engine'
import type { IamRequest } from '../../core/types'
import { iamGuard as expressGuard, iamAccessMiddleware as expressMiddleware } from '../express'
import { IAM_UNKNOWN_RESOURCE, iamActionForMethod, iamDefaultResource, iamIsSubjectId } from '../generic'
import { iamGuard as honoGuard, iamAccessMiddleware as honoMiddleware } from '../hono'
import { IamAuthorize, iamNestAccessGuard, type NestRequest } from '../nest'
import { createIamNextMiddleware, withIamAccess } from '../next'

/**
 * The five framework integrations each build their own `(action, resource,
 * environment, scope)` tuple from a request and hand it to the same engine. A
 * policy is written once and expected to mean the same thing behind all five;
 * every divergence found so far - nest reading the last path segment, next's
 * middleware passing no environment, next's middleware skipping the
 * double-encoding residue check - was a place where one of them quietly built a
 * different tuple than the rest on the same bytes.
 *
 * Per-adapter suites cannot catch that: each one asserts its own answer. This
 * file drives one hostile-request table through all of them against a recording
 * engine and compares the tuples to each other.
 */

const USER = 'u1'

/** What an integration actually asked the engine. */
interface RecordedCall {
  action: string
  hasEnvironment: boolean
  resourceId: string | undefined
  resourceType: string
  scope: string | undefined
  subjectId: string
}

/**
 * Records the tuple instead of deciding it. Subclasses the real engine rather
 * than standing in for it structurally, so a change to `can()`'s signature
 * breaks this file instead of being absorbed by a hand-rolled double.
 */
class RecordingEngine extends IamEngine {
  readonly calls: RecordedCall[] = []

  /** @param verdict - The answer every recorded check returns. */
  constructor(private readonly verdict: boolean = true) {
    super({ adapter: new IamMemoryAdapter({}), cacheTTL: 0 })
  }

  override async can(
    subjectId: string,
    action: string,
    resource: IamRequest.IResource,
    environment?: IamRequest.IAccessRequest['environment'],
    scope?: string,
  ): Promise<boolean> {
    this.calls.push({
      action,
      hasEnvironment: environment !== undefined,
      resourceId: resource.id,
      resourceType: resource.type,
      scope,
      subjectId,
    })
    return this.verdict
  }
}

/**
 * Paths a router resolves one way and a naive authorization check reads
 * another, plus the plain controls that prove the table is not all one answer.
 */
const HOSTILE_REQUESTS = [
  { method: 'GET', path: '/posts/42' },
  { method: 'DELETE', path: '/posts/../admin/secret' },
  { method: 'POST', path: '//admin' },
  { method: 'GET', path: '/%61dmin' },
  { method: 'GET', path: '/posts/%252e%252e/admin' },
  { method: 'GET', path: '/' },
  { method: 'PATCH', path: '/posts/' },
  { method: 'GET', path: '/%zz' },
  { method: 'PROPFIND', path: '/posts/42' },
] as const

function expressRes() {
  return {
    body: undefined as unknown,
    json(body: unknown) {
      this.body = body
    },
    status(code: number) {
      this.statusCode = code
      return this
    },
    statusCode: 0,
  }
}

function honoCtx(path: string, method: string) {
  return {
    get: () => USER,
    json: (data: unknown, status = 200) => new Response(JSON.stringify(data), { status }),
    req: {
      header: () => undefined,
      method,
      param: () => undefined,
      path,
      url: `https://example.com${path}`,
    },
    set: () => undefined,
    text: (data: string, status = 200) => new Response(data, { status }),
  }
}

/** A route method carrying `@IamAuthorize({ infer: true })`, the inferring path. */
function inferringHandler() {
  const handler = function route() {
    return null
  }
  IamAuthorize({ infer: true })({}, 'route', { configurable: true, value: handler, writable: true })
  return handler
}

function nestCtx(request: NestRequest, handler: () => null) {
  return { getHandler: () => handler, switchToHttp: () => ({ getRequest: () => request }) }
}

describe('the path-deriving integrations build the same tuple', () => {
  // Positive control. Every assertion below is a three-way equality, which a
  // table that produced one constant answer would satisfy without pinning
  // anything - including the `unknown` refusal, the answer most worth pinning.
  it('the table produces more than one answer, including a refusal', () => {
    const types = new Set(HOSTILE_REQUESTS.map((r) => iamDefaultResource(r.path).type))
    const actions = new Set(HOSTILE_REQUESTS.map((r) => iamActionForMethod(r.method)))
    expect(types.size).toBeGreaterThan(3)
    expect(types.has(IAM_UNKNOWN_RESOURCE)).toBe(true)
    expect(actions.size).toBeGreaterThan(3)
  })

  for (const { method, path } of HOSTILE_REQUESTS) {
    it(`express, hono and nest agree on ${method} ${path}`, async () => {
      const expected = { action: iamActionForMethod(method), resourceType: iamDefaultResource(path).type }

      const express = new RecordingEngine()
      await expressMiddleware(express, { getUserId: () => USER })({ method, path }, expressRes(), vi.fn())

      const hono = new RecordingEngine()
      await honoMiddleware(hono)(honoCtx(path, method), async () => undefined)

      // No `request.route`: the fallback branch every nest test supplied a
      // `routePath` for, and the one platform-fastify actually takes.
      const nest = new RecordingEngine()
      await iamNestAccessGuard(nest, { getUserId: () => USER })(
        nestCtx({ method, params: {}, path }, inferringHandler()),
      )

      const tuples = [express, hono, nest].map((engine) => ({
        action: engine.calls[0]?.action,
        resourceType: engine.calls[0]?.resourceType,
      }))
      expect(tuples).toEqual([expected, expected, expected])
    })
  }
})

describe('createIamNextMiddleware refuses exactly what the others call `unknown`', () => {
  for (const { method, path } of HOSTILE_REQUESTS) {
    it(`${method} ${path}`, async () => {
      const engine = new RecordingEngine()
      // A catch-all rule, so the decision under test is the residue check and
      // not whether some prefix happened to match.
      const mw = createIamNextMiddleware(engine, {
        getUserId: () => USER,
        rules: [{ pattern: '/', resource: 'any' }],
      })

      const req = new Request(`https://example.com${path}`, { method })
      // The expectation is computed from the path the middleware can actually
      // see, not the one written above. `new Request(...)` resolves dot
      // segments while constructing the URL, so a traversal never reaches next
      // middleware to be refused - a Fetch-API limitation the express and
      // generic integrations do not share, recorded as a divergence in
      // `e2e-http-servers.e2e.test.ts`.
      const seenPath = new URL(req.url).pathname
      const res = await mw(req)

      if (iamDefaultResource(seenPath).type === IAM_UNKNOWN_RESOURCE) {
        expect(res?.status).toBe(403)
        // Refused before the engine, so a permissive rule cannot rescue it.
        expect(engine.calls).toEqual([])
        return
      }
      expect(res).toBeNull()
      expect(engine.calls[0]?.action).toBe(iamActionForMethod(method))
    })
  }
})

describe('nest route templates agree with the shared resource helper', () => {
  const TEMPLATES: ReadonlyArray<{ expected: string; template: string }> = [
    { expected: 'posts', template: '/posts/:id' },
    { expected: 'posts', template: 'posts' },
    // `'*'` is the engine's wildcard *pattern* sentinel: returned verbatim it
    // matched every `resources: ['*']` allow and no targeted deny.
    { expected: IAM_UNKNOWN_RESOURCE, template: '/*' },
    // A wildcard *after* the first segment is harmless: `/files/*path` only
    // ever routes under `/files`, which is exactly what a concrete request to
    // it resolves to in express and hono. Only a non-literal first segment
    // leaves the resource unnamed.
    { expected: 'files', template: '/files/*path' },
    { expected: IAM_UNKNOWN_RESOURCE, template: '/*path' },
    { expected: IAM_UNKNOWN_RESOURCE, template: '/%61dmin' },
    // Every segment is a parameter: nothing is named, so nothing is claimed.
    { expected: 'root', template: '/:id' },
    { expected: 'root', template: '/' },
  ]

  for (const { expected, template } of TEMPLATES) {
    it(`template ${template} authorizes against ${expected}`, async () => {
      const engine = new RecordingEngine()
      await iamNestAccessGuard(engine, { getUserId: () => USER })(
        nestCtx(
          { method: 'GET', params: {}, path: '/should-not-be-read', route: { path: template } },
          inferringHandler(),
        ),
      )
      expect(engine.calls[0]?.resourceType).toBe(expected)
    })
  }
})

describe('every integration passes a defined environment', () => {
  // The one that did not was `createIamNextMiddleware`: a rule keyed on
  // `environment.ip` / `.userAgent` / `.hour` never fired there while firing in
  // the other four on the same request, so a time-of-day or IP deny was absent
  // exactly where a next app puts its edge checks.
  it('all five hand `can` an environment object', async () => {
    const express = new RecordingEngine()
    await expressMiddleware(express, { getUserId: () => USER })(
      { method: 'GET', path: '/posts/42' },
      expressRes(),
      vi.fn(),
    )

    const hono = new RecordingEngine()
    await honoMiddleware(hono)(honoCtx('/posts/42', 'GET'), async () => undefined)

    const nest = new RecordingEngine()
    await iamNestAccessGuard(nest, { getUserId: () => USER })(
      nestCtx({ method: 'GET', params: {}, path: '/posts/42' }, inferringHandler()),
    )

    const nextRoute = new RecordingEngine()
    await withIamAccess(nextRoute, 'read', 'posts', async () => new Response('ok'), { getUserId: () => USER })(
      new Request('https://example.com/posts/42'),
      { params: { id: '42' } },
    )

    const nextMw = new RecordingEngine()
    await createIamNextMiddleware(nextMw, {
      getUserId: () => USER,
      rules: [{ pattern: '/posts', resource: 'posts' }],
    })(new Request('https://example.com/posts/42'))

    const engines = [express, hono, nest, nextRoute, nextMw]
    expect(engines.map((e) => e.calls.length)).toEqual([1, 1, 1, 1, 1])
    expect(engines.map((e) => e.calls[0]?.hasEnvironment)).toEqual([true, true, true, true, true])
  })
})

describe('a throwing getUserId stays inside the integration', () => {
  // `adapter-failure-mode-parity.test.ts` covers express (both entry points),
  // hono's middleware, nest and `withIamAccess`. These are the two remaining
  // rows of that table.
  const boom = () => {
    throw new Error('idp down')
  }

  it('hono guard routes it to onError', async () => {
    const onError = vi.fn((_err: Error) => new Response(null, { status: 500 }))
    const res = await honoGuard(new RecordingEngine(), 'read', 'posts', { getUserId: boom, onError })(
      honoCtx('/posts/42', 'GET'),
      async () => undefined,
    )
    expect(res?.status).toBe(500)
    expect(onError.mock.calls[0]?.[0]?.message).toBe('idp down')
  })

  it('createIamNextMiddleware routes it to onError', async () => {
    const onError = vi.fn((_err: Error) => Response.json({ error: 'Internal server error' }, { status: 500 }))
    const mw = createIamNextMiddleware(new RecordingEngine(), {
      getUserId: boom,
      onError,
      rules: [{ pattern: '/posts', resource: 'posts' }],
    })
    const res = await mw(new Request('https://example.com/posts/42'))
    expect(res?.status).toBe(500)
    expect(onError.mock.calls[0]?.[0]?.message).toBe('idp down')
  })
})

describe('the authz try wraps the check, not the downstream handler', () => {
  // Hono was the only one of the five that `await`ed the downstream handler
  // inside its own try. A business-logic error thrown by the route came back
  // out of `await next()`, was caught here, and was reported through the
  // middleware's `onError` - documented as "handles thrown errors during
  // evaluation" - which pre-empted the app's own `app.onError` and turned every
  // route failure into an authorization-shaped 500.
  const routeBlewUp = async () => {
    throw new Error('route blew up')
  }

  it('hono middleware lets a route error past onError', async () => {
    const onError = vi.fn((_err: Error) => new Response(null, { status: 500 }))
    const mw = honoMiddleware(new RecordingEngine(), { onError })
    await expect(mw(honoCtx('/posts/42', 'GET'), routeBlewUp)).rejects.toThrow('route blew up')
    expect(onError).not.toHaveBeenCalled()
  })

  it('hono guard lets a route error past onError', async () => {
    const onError = vi.fn((_err: Error) => new Response(null, { status: 500 }))
    const guard = honoGuard(new RecordingEngine(), 'read', 'posts', { getUserId: () => USER, onError })
    await expect(guard(honoCtx('/posts/42', 'GET'), routeBlewUp)).rejects.toThrow('route blew up')
    expect(onError).not.toHaveBeenCalled()
  })

  // Control: the same `onError` still fires for a failure inside the check, so
  // moving `next()` out did not simply disconnect the hook.
  it('hono still routes an evaluation error to onError', async () => {
    const onError = vi.fn((_err: Error) => new Response(null, { status: 500 }))
    const mw = honoMiddleware(new RecordingEngine(), {
      getUserId: () => {
        throw new Error('idp down')
      },
      onError,
    })
    const res = await mw(honoCtx('/posts/42', 'GET'), routeBlewUp)
    expect(res?.status).toBe(500)
    expect(onError.mock.calls[0]?.[0]?.message).toBe('idp down')
  })
})

describe('express never offers `next` to an error hook', () => {
  // `onError` used to receive express's `next`, and the obvious handler to
  // write with it - `(err, req, res, next) => next()` - continues the chain,
  // which is a fail-open on the exact path where the check did not complete.
  // The hook cannot be handed what it must not call.
  const boom = () => {
    throw new Error('idp down')
  }

  it('calls onError with (err, req, res) and nothing else', async () => {
    const onError = vi.fn()
    const next = vi.fn()
    await expressMiddleware(new RecordingEngine(), { getUserId: boom, onError })(
      { method: 'GET', path: '/posts/42' },
      expressRes(),
      next,
    )
    expect(onError).toHaveBeenCalledOnce()
    expect(onError.mock.calls[0]?.length).toBe(3)
    expect(next).not.toHaveBeenCalled()
  })
})

describe('createIamNextMiddleware answers through its hooks', () => {
  // The three literal responses here were the only unhookable ones of the five:
  // an app that renders its own sign-in redirect or problem+json got a bare
  // `{"error":"Unauthorized"}` from next's middleware and nothing else.
  it('routes the 401 through onUnauthorized', async () => {
    const onUnauthorized = vi.fn(() => new Response(null, { status: 302 }))
    const mw = createIamNextMiddleware(new RecordingEngine(), {
      getUserId: () => null,
      onUnauthorized,
      rules: [{ pattern: '/posts', resource: 'posts' }],
    })
    expect((await mw(new Request('https://example.com/posts/42')))?.status).toBe(302)
    expect(onUnauthorized).toHaveBeenCalledOnce()
  })

  it('routes the 403 through onDenied', async () => {
    const onDenied = vi.fn(() => new Response(null, { status: 418 }))
    const mw = createIamNextMiddleware(new RecordingEngine(false), {
      getUserId: () => USER,
      onDenied,
      rules: [{ pattern: '/posts', resource: 'posts' }],
    })
    expect((await mw(new Request('https://example.com/posts/42')))?.status).toBe(418)
    expect(onDenied).toHaveBeenCalledOnce()
  })

  it('routes the double-encoded-path refusal through onDenied too', async () => {
    const onDenied = vi.fn(() => new Response(null, { status: 418 }))
    const mw = createIamNextMiddleware(new RecordingEngine(), {
      getUserId: () => USER,
      onDenied,
      rules: [{ pattern: '/', resource: 'any' }],
    })
    expect((await mw(new Request('https://example.com/posts/%252e%252e/admin')))?.status).toBe(418)
    expect(onDenied).toHaveBeenCalledOnce()
  })
})

/**
 * `iamIsSubjectId` is `typeof value === 'string' && value.trim().length > 0`,
 * and it is the only layer that refuses a blank or non-string subject id -
 * `engine.can` guards `length === 0`, not `trim()`, so `'   '` is a perfectly
 * good key to it and any assignment stored under that key grants its
 * permissions.
 *
 * Six of the seven call sites were pinned by nothing: mutating `!iamIsSubjectId(userId)`
 * to `userId == null` at all of them survived the suite, and only express's
 * middleware had a test. The predicate itself had no direct test either. This
 * drives every entry point through the same table so one weakened guard cannot
 * hide behind the others.
 *
 * The `null`/`undefined` rows do not discriminate on their own - `== null`
 * catches those too. The blank strings and the non-strings are the half that
 * fails under the mutant, and they are also the half a real `getUserId` returns
 * by accident: a header that arrived as spaces, or a numeric id from a JWT.
 */
describe('no integration lets a blank or non-string subject id reach the engine', () => {
  const REFUSED: readonly [string, unknown][] = [
    ['a whitespace-only string', '   '],
    ['the empty string', ''],
    ['a tab and a newline', '\t\n'],
    ['a number', 42],
    ['a boolean', true],
    ['an object', {}],
    ['an array', []],
    ['null', null],
    ['undefined', undefined],
  ]

  // `unknown`, not `Promise<unknown>`: express's middleware and guard return
  // `void` while the other five return a promise. `await` handles both.
  const ENTRY_POINTS: readonly [string, (engine: RecordingEngine, getUserId: () => never) => unknown][] = [
    [
      'express middleware',
      (e, g) => expressMiddleware(e, { getUserId: g })({ method: 'GET', path: '/posts/42' }, expressRes(), vi.fn()),
    ],
    [
      'express guard',
      (e, g) =>
        expressGuard(e, 'read', 'posts', { getUserId: g })(
          { method: 'GET', params: {}, path: '/posts/42' },
          expressRes(),
          vi.fn(),
        ),
    ],
    [
      'hono middleware',
      (e, g) => honoMiddleware(e, { getUserId: g })(honoCtx('/posts/42', 'GET'), async () => undefined),
    ],
    [
      'hono guard',
      (e, g) => honoGuard(e, 'read', 'posts', { getUserId: g })(honoCtx('/posts/42', 'GET'), async () => undefined),
    ],
    [
      'nest guard',
      (e, g) =>
        iamNestAccessGuard(e, { getUserId: g })(
          nestCtx({ method: 'GET', params: {}, path: '/posts/42' }, inferringHandler()),
        ),
    ],
    [
      'next withIamAccess',
      (e, g) =>
        withIamAccess(e, 'read', 'posts', async () => new Response('ok'), { getUserId: g })(
          new Request('https://example.com/posts/42'),
          { params: { id: '42' } },
        ),
    ],
    [
      'next middleware',
      (e, g) =>
        createIamNextMiddleware(e, { getUserId: g, rules: [{ pattern: '/posts', resource: 'posts' }] })(
          new Request('https://example.com/posts/42'),
        ),
    ],
  ]

  for (const [entry, run] of ENTRY_POINTS) {
    for (const [label, value] of REFUSED) {
      it(`${entry} refuses ${label} without asking the engine`, async () => {
        const engine = new RecordingEngine()
        await run(engine, (() => value) as never)
        expect(engine.calls).toEqual([])
      })
    }

    it(`${entry} still asks the engine for a real subject id`, async () => {
      // Positive control per entry point: an integration that refused every
      // request would satisfy every row above.
      const engine = new RecordingEngine()
      await run(engine, (() => USER) as never)
      expect(engine.calls.map((c) => c.subjectId)).toEqual([USER])
    })
  }
})

describe('iamIsSubjectId itself', () => {
  it('accepts a non-blank string and nothing else', () => {
    for (const ok of ['u1', ' u1 ', '0', 'false']) expect(iamIsSubjectId(ok)).toBe(true)
    for (const bad of ['', '   ', '\t\n', 42, 0, true, false, null, undefined, {}, [], ['u1']]) {
      expect(iamIsSubjectId(bad)).toBe(false)
    }
  })
})
