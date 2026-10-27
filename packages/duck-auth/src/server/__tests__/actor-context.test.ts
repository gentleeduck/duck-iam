/** The actor scope, end to end through the framework adapters. */

import { describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { actorId, withActor, withRequestActor } from '~/core/actor'
import { AuthEngine } from '~/core/engine'
import { AuthError } from '~/core/errors'
import { currentAuditEnvelope, type Events, runWithAuditEnvelope } from '~/core/events'
import type { Sessions } from '~/core/sessions/sessions.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { elysiaWithActor } from '~/server/elysia'
import { expressActorContext, expressCaller } from '~/server/express'
import { fastifyWithActor } from '~/server/fastify'
import { GRPC_STATUS, withGrpc } from '~/server/grpc'
import { honoActorContext } from '~/server/hono'
import { koaActorContext } from '~/server/koa'
import { makeGuard, type NestAdapter, nestActorContext } from '~/server/nestjs'
import { nextWithActor } from '~/server/next'
import { expressRes, fastifyReply, honoCtx, koaCtx, nestCtx } from '~/test/adapter-fakes'

type Profile = { username: string; email: string }

function buildAuth() {
  const adapter = new MemoryAdapter<Profile>()
  const auth = new AuthEngine<Profile>({
    baseUrl: 'https://x',
    limiter: new MemoryLimiter({ max: 50, windowMs: 60_000 }),
    stores: {
      credentials: adapter.credentials,
      identities: adapter.identities,
      sessions: adapter.sessions,
    },
    transport: new CookieTransport({ name: 'duck-sid' }),
  })
  return { adapter, auth }
}

/** A real identity with a real session; `sid` is the plaintext the wire carries. */
async function signIn(
  auth: AuthEngine<Profile>,
  actingAs?: Sessions.ActingAs,
): Promise<{ identityId: string; sid: string }> {
  const identity = await auth.identities.create({
    emailVerified: true,
    profile: { email: `${Math.random().toString(36).slice(2)}@x.com`, username: 'a' },
  })
  const { sid } = await auth.sessions.create({
    aal: 1,
    factors: [],
    identityId: identity.id,
    kind: 'user',
    ...(actingAs && { actingAs }),
  })
  return { identityId: identity.id, sid }
}

const cookieHeader = (sid: string) => ({ cookie: `duck-sid=${sid}` })

/** A gRPC call carrying `cookie`, under `required: false` so only a raise keeps `handler` from running. */
function grpcAnswer(auth: AuthEngine<Profile>, cookie: string, handler: () => unknown): Promise<unknown> {
  return new Promise((resolve) =>
    withGrpc(
      auth,
      (_call, cb) => {
        handler()
        cb(null, {})
      },
      { required: false },
    )({ metadata: { get: (key) => (key === 'cookie' ? [cookie] : []) }, request: {} }, resolve),
  )
}

describe('the adapters bind an actor scope around handler execution', () => {
  it('express middleware binds the session identity for everything downstream', async () => {
    const { auth } = buildAuth()
    const { identityId, sid } = await signIn(auth)

    let seen: string | null = 'never ran'
    await expressActorContext(auth)({ headers: cookieHeader(sid), method: 'POST' }, expressRes, () => {
      seen = actorId()
    })
    expect(seen).toBe(identityId)
  })

  it('leaves the actor null for an anonymous request', async () => {
    const { auth } = buildAuth()
    let seen: string | null = 'never ran'
    await expressActorContext(auth)({ headers: {}, method: 'POST' }, expressRes, () => {
      seen = actorId()
    })
    // Not a placeholder and not a throw: no actor was established, and that is
    // exactly what the column should record.
    expect(seen).toBeNull()
  })

  /**
   * A stale or forged cookie on a public route must not become a 500. It leaves
   * the actor unbound, which is the same honest `null` as an anonymous request;
   * refusing the request is a guard's job, not the scope's.
   */
  it('runs the handler unbound when the session cannot be resolved', async () => {
    const { auth } = buildAuth()
    let ran = false
    let seen: string | null = 'never ran'
    await expressActorContext(auth)({ headers: cookieHeader('not-a-real-sid'), method: 'POST' }, expressRes, () => {
      ran = true
      seen = actorId()
    })
    expect(ran).toBe(true)
    expect(seen).toBeNull()
  })

  it('koa middleware binds across its awaited next()', async () => {
    const { auth } = buildAuth()
    const { identityId, sid } = await signIn(auth)

    let seen: string | null = 'never ran'
    await koaActorContext(auth)(koaCtx({ headers: cookieHeader(sid), method: 'POST' }), async () => {
      // Deliberately after an await: the binding has to survive the boundary.
      await Promise.resolve()
      seen = actorId()
    })
    expect(seen).toBe(identityId)
  })

  it('hono middleware binds across its awaited next()', async () => {
    const { auth } = buildAuth()
    const { identityId, sid } = await signIn(auth)

    let seen: string | null = 'never ran'
    await honoActorContext(auth)(honoCtx(new Request('https://x/me', { headers: cookieHeader(sid) })), async () => {
      await Promise.resolve()
      seen = actorId()
    })
    expect(seen).toBe(identityId)
  })

  it('nest middleware binds the session identity for everything downstream', async () => {
    const { auth } = buildAuth()
    const { identityId, sid } = await signIn(auth)

    let seen: string | null = 'never ran'
    await nestActorContext(auth)({ headers: cookieHeader(sid), identity: null, method: 'POST' }, {}, () => {
      seen = actorId()
    })
    expect(seen).toBe(identityId)
  })

  it('next, fastify and elysia wrappers bind around the handler they wrap', async () => {
    const { auth } = buildAuth()
    const { identityId, sid } = await signIn(auth)

    const nextSeen = await nextWithActor(
      auth,
      async () => new Response(actorId() ?? 'null'),
    )(new Request('https://x/me', { headers: cookieHeader(sid) })).then((r) => r.text())
    expect(nextSeen).toBe(identityId)

    let fastifySeen: string | null = 'never ran'
    await fastifyWithActor(auth, async () => {
      fastifySeen = actorId()
    })({ headers: cookieHeader(sid), method: 'POST' }, fastifyReply)
    expect(fastifySeen).toBe(identityId)

    const elysiaSeen = await elysiaWithActor(
      auth,
      async () => new Response(actorId() ?? 'null'),
    )({ request: new Request('https://x/me', { headers: cookieHeader(sid) }) }).then((r) => r.text())
    expect(elysiaSeen).toBe(identityId)
  })

  it('next passes the route context on with the request', async () => {
    const { auth } = buildAuth()
    const context = { params: Promise.resolve({ id: 'u-1' }) }
    const res = await nextWithActor(auth, async (_req: Request, ctx: typeof context) =>
      Response.json(await ctx.params),
    )(new Request('https://x/users/u-1'), context)
    expect(await res.json()).toEqual({ id: 'u-1' })
  })
})

describe('a request is attributed to its own session, never to the scope it arrived in', () => {
  // A server started inside a scope hands it to every request it takes, as these calls inherit it here.
  const anonymous = () => ({ headers: new Headers() })
  const profile = (username: string) => ({ email: `${username}@x.com`, username })

  it('an anonymous request writes and audits as nobody inside a system scope', async () => {
    const { auth } = buildAuth()
    const audits: Array<Events.Envelope | undefined> = []
    auth.events.on('signup.completed', (p) => void audits.push(p.audit))

    const created = await withActor('system', () =>
      withRequestActor(auth, anonymous(), () =>
        auth.identities.create({ emailVerified: false, profile: profile('anon') }),
      ),
    )
    expect(created.createdBy).toBeNull()
    expect(audits).toEqual([undefined])

    // The scope is live: the same write outside a request is the system's.
    const direct = await withActor('system', () =>
      auth.identities.create({ emailVerified: false, profile: profile('seeded') }),
    )
    expect(direct.createdBy).toBe('system')
    expect(audits[1]).toEqual({ actorId: 'system' })
  })

  it('a signed-in request inside a system scope is its own identity', async () => {
    const { auth } = buildAuth()
    const { identityId, sid } = await signIn(auth)
    const seen = await withActor('system', () =>
      withRequestActor(auth, { headers: new Headers(cookieHeader(sid)) }, async () => actorId()),
    )
    expect(seen).toBe(identityId)
  })

  it('an ambient audit envelope reaches neither a signed-in nor an anonymous request', async () => {
    const { auth } = buildAuth()
    const { identityId, sid } = await signIn(auth)
    const audits: Array<Events.Envelope | undefined> = []
    auth.events.on('session.revoked', (p) => void audits.push(p.audit))
    const system: Events.Envelope = { actorId: 'system' }

    await runWithAuditEnvelope(system, () =>
      withRequestActor(auth, { headers: new Headers(cookieHeader(sid)) }, () => auth.sessions.revoke(sid)),
    )
    expect(audits).toEqual([{ actorId: identityId }])
    const anon = await runWithAuditEnvelope(system, () =>
      withRequestActor(auth, anonymous(), async () => currentAuditEnvelope()),
    )
    expect(anon).toBeUndefined()
    expect(await runWithAuditEnvelope(system, async () => currentAuditEnvelope())).toBe(system)
  })

  it('nest runs a request without a session as nobody', async () => {
    const { auth } = buildAuth()
    let seen: string | null = 'never ran'
    await withActor('system', () =>
      nestActorContext(auth)({ headers: {}, identity: null, method: 'GET' }, {}, () => {
        seen = actorId()
      }),
    )
    expect(seen).toBeNull()
  })
})

describe("a tenant's session binds only where the request names its tenant", () => {
  const one = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined)
  /** One request carrying `sid` and, when given, an `x-tenant` header through a wrapper, which reads that header
   *  as its tenant when `named`; answers the actor it bound. */
  type Run = (auth: AuthEngine<Profile>, sid: string, tenant: string | undefined, named: boolean) => Promise<unknown>
  const headersFor = (sid: string, tenant: string | undefined) => ({
    ...cookieHeader(sid),
    ...(tenant !== undefined && { 'x-tenant': tenant }),
  })
  const RUNS: Record<string, Run> = {
    elysia: (auth, sid, tenant, named) =>
      elysiaWithActor(
        auth,
        async () => new Response(actorId() ?? ''),
        named ? { tenantId: (ctx) => ctx.request.headers.get('x-tenant') ?? undefined } : {},
      )({ request: new Request('https://x/me', { headers: headersFor(sid, tenant) }) })
        .then((r) => r.text())
        .then((t) => t || null),
    express: async (auth, sid, tenant, named) => {
      let seen: string | null = 'never ran'
      await expressActorContext(auth, named ? { tenantId: (req) => one(req.headers['x-tenant']) } : {})(
        { headers: headersFor(sid, tenant), method: 'POST' },
        expressRes,
        () => {
          seen = actorId()
        },
      )
      return seen
    },
    fastify: async (auth, sid, tenant, named) => {
      let seen: string | null = 'never ran'
      await fastifyWithActor(
        auth,
        async () => {
          seen = actorId()
        },
        named ? { tenantId: (req) => one(req.headers['x-tenant']) } : {},
      )({ headers: headersFor(sid, tenant), method: 'POST' }, fastifyReply)
      return seen
    },
    grpc: (auth, sid, tenant, named) =>
      new Promise((resolve) => {
        let seen: string | null = 'never ran'
        const values: Record<string, string[]> = { cookie: [`duck-sid=${sid}`], 'x-tenant': tenant ? [tenant] : [] }
        withGrpc(
          auth,
          (_call, cb) => {
            seen = actorId()
            cb(null, {})
          },
          named ? { required: false, tenantId: (call) => one(call.metadata.get('x-tenant')[0]) } : { required: false },
        )({ metadata: { get: (key) => values[key] ?? [] }, request: {} }, () => resolve(seen))
      }),
    hono: async (auth, sid, tenant, named) => {
      let seen: string | null = 'never ran'
      await honoActorContext(auth, named ? { tenantId: (ctx) => one(ctx.req.header('x-tenant')) } : {})(
        honoCtx(new Request('https://x/me', { headers: headersFor(sid, tenant) })),
        async () => {
          seen = actorId()
        },
      )
      return seen
    },
    koa: async (auth, sid, tenant, named) => {
      let seen: string | null = 'never ran'
      await koaActorContext(auth, named ? { tenantId: (ctx) => one(ctx.request.headers['x-tenant']) } : {})(
        koaCtx({ headers: headersFor(sid, tenant), method: 'POST' }),
        async () => {
          seen = actorId()
        },
      )
      return seen
    },
    nest: async (auth, sid, tenant, named) => {
      let seen: string | null = 'never ran'
      await nestActorContext(auth, named ? { tenantId: (req) => one(req.headers['x-tenant']) } : {})(
        { headers: headersFor(sid, tenant), identity: null, method: 'POST' },
        {},
        () => {
          seen = actorId()
        },
      )
      return seen
    },
    next: (auth, sid, tenant, named) =>
      nextWithActor(
        auth,
        async () => new Response(actorId() ?? ''),
        named ? { tenantId: (req) => req.headers.get('x-tenant') ?? undefined } : {},
      )(new Request('https://x/me', { headers: headersFor(sid, tenant) }))
        .then((r) => r.text())
        .then((t) => t || null),
  }

  it.each(Object.entries(RUNS))('%s', async (_name, run) => {
    const { auth } = buildAuth()
    const identity = await auth.identities.create({ emailVerified: true, profile: { email: 't@x.com', username: 't' } })
    const create = (tenantId?: string) =>
      auth.sessions.create({
        aal: 1,
        factors: [],
        identityId: identity.id,
        kind: 'user',
        ...(tenantId && { tenantId }),
      })
    const { sid } = await create('acme')
    const { sid: untenanted } = await create()

    expect(await run(auth, sid, 'acme', false)).toBeNull()
    expect(await run(auth, sid, undefined, true)).toBeNull()
    expect(await run(auth, sid, 'other', true)).toBeNull()
    expect(await run(auth, sid, 'acme', true)).toBe(identity.id)
    expect(await run(auth, untenanted, 'acme', true)).toBeNull()
    expect(await run(auth, untenanted, undefined, true)).toBe(identity.id)
  })

  it('names the tenant beside a caller fingerprint too', async () => {
    const { auth } = buildAuth()
    const identity = await auth.identities.create({ emailVerified: true, profile: { email: 't@x.com', username: 't' } })
    const { sid } = await auth.sessions.create({
      aal: 1,
      factors: [],
      identityId: identity.id,
      kind: 'user',
      tenantId: 'acme',
    })
    let seen: string | null = 'never ran'
    await expressActorContext(auth, {
      getCaller: expressCaller,
      onHijack: async () => {},
      tenantId: (req) => one(req.headers['x-tenant']),
    })({ headers: headersFor(sid, 'acme'), method: 'POST' }, expressRes, () => {
      seen = actorId()
    })
    expect(seen).toBe(identity.id)
  })

  it('nest makeGuard admits a tenant session only where the request names its tenant', async () => {
    const { auth } = buildAuth()
    const identity = await auth.identities.create({ emailVerified: true, profile: { email: 't@x.com', username: 't' } })
    const { sid } = await auth.sessions.create({
      aal: 1,
      factors: [],
      identityId: identity.id,
      kind: 'user',
      tenantId: 'acme',
    })
    const req = (tenant?: string): NestAdapter.Request => ({
      headers: headersFor(sid, tenant),
      identity: null,
      method: 'GET',
    })
    const named = makeGuard(auth, { csrf: false, tenantId: (r) => one(r.headers['x-tenant']) })

    await expect(makeGuard(auth, { csrf: false }).canActivate(nestCtx(req('acme')))).rejects.toMatchObject({
      code: 'AUTH_UNAUTHENTICATED',
    })
    await expect(named.canActivate(nestCtx(req('other')))).rejects.toMatchObject({ code: 'AUTH_UNAUTHENTICATED' })
    const admitted = req('acme')
    await expect(named.canActivate(nestCtx(admitted))).resolves.toBe(true)
    expect(admitted.identity).toMatchObject({ id: identity.id })
  })
})

describe('impersonation attributes the operator, not the account acted on', () => {
  /**
   * The subject is already the row being written; the column exists to name the
   * human accountable. `actingAs.realIdentityId` is that human, and it reached
   * audit events but never the provenance columns.
   */
  it('binds actingAs.realIdentityId as the actor', async () => {
    const { auth } = buildAuth()
    const { identityId, sid } = await signIn(auth, {
      expiresAt: new Date(Date.now() + 600_000),
      realIdentityId: 'operator-7',
      reason: 'support',
      startedAt: new Date(),
    })

    let seen: string | null = 'never ran'
    let envelope: string | undefined = 'never ran'
    await expressActorContext(auth)({ headers: cookieHeader(sid), method: 'POST' }, expressRes, () => {
      seen = actorId()
      envelope = currentAuditEnvelope()?.actingAs?.realIdentityId
    })
    expect(seen).toBe('operator-7')
    expect(seen).not.toBe(identityId)
    // The audit envelope rides along, so an event emitted here names both.
    expect(envelope).toBe('operator-7')
  })
})

describe('what the middleware costs beside a guard', () => {
  it('costs one resolveSession for the pairing the adapter recommends', async () => {
    // `makeGuard` as an `APP_GUARD` with `nestActorContext` as middleware. Nest runs middleware
    // before guards, so the guard reuses what the middleware resolved.
    const { auth } = buildAuth()
    const { identityId, sid } = await signIn(auth)
    const resolveSession = vi.spyOn(auth, 'resolveSession')

    // A Nest request object, in the order Nest touches it: middleware, then guard.
    const req: NestAdapter.Request = { headers: cookieHeader(sid), identity: null, method: 'GET' }

    let identityAtMiddleware: unknown = 'never ran'
    let actorAtMiddleware: string | null = 'never ran'
    await nestActorContext(auth)(req, {}, () => {
      identityAtMiddleware = req.identity
      actorAtMiddleware = actorId()
    })

    await makeGuard(auth, { csrf: false }).canActivate(nestCtx(req))

    expect(actorAtMiddleware).toBe(identityId)
    // The middleware resolved it before calling next, so the handler sees it too.
    expect(identityAtMiddleware).toMatchObject({ id: identityId })
    expect(resolveSession).toHaveBeenCalledTimes(1)
  })
})

describe('a session store that fails is raised, never run as nobody', () => {
  /** A signed-in cookie over a session store that has gone down since. */
  async function storeDown() {
    const { adapter, auth } = buildAuth()
    const { sid } = await signIn(auth)
    vi.spyOn(adapter.sessions, 'getByHash').mockImplementation(() => {
      throw new AuthError('AUTH_ADAPTER_UNAVAILABLE')
    })
    return { auth, headers: cookieHeader(sid) }
  }
  const down = { code: 'AUTH_ADAPTER_UNAVAILABLE' }

  it('reaches no handler through any wrapper', async () => {
    const { auth, headers } = await storeDown()
    const handler = vi.fn(async () => new Response('ok'))
    const passed: unknown[] = []

    await expect(withRequestActor(auth, { headers: new Headers(headers) }, handler)).rejects.toMatchObject(down)
    // Hono and Next answer a refusal themselves, and still raise a failure to the framework.
    await expect(
      honoActorContext(auth)(honoCtx(new Request('https://x/me', { headers })), async () => void handler()),
    ).rejects.toMatchObject(down)
    await expect(nextWithActor(auth, handler)(new Request('https://x/me', { headers }))).rejects.toMatchObject(down)
    await expect(
      koaActorContext(auth)(koaCtx({ headers, method: 'GET' }), async () => void handler()),
    ).rejects.toMatchObject(down)
    await expect(
      fastifyWithActor(auth, async () => void handler())({ headers, method: 'GET' }, fastifyReply),
    ).rejects.toMatchObject(down)
    await expect(
      elysiaWithActor(auth, handler)({ request: new Request('https://x/me', { headers }) }),
    ).rejects.toMatchObject(down)
    await expressActorContext(auth)({ headers, method: 'GET' }, expressRes, (err) => void passed.push(err))
    await nestActorContext(auth)({ headers, identity: null, method: 'GET' }, {}, (err) => {
      passed.push(err)
    })
    expect(await grpcAnswer(auth, headers.cookie, handler)).toEqual({
      code: GRPC_STATUS.UNAVAILABLE,
      message: 'AUTH_ADAPTER_UNAVAILABLE',
    })

    expect(passed).toEqual([expect.objectContaining(down), expect.objectContaining(down)])
    expect(handler).not.toHaveBeenCalled()
  })
})

describe('a session that outlived its identity is refused, never run as nobody', () => {
  it('reaches no handler through any wrapper', async () => {
    const { adapter, auth } = buildAuth()
    const { sid } = await signIn(auth)
    // An erase whose session cascade never landed.
    vi.spyOn(adapter.identities, 'find').mockRejectedValue(new AuthError('AUTH_IDENTITY_NOT_FOUND'))
    const headers = cookieHeader(sid)
    const erased = { code: 'AUTH_SESSION_IDENTITY_ERASED' }
    const handler = vi.fn(async () => new Response('ok'))
    const passed: unknown[] = []

    await expect(withRequestActor(auth, { headers: new Headers(headers) }, handler)).rejects.toMatchObject(erased)
    const answers = [
      await honoActorContext(auth)(honoCtx(new Request('https://x/me', { headers })), async () => void handler()),
      await nextWithActor(auth, handler)(new Request('https://x/me', { headers })),
    ]
    for (const answer of answers) {
      expect(answer?.status).toBe(401)
      expect(await answer?.json()).toMatchObject({ error: erased, ok: false })
    }
    await expect(
      koaActorContext(auth)(koaCtx({ headers, method: 'GET' }), async () => void handler()),
    ).rejects.toMatchObject(erased)
    await expect(
      fastifyWithActor(auth, async () => void handler())({ headers, method: 'GET' }, fastifyReply),
    ).rejects.toMatchObject(erased)
    await expect(
      elysiaWithActor(auth, handler)({ request: new Request('https://x/me', { headers }) }),
    ).rejects.toMatchObject(erased)
    await expressActorContext(auth)({ headers, method: 'GET' }, expressRes, (err) => void passed.push(err))
    await nestActorContext(auth)({ headers, identity: null, method: 'GET' }, {}, (err) => {
      passed.push(err)
    })
    expect(await grpcAnswer(auth, headers.cookie, handler)).toEqual({
      code: GRPC_STATUS.UNAUTHENTICATED,
      message: 'AUTH_SESSION_IDENTITY_ERASED',
    })

    expect(passed).toEqual([expect.objectContaining(erased), expect.objectContaining(erased)])
    expect(handler).not.toHaveBeenCalled()
  })
})
