/** The actor scope, end to end through the framework adapters. */

import { describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { actorId } from '~/core/actor'
import { AuthEngine } from '~/core/engine'
import { currentAuditEnvelope } from '~/core/events'
import type { Sessions } from '~/core/sessions/sessions.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { elysiaWithActor } from '~/server/elysia'
import { expressActorContext } from '~/server/express'
import { fastifyWithActor } from '~/server/fastify'
import { honoActorContext } from '~/server/hono'
import { koaActorContext } from '~/server/koa'
import { makeGuard, nestActorContext } from '~/server/nestjs'
import { nextWithActor } from '~/server/next'

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
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
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

describe('the adapters bind an actor scope around handler execution', () => {
  it('express middleware binds the session identity for everything downstream', async () => {
    const { auth } = buildAuth()
    const { identityId, sid } = await signIn(auth)

    let seen: string | null = 'never ran'
    await expressActorContext(auth)(
      { headers: cookieHeader(sid), method: 'POST', url: '/me' },
      // biome-ignore lint/suspicious/noExplicitAny: the middleware never touches the response.
      {} as any,
      () => {
        seen = actorId()
      },
    )
    expect(seen).toBe(identityId)
  })

  it('leaves the actor null for an anonymous request', async () => {
    const { auth } = buildAuth()
    let seen: string | null = 'never ran'
    await expressActorContext(auth)(
      { headers: {}, method: 'POST', url: '/me' },
      // biome-ignore lint/suspicious/noExplicitAny: the middleware never touches the response.
      {} as any,
      () => {
        seen = actorId()
      },
    )
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
    await expressActorContext(auth)(
      { headers: cookieHeader('not-a-real-sid'), method: 'POST', url: '/me' },
      // biome-ignore lint/suspicious/noExplicitAny: the middleware never touches the response.
      {} as any,
      () => {
        ran = true
        seen = actorId()
      },
    )
    expect(ran).toBe(true)
    expect(seen).toBeNull()
  })

  it('koa middleware binds across its awaited next()', async () => {
    const { auth } = buildAuth()
    const { identityId, sid } = await signIn(auth)

    let seen: string | null = 'never ran'
    await koaActorContext(auth)(
      // biome-ignore lint/suspicious/noExplicitAny: only `request.headers` is read.
      { request: { headers: cookieHeader(sid), method: 'POST' } } as any,
      async () => {
        // Deliberately after an await: the binding has to survive the boundary.
        await Promise.resolve()
        seen = actorId()
      },
    )
    expect(seen).toBe(identityId)
  })

  it('hono middleware binds across its awaited next()', async () => {
    const { auth } = buildAuth()
    const { identityId, sid } = await signIn(auth)

    let seen: string | null = 'never ran'
    await honoActorContext(auth)(
      // biome-ignore lint/suspicious/noExplicitAny: only `req.raw.headers` is read.
      { req: { raw: new Request('https://x/me', { headers: cookieHeader(sid) }) } } as any,
      async () => {
        await Promise.resolve()
        seen = actorId()
      },
    )
    expect(seen).toBe(identityId)
  })

  it('nest middleware reuses the session makeGuard already resolved', async () => {
    const { auth } = buildAuth()
    const { identityId, sid } = await signIn(auth)
    const resolved = await auth.resolveSession({ headers: new Headers(cookieHeader(sid)) })

    let seen: string | null = 'never ran'
    await nestActorContext(auth).use(
      // The guard ran first and populated `session`; no second resolveSession.
      // biome-ignore lint/suspicious/noExplicitAny: a NestAdapter.Request stub.
      { headers: {}, identity: null, method: 'POST', session: resolved.session } as any,
      {},
      () => {
        seen = actorId()
      },
    )
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
      // biome-ignore lint/suspicious/noExplicitAny: only `headers` is read.
    })({ headers: cookieHeader(sid), method: 'POST' } as any, {} as any)
    expect(fastifySeen).toBe(identityId)

    const elysiaSeen = await elysiaWithActor(
      auth,
      async () => new Response(actorId() ?? 'null'),
    )(
      // biome-ignore lint/suspicious/noExplicitAny: only `request.headers` is read.
      { request: new Request('https://x/me', { headers: cookieHeader(sid) }) } as any,
    ).then((r) => r.text())
    expect(elysiaSeen).toBe(identityId)
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
    await expressActorContext(auth)(
      { headers: cookieHeader(sid), method: 'POST', url: '/me' },
      // biome-ignore lint/suspicious/noExplicitAny: the middleware never touches the response.
      {} as any,
      () => {
        seen = actorId()
        envelope = currentAuditEnvelope()?.actingAs?.realIdentityId
      },
    )
    expect(seen).toBe('operator-7')
    expect(seen).not.toBe(identityId)
    // The audit envelope rides along, so an event emitted here names both.
    expect(envelope).toBe('operator-7')
  })
})

describe('what the middleware costs beside a guard', () => {
  it('costs one resolveSession for the pairing the adapter recommends', async () => {
    // `makeGuard` as an `APP_GUARD` with `nestActorContext` as middleware. Nest runs middleware
    // before guards, so the `req.session` shortcut could never fire from that side: the middleware
    // resolves, stashes the session and the identity, and the guard reuses both.
    const { auth } = buildAuth()
    const { identityId, sid } = await signIn(auth)
    const resolveSession = vi.spyOn(auth, 'resolveSession')

    // A Nest request object, in the order Nest touches it: middleware, then guard.
    const req = { headers: cookieHeader(sid), method: 'GET', url: '/me' }

    let sessionAtMiddleware: unknown = 'never ran'
    let identityAtMiddleware: unknown = 'never ran'
    let actorAtMiddleware: string | null = 'never ran'
    // biome-ignore lint/suspicious/noExplicitAny: a NestAdapter.Request stub.
    await nestActorContext(auth).use(req as any, {}, () => {
      sessionAtMiddleware = 'session' in req ? req.session : undefined
      identityAtMiddleware = 'identity' in req ? req.identity : undefined
      actorAtMiddleware = actorId()
    })

    await makeGuard(auth, { csrf: false }).canActivate({
      getHandler: () => () => undefined,
      switchToHttp: () => ({ getRequest: () => req }),
      // biome-ignore lint/suspicious/noExplicitAny: only `switchToHttp` is read.
    } as any)

    expect(actorAtMiddleware).toBe(identityId)
    // The middleware resolved it before calling next, so the handler sees it too.
    expect(sessionAtMiddleware).toMatchObject({ identityId })
    expect(identityAtMiddleware).toMatchObject({ id: identityId })
    expect(resolveSession).toHaveBeenCalledTimes(1)
  })

  /**
   * The shortcut is real, but only something that is not `makeGuard` can arm it: an earlier
   * middleware of the host application resolving the session itself and assigning it.
   */
  it('reuses a session an earlier middleware already put on the request', async () => {
    const { auth } = buildAuth()
    const { identityId, sid } = await signIn(auth)
    const resolved = await auth.resolveSession({ headers: new Headers(cookieHeader(sid)) })
    const resolveSession = vi.spyOn(auth, 'resolveSession')

    let seen: string | null = 'never ran'
    await nestActorContext(auth).use(
      // biome-ignore lint/suspicious/noExplicitAny: a NestAdapter.Request stub.
      { headers: {}, identity: null, method: 'GET', session: resolved.session } as any,
      {},
      () => {
        seen = actorId()
      },
    )

    expect(seen).toBe(identityId)
    expect(resolveSession).not.toHaveBeenCalled()
  })
})
