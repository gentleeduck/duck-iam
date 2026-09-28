/** E2E: the actor wrappers mounted as each framework documents them, answering through that framework. */
import 'reflect-metadata'
import { createServer, type RequestListener, type Server } from 'node:http'
import * as grpc from '@grpc/grpc-js'
import {
  Controller,
  Get,
  type INestApplication,
  type MiddlewareConsumer,
  Module,
  type NestModule,
} from '@nestjs/common'
import { NestFactory } from '@nestjs/core'
import { type Context, Elysia } from 'elysia'
import express from 'express'
import Fastify, { type FastifyReply, type FastifyRequest } from 'fastify'
import { Hono } from 'hono'
import Koa from 'koa'
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { actorId } from '~/core/actor'
import { AuthEngine } from '~/core/engine'
import { AuthError } from '~/core/errors'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { elysiaWithActor } from '~/server/elysia'
import { expressActorContext } from '~/server/express'
import { fastifyCsrf, fastifyWithActor, registerFastify } from '~/server/fastify'
import { GRPC_STATUS, withGrpc } from '~/server/grpc'
import { honoActorContext } from '~/server/hono'
import { koaActorContext } from '~/server/koa'
import { NestExceptionFilter, nestActorContext } from '~/server/nestjs'

type Profile = { username: string; email: string }

const adapter = new MemoryAdapter<Profile>()
const auth = new AuthEngine<Profile>({
  baseUrl: 'https://app.test',
  limiter: new MemoryLimiter({ max: 1_000, windowMs: 60_000 }),
  stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
  transport: new CookieTransport({ name: 'duck-sid', secure: false }),
})

/** Every handler counts itself, so a refusal can be shown to have run nothing. */
let ran = 0

async function signIn(): Promise<{ cookie: string; id: string }> {
  const name = crypto.randomUUID()
  const identity = await auth.identities.create({ profile: { email: `${name}@x.test`, username: name } })
  const { sid } = await auth.sessions.create({ aal: 1, factors: [], identityId: identity.id, kind: 'user' })
  return { cookie: `duck-sid=${sid}`, id: identity.id }
}

/** An erase whose session cascade never landed. */
const eraseIdentities = () =>
  vi.spyOn(adapter.identities, 'find').mockRejectedValue(new AuthError('AUTH_IDENTITY_NOT_FOUND'))
const takeStoreDown = () =>
  vi.spyOn(adapter.sessions, 'getByHash').mockRejectedValue(new AuthError('AUTH_ADAPTER_UNAVAILABLE'))

afterEach(() => {
  vi.restoreAllMocks()
  ran = 0
})

/** A Node listener on a free loopback port, and the `get` that asks it for `/me`. */
async function serve(
  listener: RequestListener,
): Promise<{ get: (cookie?: string) => Promise<Answer>; server: Server }> {
  const server = createServer(listener)
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  if (typeof address !== 'object' || address === null) throw new Error('the server has no port')
  return {
    get: (cookie) => answer(fetch(`http://127.0.0.1:${address.port}/me`, { headers: cookie ? { cookie } : {} })),
    server,
  }
}

type Answer = { body: unknown; status: number }

/** JSON when the route answered, the framework's own error body otherwise. */
async function answer(pending: Promise<Response>): Promise<Answer> {
  const res = await pending
  return { body: res.ok ? await res.json() : await res.text(), status: res.status }
}

describe('Hono, with honoActorContext above the routes', () => {
  const app = new Hono()
  app.use(honoActorContext(auth))
  app.get('/me', (c) => {
    ran += 1
    return c.json({ actor: actorId() })
  })
  // The host's own handler, which a failure must reach.
  app.onError((err, c) => c.json({ code: err instanceof AuthError ? err.code : 'unknown' }, 503))

  const get = async (cookie?: string) => {
    const res = await app.request('/me', { headers: cookie ? { cookie } : {} })
    return { body: await res.json(), status: res.status }
  }

  it('serves a signed-in request as its identity and an anonymous one as nobody', async () => {
    const { cookie, id } = await signIn()
    expect(await get(cookie)).toEqual({ body: { actor: id }, status: 200 })
    expect(await get()).toEqual({ body: { actor: null }, status: 200 })
  })

  it('answers a refusal at its own status, without the handler', async () => {
    const { cookie } = await signIn()
    eraseIdentities()
    expect(await get(cookie)).toMatchObject({
      body: { error: { code: 'AUTH_SESSION_IDENTITY_ERASED' }, ok: false },
      status: 401,
    })
    expect(ran).toBe(0)
  })

  it('raises a store outage to the app’s onError, without the handler', async () => {
    const { cookie } = await signIn()
    takeStoreDown()
    expect(await get(cookie)).toEqual({ body: { code: 'AUTH_ADAPTER_UNAVAILABLE' }, status: 503 })
    expect(ran).toBe(0)
  })
})

describe('Nest, with nestActorContext applied to every route', () => {
  @Controller()
  class MeController {
    @Get('me')
    me() {
      ran += 1
      return { actor: actorId() }
    }
  }

  @Module({ controllers: [MeController] })
  class AppModule implements NestModule {
    configure(consumer: MiddlewareConsumer) {
      consumer.apply(nestActorContext(auth)).forRoutes('*')
    }
  }

  let app: INestApplication
  let origin = ''
  beforeAll(async () => {
    app = await NestFactory.create(AppModule, { logger: false })
    app.useGlobalFilters(new NestExceptionFilter())
    await app.listen(0, '127.0.0.1')
    origin = await app.getUrl()
  })
  afterAll(() => app?.close())

  const get = async (cookie?: string) => {
    const res = await fetch(`${origin}/me`, { headers: cookie ? { cookie } : {} })
    return { body: await res.json(), status: res.status }
  }

  it('serves a signed-in request as its identity and an anonymous one as nobody', async () => {
    const { cookie, id } = await signIn()
    expect(await get(cookie)).toEqual({ body: { actor: id }, status: 200 })
    expect(await get()).toEqual({ body: { actor: null }, status: 200 })
  })

  it('answers a refusal at its own status, without the handler', async () => {
    const { cookie } = await signIn()
    eraseIdentities()
    expect(await get(cookie)).toMatchObject({ status: 401 })
    expect(ran).toBe(0)
  })

  it('raises a store outage to the exception layer, without the handler', async () => {
    const { cookie } = await signIn()
    takeStoreDown()
    expect(await get(cookie)).toMatchObject({ status: 503 })
    expect(ran).toBe(0)
  })
})

describe('gRPC, with withGrpc around a unary handler', () => {
  const ser = (value: unknown) => Buffer.from(JSON.stringify(value))
  const de = (bytes: Buffer): unknown => JSON.parse(bytes.toString())
  const path = '/e2e.Actor/Me'
  const method = (at: string) => ({
    path: at,
    requestDeserialize: de,
    requestSerialize: ser,
    requestStream: false,
    responseDeserialize: de,
    responseSerialize: ser,
    responseStream: false,
  })
  const crash = () => {
    throw new TypeError('the host handler has a bug')
  }
  const server = new grpc.Server()
  server.addService(
    { crash: method('/e2e.Actor/Crash'), crashUnwrapped: method('/e2e.Actor/CrashUnwrapped'), me: method(path) },
    {
      crash: withGrpc(auth, crash, { required: false }),
      crashUnwrapped: crash,
      me: withGrpc(
        auth,
        (_call, cb) => {
          ran += 1
          cb(null, { actor: actorId() })
        },
        { required: false },
      ),
    },
  )

  let client: grpc.Client
  beforeAll(async () => {
    const port = await new Promise<number>((resolve, reject) =>
      server.bindAsync('127.0.0.1:0', grpc.ServerCredentials.createInsecure(), (err, bound) =>
        err ? reject(err) : resolve(bound),
      ),
    )
    client = new grpc.Client(`127.0.0.1:${port}`, grpc.credentials.createInsecure())
  })
  afterAll(() => {
    client?.close()
    server.forceShutdown()
  })

  const call = (cookie?: string, at = path) => {
    const metadata = new grpc.Metadata()
    if (cookie) metadata.set('cookie', cookie)
    return new Promise<unknown>((resolve) =>
      client.makeUnaryRequest(at, ser, de, {}, metadata, (err, value) =>
        resolve(err ? { code: err.code, details: err.details } : value),
      ),
    )
  }

  it('serves a signed-in call as its identity and an anonymous one as nobody', async () => {
    const { cookie, id } = await signIn()
    expect(await call(cookie)).toEqual({ actor: id })
    expect(await call()).toEqual({ actor: null })
  })

  it('answers a refusal as UNAUTHENTICATED, without the handler', async () => {
    const { cookie } = await signIn()
    eraseIdentities()
    expect(await call(cookie)).toEqual({ code: GRPC_STATUS.UNAUTHENTICATED, details: 'AUTH_SESSION_IDENTITY_ERASED' })
    expect(ran).toBe(0)
  })

  it('answers a store outage as UNAVAILABLE, without the handler', async () => {
    const { cookie } = await signIn()
    takeStoreDown()
    expect(await call(cookie)).toEqual({ code: GRPC_STATUS.UNAVAILABLE, details: 'AUTH_ADAPTER_UNAVAILABLE' })
    expect(ran).toBe(0)
  })

  it('answers a handler that throws as grpc-js answers it unwrapped, not as an auth error', async () => {
    const { cookie } = await signIn()
    const unwrapped = await call(cookie, '/e2e.Actor/CrashUnwrapped')
    expect(unwrapped).toEqual({ code: GRPC_STATUS.UNKNOWN, details: 'Unknown error' })
    expect(await call(cookie, '/e2e.Actor/Crash')).toEqual(unwrapped)
  })
})

describe('Express, with expressActorContext above the routes and no error handler of its own', () => {
  const app = express()
  app.use(expressActorContext(auth))
  app.get('/me', (_req, res) => {
    ran += 1
    res.json({ actor: actorId() })
  })

  let served: Awaited<ReturnType<typeof serve>>
  beforeAll(async () => {
    served = await serve(app)
  })
  afterAll(() => served?.server.close())

  it('serves a signed-in request as its identity and an anonymous one as nobody', async () => {
    const { cookie, id } = await signIn()
    expect(await served.get(cookie)).toEqual({ body: { actor: id }, status: 200 })
    expect(await served.get()).toEqual({ body: { actor: null }, status: 200 })
  })

  it('answers a refusal at the status Express reads off it, without the handler', async () => {
    const { cookie } = await signIn()
    eraseIdentities()
    expect(await served.get(cookie)).toMatchObject({ status: 401 })
    expect(ran).toBe(0)
  })

  it('raises a store outage to the error handler, without the handler', async () => {
    const { cookie } = await signIn()
    takeStoreDown()
    expect(await served.get(cookie)).toMatchObject({ status: 503 })
    expect(ran).toBe(0)
  })
})

describe('Koa, with koaActorContext above the routes and no error handler of its own', () => {
  const app = new Koa()
  app.silent = true
  app.use(koaActorContext(auth))
  app.use((ctx) => {
    ran += 1
    ctx.body = { actor: actorId() }
  })

  let served: Awaited<ReturnType<typeof serve>>
  beforeAll(async () => {
    served = await serve(app.callback())
  })
  afterAll(() => served?.server.close())

  it('serves a signed-in request as its identity and an anonymous one as nobody', async () => {
    const { cookie, id } = await signIn()
    expect(await served.get(cookie)).toEqual({ body: { actor: id }, status: 200 })
    expect(await served.get()).toEqual({ body: { actor: null }, status: 200 })
  })

  it('answers a refusal at the status Koa reads off it, without the handler', async () => {
    const { cookie } = await signIn()
    eraseIdentities()
    expect(await served.get(cookie)).toEqual({ body: 'Unauthorized', status: 401 })
    expect(ran).toBe(0)
  })

  it('raises a store outage to the error handler, without the handler', async () => {
    const { cookie } = await signIn()
    takeStoreDown()
    expect(await served.get(cookie)).toEqual({ body: 'Service Unavailable', status: 503 })
    expect(ran).toBe(0)
  })
})

describe('Fastify, with fastifyWithActor around a route and no error handler of its own', () => {
  const app = Fastify()
  // The whole adapter as documented, each piece typed as Fastify types it, which it has to accept.
  registerFastify(app, auth)
  app.addHook('preHandler', fastifyCsrf(auth))
  app.get(
    '/me',
    fastifyWithActor(auth, async (_req: FastifyRequest, _reply: FastifyReply) => {
      ran += 1
      return { actor: actorId() }
    }),
  )
  afterAll(() => app.close())

  const get = (cookie?: string) =>
    app.inject({ headers: cookie ? { cookie } : {}, method: 'GET', url: '/me' }).then((res) => ({
      body: res.json(),
      status: res.statusCode,
    }))

  it('serves a signed-in request as its identity and an anonymous one as nobody', async () => {
    const { cookie, id } = await signIn()
    expect(await get(cookie)).toEqual({ body: { actor: id }, status: 200 })
    expect(await get()).toEqual({ body: { actor: null }, status: 200 })
  })

  it('answers a refusal at the status Fastify reads off it, without the handler', async () => {
    const { cookie } = await signIn()
    eraseIdentities()
    expect(await get(cookie)).toMatchObject({ body: { code: 'AUTH_SESSION_IDENTITY_ERASED' }, status: 401 })
    expect(ran).toBe(0)
  })

  it('raises a store outage to the error handler, without the handler', async () => {
    const { cookie } = await signIn()
    takeStoreDown()
    expect(await get(cookie)).toMatchObject({ body: { code: 'AUTH_ADAPTER_UNAVAILABLE' }, status: 503 })
    expect(ran).toBe(0)
  })
})

describe('Elysia, with elysiaWithActor around a route and no error handler of its own', () => {
  // Typed as Elysia types it, which the wrapper has to accept.
  const app = new Elysia().get(
    '/me',
    elysiaWithActor(auth, async (_ctx: Context) => {
      ran += 1
      return { actor: actorId() }
    }),
  )

  const get = (cookie?: string) =>
    answer(app.handle(new Request('http://localhost/me', { headers: cookie ? { cookie } : {} })))

  it('serves a signed-in request as its identity and an anonymous one as nobody', async () => {
    const { cookie, id } = await signIn()
    expect(await get(cookie)).toEqual({ body: { actor: id }, status: 200 })
    expect(await get()).toEqual({ body: { actor: null }, status: 200 })
  })

  it('answers a refusal at the status Elysia reads off it, without the handler', async () => {
    const { cookie } = await signIn()
    eraseIdentities()
    expect(await get(cookie)).toMatchObject({ status: 401 })
    expect(ran).toBe(0)
  })

  it('raises a store outage to the error handler, without the handler', async () => {
    const { cookie } = await signIn()
    takeStoreDown()
    expect(await get(cookie)).toMatchObject({ status: 503 })
    expect(ran).toBe(0)
  })
})
