/** The vanilla client against each adapter's own handlers, on its real framework as the framework comes. */
import 'reflect-metadata'
import { createServer, type RequestListener, type Server } from 'node:http'
import { Controller, Get, type INestApplication, Module, Post, Req, Res } from '@nestjs/common'
import { NestFactory } from '@nestjs/core'
import { Elysia } from 'elysia'
import express from 'express'
import Fastify from 'fastify'
import { Hono } from 'hono'
import Koa from 'koa'
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { createAuthClient } from '~/client/vanilla'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { elysiaSession, elysiaSignIn, elysiaSignOut } from '~/server/elysia'
import { mountSession, mountSignIn, mountSignOut } from '~/server/express'
import { registerFastify } from '~/server/fastify'
import { mountHono } from '~/server/hono'
import { koaSession, koaSignIn, koaSignOut } from '~/server/koa'
import { type NestAdapter, nestSession, nestSignIn, nestSignOut } from '~/server/nestjs'
import { mountNext } from '~/server/next'
import { browserFetch, type Profile } from '~/test/browser-over-engine'

const adapter = new MemoryAdapter<Profile>()
const auth = new AuthEngine<Profile>({
  baseUrl: 'http://localhost',
  // Every framework signs the one account in three times.
  limiter: new MemoryLimiter({ max: 100, windowMs: 60_000 }),
  providers: [passwords<Profile>({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) })],
  stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
  transport: new CookieTransport({ name: 'duck-sid', secure: false }),
})

/** A Node listener on a free loopback port, and its origin. */
async function listen(listener: RequestListener): Promise<{ origin: string; server: Server }> {
  const server = createServer(listener)
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  if (typeof address !== 'object' || address === null) throw new Error('the server has no port')
  return { origin: `http://127.0.0.1:${address.port}`, server }
}

@Controller('auth')
class AuthController {
  @Post('signin')
  signIn(@Req() req: NestAdapter.Request, @Res() res: NestAdapter.Response) {
    return nestSignIn(auth)(req, res)
  }

  @Post('signout')
  signOut(@Req() req: NestAdapter.Request, @Res() res: NestAdapter.Response) {
    return nestSignOut(auth)(req, res)
  }

  @Get('session')
  session(@Req() req: NestAdapter.Request, @Res() res: NestAdapter.Response) {
    return nestSession(auth)(req, res)
  }
}

@Module({ controllers: [AuthController] })
class AppModule {}

const hono = new Hono()
mountHono(hono, auth)

const elysia = new Elysia()
  .post('/auth/signin', elysiaSignIn(auth))
  .post('/auth/signout', elysiaSignOut(auth))
  .get('/auth/session', elysiaSession(auth))

const fastify = Fastify()
registerFastify(fastify, auth)

const expressApp = express()
expressApp.use(express.json())
expressApp.post('/auth/signin', mountSignIn(auth))
expressApp.post('/auth/signout', mountSignOut(auth))
expressApp.get('/auth/session', mountSession(auth))

const koa = new Koa()
koa.use(async (ctx, next) => {
  let text = ''
  for await (const chunk of ctx.req) text += chunk
  Object.assign(ctx.request, { body: text === '' ? undefined : JSON.parse(text) })
  await next()
})
koa.use(async (ctx) => {
  const route = `${ctx.method} ${ctx.path}`
  if (route === 'POST /auth/signin') await koaSignIn(auth)(ctx)
  if (route === 'POST /auth/signout') await koaSignOut(auth)(ctx)
  if (route === 'GET /auth/session') await koaSession(auth)(ctx)
})

const origins = { express: '', fastify: '', koa: '', nest: '' }
const servers: Server[] = []
let nest: INestApplication | undefined
beforeAll(async () => {
  const onExpress = await listen(expressApp)
  const onKoa = await listen(koa.callback())
  servers.push(onExpress.server, onKoa.server)
  origins.express = onExpress.origin
  origins.koa = onKoa.origin
  origins.fastify = await fastify.listen({ host: '127.0.0.1', port: 0 })
  nest = await NestFactory.create(AppModule, { logger: false })
  await nest.listen(0, '127.0.0.1')
  origins.nest = await nest.getUrl()
})
afterAll(async () => {
  for (const server of servers) server.close()
  await fastify.close()
  await nest?.close()
})
afterEach(() => vi.unstubAllGlobals())

let id = ''
beforeAll(async () => {
  ;({ id } = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a' } }))
  await auth.passwords.set(id, 'correct-pw', adapter.credentials)
})

describe.each<[string, () => (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>]>([
  ['Hono', () => browserFetch((req) => hono.fetch(req))],
  ['Elysia', () => browserFetch((req) => elysia.handle(req))],
  ['Next', () => browserFetch((req) => (req.method === 'POST' ? mountNext(auth).POST(req) : mountNext(auth).GET(req)))],
  ['Express', () => browserFetch(fetch, origins.express)],
  ['Fastify', () => browserFetch(fetch, origins.fastify)],
  ['Koa', () => browserFetch(fetch, origins.koa)],
  ['NestJS', () => browserFetch(fetch, origins.nest)],
])('%s', (_framework, browser) => {
  it('signs in, reads the session, and signs out on the server too', async () => {
    const client = createAuthClient<Profile>({ csrfCookieName: 'duck-csrf', fetch: browser() })
    const signedIn = await client.signIn({
      input: { email: 'a@x.com', password: 'correct-pw' },
      providerId: 'password',
    })
    expect(signedIn).toMatchObject({ data: { identity: { id } }, ok: true })
    expect(await client.signOut()).toMatchObject({ ok: true })
    expect(await client.getSession()).toMatchObject({ data: { identity: null, session: null }, ok: true })
  })

  it('ends the session a second sign-in in the same browser replaces', async () => {
    const client = createAuthClient<Profile>({ csrfCookieName: 'duck-csrf', fetch: browser() })
    const input = { input: { email: 'a@x.com', password: 'correct-pw' }, providerId: 'password' }
    await adapter.sessions.deleteAllForIdentity(id)
    await client.signIn(input)
    await client.signIn(input)
    expect(await adapter.sessions.listByIdentity(id)).toHaveLength(1)
    await client.signOut()
  })
})
