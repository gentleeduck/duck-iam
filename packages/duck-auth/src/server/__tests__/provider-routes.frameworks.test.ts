/** An oauth sign-in begun and completed through each framework's own router, with the id as `client.beginProvider`
 *  sends it. */
import 'reflect-metadata'
import { createServer, type RequestListener, type Server } from 'node:http'
import { Controller, Get, type INestApplication, Module, Post, Req, Res } from '@nestjs/common'
import { NestFactory } from '@nestjs/core'
import { Elysia } from 'elysia'
import express from 'express'
import Fastify from 'fastify'
import { Hono } from 'hono'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { google } from '~/providers/oauth/google'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { elysiaProviderBegin, elysiaProviderCallback } from '~/server/elysia'
import { mountProviderBegin, mountProviderCallback } from '~/server/express'
import { registerFastify } from '~/server/fastify'
import { mountHono } from '~/server/hono'
import { type NestAdapter, nestProviderBegin, nestProviderCallback } from '~/server/nestjs'
import { mountNext } from '~/server/next'
import { afterOAuthBegin } from '~/test/oauth-browser'

/** Google's token and userinfo endpoints, answering one fixed account. */
const fakeGoogle: typeof globalThis.fetch = async (input) => {
  const url = String(input)
  if (url.startsWith('https://oauth2.googleapis.com/token')) {
    return Response.json({ access_token: 'at', expires_in: 3600, token_type: 'Bearer' })
  }
  if (url.startsWith('https://openidconnect.googleapis.com/v1/userinfo')) {
    return Response.json({ email: 'g@x.com', email_verified: true, sub: 'g-1' })
  }
  throw new Error(`unexpected ${url}`)
}

const adapter = new MemoryAdapter()
const auth = new AuthEngine({
  baseUrl: 'http://localhost',
  providers: [
    google({
      allowStateReplay: true,
      clientId: 'client-id',
      clientSecret: 'client-secret',
      fetch: fakeGoogle,
      profileToIdentityProfile: (p) => ({ email: p.email ?? '', username: p.sub }),
      redirectUri: 'http://localhost/auth/providers/oauth:google/callback',
      stateCookie: { name: 'duck-oauth', secure: false },
      stateSigningSecret: 'x'.repeat(32),
    }),
    passwords({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) }),
  ],
  stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
  transport: new CookieTransport({ name: 'duck-sid', secure: false }),
})

const BEGIN: RequestInit = {
  body: '{}',
  headers: { 'content-type': 'application/json' },
  method: 'POST',
  redirect: 'manual',
}

type Answer = { body: string; cookies: string[]; location: string | null; status: number }

const answer = async (res: Response): Promise<Answer> => ({
  body: await res.text(),
  cookies: res.headers.getSetCookie(),
  location: res.headers.get('location'),
  status: res.status,
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
  @Post('providers/:id/begin')
  begin(@Req() req: NestAdapter.Request, @Res() res: NestAdapter.Response) {
    return nestProviderBegin(auth)(req, res)
  }

  @Get('providers/:id/callback')
  callbackGet(@Req() req: NestAdapter.Request, @Res() res: NestAdapter.Response) {
    return nestProviderCallback(auth)(req, res)
  }

  @Post('providers/:id/callback')
  callbackPost(@Req() req: NestAdapter.Request, @Res() res: NestAdapter.Response) {
    return nestProviderCallback(auth)(req, res)
  }
}

@Module({ controllers: [AuthController] })
class AppModule {}

const hono = new Hono()
mountHono(hono, auth)

const elysia = new Elysia()
  .post('/auth/providers/:id/begin', elysiaProviderBegin(auth))
  .get('/auth/providers/:id/callback', elysiaProviderCallback(auth))
  .post('/auth/providers/:id/callback', elysiaProviderCallback(auth))

const fastify = Fastify()
fastify.addContentTypeParser('application/x-www-form-urlencoded', { parseAs: 'string' }, (_req, body, done) =>
  done(null, body),
)
registerFastify(fastify, auth)

const expressApp = express()
expressApp.use(express.json(), express.urlencoded({ extended: false }))
expressApp.post('/auth/providers/:id/begin', mountProviderBegin(auth))
expressApp.get('/auth/providers/:id/callback', mountProviderCallback(auth))
expressApp.post('/auth/providers/:id/callback', mountProviderCallback(auth))

const origins = { express: '', fastify: '', nest: '' }
let expressServer: Server | undefined
let nest: INestApplication | undefined
beforeAll(async () => {
  const served = await listen(expressApp)
  expressServer = served.server
  origins.express = served.origin
  origins.fastify = await fastify.listen({ host: '127.0.0.1', port: 0 })
  nest = await NestFactory.create(AppModule, { logger: false })
  await nest.listen(0, '127.0.0.1')
  origins.nest = await nest.getUrl()
})
afterAll(async () => {
  expressServer?.close()
  await fastify.close()
  await nest?.close()
})

describe.each<[string, (path: string, init: RequestInit) => Promise<Answer>]>([
  ['Hono', async (path, init) => answer(await hono.request(path, init))],
  ['Elysia', async (path, init) => answer(await elysia.handle(new Request(`http://localhost${path}`, init)))],
  [
    'Next',
    async (path, init) => {
      const req = new Request(`http://localhost${path}`, init)
      return answer(await (req.method === 'POST' ? mountNext(auth).POST(req) : mountNext(auth).GET(req)))
    },
  ],
  ['Express', async (path, init) => answer(await fetch(`${origins.express}${path}`, init))],
  ['Fastify', async (path, init) => answer(await fetch(`${origins.fastify}${path}`, init))],
  ['NestJS', async (path, init) => answer(await fetch(`${origins.nest}${path}`, init))],
])('%s', (_framework, send) => {
  it('begins it with a redirect to the IdP and the cookie binding the callback, `:` escaped or not', async () => {
    for (const id of [encodeURIComponent('oauth:google'), 'oauth:google']) {
      const res = await send(`/auth/providers/${id}/begin`, BEGIN)
      expect(res.status, id).toBe(302)
      expect(res.location).toMatch(/^https:\/\/accounts\.google\.com\/o\/oauth2\/v2\/auth\?/)
      expect(res.cookies).toEqual([expect.stringMatching(/^duck-oauth=/)])
    }
  })

  it('answers a script, which cannot follow the redirect, with the URL and the same cookie', async () => {
    const res = await send(`/auth/providers/${encodeURIComponent('oauth:google')}/begin`, {
      ...BEGIN,
      headers: { accept: 'application/json', 'content-type': 'application/json' },
    })
    expect(res.status).toBe(200)
    expect(res.location).toBeNull()
    expect(JSON.parse(res.body)).toEqual({
      url: expect.stringMatching(/^https:\/\/accounts\.google\.com\/o\/oauth2\/v2\/auth\?/),
    })
    expect(res.cookies).toEqual([expect.stringMatching(/^duck-oauth=/)])
  })

  it('refuses an id nobody registered', async () => {
    const res = await send(`/auth/providers/${encodeURIComponent('oauth:nope')}/begin`, BEGIN)
    expect(res.status).toBe(400)
    expect(res.location).toBeNull()
  })

  it.each([
    ['redirect', 'GET'],
    ['form post', 'POST'],
  ])('completes it on the callback, by %s', async (_, method) => {
    const { state, cookieHeader } = afterOAuthBegin(await auth.flows.beginProvider('oauth:google', {}))
    const params = new URLSearchParams({ code: 'authcode', state }).toString()
    const path = `/auth/providers/${encodeURIComponent('oauth:google')}/callback`
    const res =
      method === 'GET'
        ? await send(`${path}?${params}`, { headers: { cookie: cookieHeader }, redirect: 'manual' })
        : await send(path, {
            body: params,
            headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader },
            method,
            redirect: 'manual',
          })
    expect(res.status).toBe(200)
    expect(res.cookies).toContainEqual(expect.stringMatching(/^duck-sid=[^;]+/))
  })

  it('ends the session the callback replaces', async () => {
    const path = `/auth/providers/${encodeURIComponent('oauth:google')}/callback`
    const signIn = async (session?: string) => {
      const { state, cookieHeader } = afterOAuthBegin(await auth.flows.beginProvider('oauth:google', {}))
      const res = await send(`${path}?${new URLSearchParams({ code: 'authcode', state })}`, {
        headers: { cookie: session ? `${cookieHeader}; ${session}` : cookieHeader },
        redirect: 'manual',
      })
      return res.cookies.find((line) => line.startsWith('duck-sid='))?.split(';')[0] ?? ''
    }
    const live = (session: string) => auth.resolveSession({ headers: new Headers({ cookie: session }) }).orNull()
    const first = await signIn()
    const second = await signIn(first)
    expect(await live(second)).not.toBeNull()
    expect(first).not.toBe('')
    expect(await live(first)).toBeNull()
  })

  it('refuses the callback for a provider that is not oauth, before it runs', async () => {
    const res = await send('/auth/providers/password/callback?code=c&state=s', { redirect: 'manual' })
    expect(res.status).toBe(400)
    expect(res.cookies).toEqual([])
  })
})
