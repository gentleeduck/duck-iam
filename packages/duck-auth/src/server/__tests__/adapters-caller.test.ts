import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { elysiaSignIn } from '../elysia'
import { mountSignIn as expressSignIn } from '../express'
import { fastifySignIn } from '../fastify'
import { honoSignIn } from '../hono'
import { koaSignIn } from '../koa'
import { nestSignIn } from '../nestjs'
import { nextSignIn } from '../next'

/**
 * One case per adapter, asserting the session row it produced can name the device. The unit
 * tests next door prove the helper; these prove each adapter reaches for it, which is the part
 * that was missing everywhere and silently.
 *
 * Split by whether the framework resolves an address. express, fastify, koa and nest do, so
 * both land. hono, elysia and next are Web Request shaped and resolve none, so the user agent
 * lands and the address only if the host threaded it: reading a forwarded header inside the
 * library would take the value the caller wrote.
 */

const EMAIL = 'adapter@example.test'
const PASSWORD = 'correct-horse-battery'
const UA = 'iryss-adapter-probe/1.0'
const IP = '203.0.113.9'

type Profile = { email: string; username: string }

async function build() {
  const adapter = new MemoryAdapter<Profile>()
  const auth = new AuthEngine<Profile>({
    baseUrl: 'http://localhost',
    limiter: new MemoryLimiter({ max: 100, windowMs: 60_000 }),
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
  auth.providers.register(passwords<Profile>({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) }))

  const identity = await auth.identities.create({ profile: { email: EMAIL, username: 'adapter' }, providers: [] })
  await auth.passwords.set(identity.id, PASSWORD, adapter.credentials)
  return { auth, identity }
}

const BODY = { input: { email: EMAIL, password: PASSWORD }, providerId: 'password' }

async function sessionAfter(
  run: (auth: AuthEngine<Profile>) => Promise<unknown>,
): Promise<{ ip: string | null; userAgent: string | null }> {
  const { auth, identity } = await build()
  await run(auth)
  const [session] = await auth.sessions.listForIdentity(identity.id)
  return { ip: session?.ip ?? null, userAgent: session?.userAgent ?? null }
}

function nodeRes() {
  const res = {
    append: () => res,
    end: () => res,
    json: () => res,
    redirect: () => res,
    send: () => res,
    setHeader: () => res,
    status: () => res,
  }
  return res
}

describe('adapters hand the caller to signIn', () => {
  it('express passes the address it resolved and the user agent', async () => {
    const seen = await sessionAfter((auth) =>
      expressSignIn(auth)(
        { body: BODY, headers: { 'user-agent': UA }, ip: IP, method: 'POST', url: '/auth/signin' },
        nodeRes() as never,
      ),
    )

    expect(seen).toEqual({ ip: IP, userAgent: UA })
  })

  it('fastify does the same', async () => {
    const seen = await sessionAfter((auth) =>
      fastifySignIn(auth)({ body: BODY, headers: { 'user-agent': UA }, ip: IP, method: 'POST', url: '/auth/signin' }, {
        header: () => undefined,
        send: () => undefined,
        status: () => ({ header: () => undefined, send: () => undefined }),
      } as never),
    )

    expect(seen).toEqual({ ip: IP, userAgent: UA })
  })

  it('koa reads them off ctx.request', async () => {
    const ctx = {
      body: undefined,
      request: { body: BODY, headers: { 'user-agent': UA }, ip: IP, method: 'POST', url: '/auth/signin' },
      set: () => undefined,
      status: 200,
    }
    const seen = await sessionAfter((auth) => koaSignIn(auth)(ctx as never))

    expect(seen).toEqual({ ip: IP, userAgent: UA })
  })

  it('nest passes req.ip, not a forwarded header', async () => {
    const seen = await sessionAfter((auth) =>
      nestSignIn(auth)(
        {
          body: BODY,
          headers: { 'user-agent': UA, 'x-forwarded-for': '198.51.100.1' },
          identity: null,
          ip: IP,
          method: 'POST',
          session: null,
        },
        nodeRes() as never,
      ),
    )

    expect(seen).toEqual({ ip: IP, userAgent: UA })
  })

  it('hono records the user agent, and no address because it resolves none', async () => {
    const seen = await sessionAfter((auth) =>
      honoSignIn(auth)({
        req: {
          header: (n?: string) => (n?.toLowerCase() === 'user-agent' ? UA : undefined),
          json: async () => BODY,
          method: 'POST',
          param: () => undefined,
          raw: new Request('http://localhost/auth/signin'),
          url: 'http://localhost/auth/signin',
        },
      } as never),
    )

    expect(seen).toEqual({ ip: null, userAgent: UA })
  })

  it('hono takes an address when the host threaded one', async () => {
    const seen = await sessionAfter((auth) =>
      honoSignIn(auth)({
        ip: IP,
        req: {
          header: (n?: string) => (n?.toLowerCase() === 'user-agent' ? UA : undefined),
          json: async () => BODY,
          method: 'POST',
          param: () => undefined,
          raw: new Request('http://localhost/auth/signin'),
          url: 'http://localhost/auth/signin',
        },
      } as never),
    )

    expect(seen).toEqual({ ip: IP, userAgent: UA })
  })

  it('elysia records the user agent off the Web Request', async () => {
    const seen = await sessionAfter((auth) =>
      elysiaSignIn(auth)({
        body: BODY,
        request: new Request('http://localhost/auth/signin', { headers: { 'user-agent': UA }, method: 'POST' }),
      } as never),
    )

    expect(seen).toEqual({ ip: null, userAgent: UA })
  })

  it('next records the user agent and never an address', async () => {
    const seen = await sessionAfter((auth) =>
      nextSignIn(auth)(
        new Request('http://localhost/auth/signin', {
          body: JSON.stringify(BODY),
          headers: { 'content-type': 'application/json', 'user-agent': UA, 'x-forwarded-for': '198.51.100.1' },
          method: 'POST',
        }) as never,
      ),
    )

    expect(seen).toEqual({ ip: null, userAgent: UA })
  })
})
