/** A CSRF check grants nothing, so every guard holds a mutation to the token of the session its cookie names,
 *  whatever that session's tenant, and no guard takes a tenant to get it wrong. */
import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { AuthError } from '~/core/errors'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { elysiaCsrf } from '~/server/elysia'
import { expressCsrf } from '~/server/express'
import { type FastifyAdapter, fastifyCsrf } from '~/server/fastify'
import { honoCsrf } from '~/server/hono'
import { koaCsrf } from '~/server/koa'
import { makeCsrfGuard, makeGuard, type NestAdapter } from '~/server/nestjs'
import { withNextCsrf } from '~/server/next'
import { expressRes, honoCtx, koaCtx, nestCtx } from '~/test/adapter-fakes'

/** A session in tenant `acme`, and the token its page holds. */
async function tenantSession() {
  const adapter = new MemoryAdapter()
  const auth = new AuthEngine({
    baseUrl: 'https://x',
    limiter: new MemoryLimiter({ max: 50, windowMs: 60_000 }),
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid' }),
  })
  const identity = await auth.identities.create({ emailVerified: true, profile: { email: 't@x.com', username: 't' } })
  const { csrfToken, sid } = await auth.sessions.create({
    aal: 1,
    factors: [],
    identityId: identity.id,
    kind: 'user',
    tenantId: 'acme',
  })
  return { auth, cookie: { cookie: `duck-sid=${sid}` }, csrfToken }
}

/** Whether a nest guard let the mutation through; a refusal other than CSRF's is raised. */
async function admitted(run: Promise<unknown>): Promise<boolean> {
  try {
    await run
    return true
  } catch (err) {
    if (err instanceof AuthError && err.code === 'AUTH_CSRF') return false
    throw err
  }
}

const post = (headers: Record<string, string>) => new Request('https://x/orders', { headers, method: 'POST' })
const nestReq = (headers: Record<string, string>): NestAdapter.Request => ({ headers, identity: null, method: 'POST' })

/** Whether each guard let a mutation carrying `headers` reach what it guards. */
const GUARDS: Record<string, (auth: AuthEngine, headers: Record<string, string>) => Promise<boolean>> = {
  elysia: async (auth, headers) => (await elysiaCsrf(auth)({ request: post(headers) })) === undefined,
  express: async (auth, headers) => {
    let ran = false
    await expressCsrf(auth)({ headers, method: 'POST' }, expressRes, () => {
      ran = true
    })
    return ran
  },
  fastify: async (auth, headers) => {
    let status = 200
    const reply: FastifyAdapter.Reply = {
      header: () => reply,
      send: () => reply,
      status: (code) => {
        status = code
        return reply
      },
    }
    await fastifyCsrf(auth)({ headers, method: 'POST' }, reply)
    return status === 200
  },
  hono: async (auth, headers) => {
    let ran = false
    await honoCsrf(auth)(honoCtx(post(headers)), async () => {
      ran = true
    })
    return ran
  },
  koa: async (auth, headers) => {
    let ran = false
    await koaCsrf(auth)(koaCtx({ headers, method: 'POST' }), async () => {
      ran = true
    })
    return ran
  },
  'nest makeCsrfGuard': (auth, headers) => admitted(makeCsrfGuard(auth).canActivate(nestCtx(nestReq(headers)))),
  'nest makeGuard': (auth, headers) =>
    admitted(makeGuard(auth, { required: false }).canActivate(nestCtx(nestReq(headers)))),
  next: async (auth, headers) => {
    let ran = false
    await withNextCsrf(auth, async () => {
      ran = true
      return new Response('ok')
    })(post(headers))
    return ran
  },
}

describe("every CSRF guard checks a tenant session's token without being told its tenant", () => {
  it.each(Object.entries(GUARDS))('%s', async (_name, passes) => {
    const { auth, cookie, csrfToken } = await tenantSession()

    expect(await passes(auth, cookie)).toBe(false)
    expect(await passes(auth, { ...cookie, 'x-csrf-token': 'not-the-token' })).toBe(false)
    expect(await passes(auth, { ...cookie, 'x-csrf-token': csrfToken })).toBe(true)
  })
})
