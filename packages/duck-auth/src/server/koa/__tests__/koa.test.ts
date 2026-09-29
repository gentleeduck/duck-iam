import { createServer } from 'node:http'
import Koa from 'koa'
import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { type KoaAdapter, koaApplyIntents, koaCsrf } from '../index'

function makeCtx(method: string, headers: Record<string, string>): KoaAdapter.Context {
  return { body: undefined, request: { headers, method }, set() {}, status: 200 }
}

function buildAuth() {
  const adapter = new MemoryAdapter()
  const auth = new AuthEngine({
    baseUrl: 'https://app',
    limiter: new MemoryLimiter({ max: 20, windowMs: 60_000 }),
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
  return { auth }
}

describe('koaCsrf', () => {
  async function run(method: string, headers: Record<string, string>) {
    const { auth } = buildAuth()
    const ctx = makeCtx(method, headers)
    let nexted = false
    await koaCsrf(auth)(ctx, async () => {
      nexted = true
    })
    return { ctx, nexted }
  }

  it('lets a safe method through even from a cross-site context', async () => {
    expect((await run('GET', { 'sec-fetch-site': 'cross-site' })).nexted).toBe(true)
  })

  it('rejects a cross-site mutation with 403 and never calls next', async () => {
    const { ctx, nexted } = await run('POST', { 'sec-fetch-site': 'cross-site' })
    expect(nexted).toBe(false)
    expect(ctx.status).toBe(403)
    expect(String(ctx.body)).toContain('AUTH_CSRF')
  })

  it('lets a Bearer request through: no ambient cookie to forge', async () => {
    expect((await run('POST', { authorization: 'Bearer tok', 'sec-fetch-site': 'cross-site' })).nexted).toBe(true)
  })

  it('lets an ordinary same-origin mutation through', async () => {
    expect((await run('POST', { 'sec-fetch-site': 'same-origin' })).nexted).toBe(true)
  })
})

describe('koaApplyIntents', () => {
  it('answers a host route on real Koa with one Set-Cookie header per cookie', async () => {
    const app = new Koa()
    app.use((ctx) =>
      koaApplyIntents(
        [
          { name: 'a', options: {}, type: 'setCookie', value: '1' },
          { name: 'b', options: {}, type: 'setCookie', value: '2' },
          { body: { ok: true }, status: 201, type: 'json' },
        ],
        ctx,
      ),
    )
    const server = createServer(app.callback())
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    const address = server.address()
    if (typeof address !== 'object' || address === null) throw new Error('the server has no port')
    try {
      const res = await fetch(`http://127.0.0.1:${address.port}/`)
      expect(res.status).toBe(201)
      expect(res.headers.getSetCookie()).toEqual(['a=1', 'b=2'])
      expect(await res.json()).toEqual({ ok: true })
    } finally {
      server.close()
    }
  })
})
