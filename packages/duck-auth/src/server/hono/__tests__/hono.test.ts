import { Hono } from 'hono'
import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { honoCsrf, toHonoAdapterCtx } from '../index'

describe('honoCsrf', () => {
  async function run(method: string, headers: Record<string, string>): Promise<Response> {
    const adapter = new MemoryAdapter()
    const auth = new AuthEngine({
      baseUrl: 'http://localhost',
      limiter: new MemoryLimiter({ max: 5, windowMs: 60_000 }),
      stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
      transport: new CookieTransport({ name: 'duck-sid', secure: false }),
    })
    const app = new Hono()
    app.use(honoCsrf(auth))
    app.on(['GET', 'POST'], '/orders', (c) => c.text('ran'))
    return app.request('/orders', { headers, method })
  }

  it('lets a safe method through even from a cross-site context', async () => {
    expect(await (await run('GET', { 'sec-fetch-site': 'cross-site' })).text()).toBe('ran')
  })

  it('refuses a cross-site mutation with a 403, before the route runs', async () => {
    const res = await run('POST', { 'sec-fetch-site': 'cross-site' })
    expect(res.status).toBe(403)
    expect(await res.text()).toContain('AUTH_CSRF')
  })

  it('lets a Bearer request through: no ambient cookie to forge', async () => {
    const res = await run('POST', { authorization: 'Bearer tok', 'sec-fetch-site': 'cross-site' })
    expect(await res.text()).toBe('ran')
  })

  it('lets an ordinary same-origin mutation through', async () => {
    expect(await (await run('POST', { 'sec-fetch-site': 'same-origin' })).text()).toBe('ran')
  })
})

describe('toHonoAdapterCtx', () => {
  it('answers a named header only as a string, and every header when unnamed', () => {
    const raw = new Request('https://x/', { headers: { 'x-a': '1' } })
    const ctx = toHonoAdapterCtx({ req: { header: (n) => (n === 'x-a' ? '1' : ['not', 'a', 'string']), raw } })
    expect(ctx.req.header('x-a')).toBe('1')
    expect(ctx.req.header('x-b')).toBeUndefined()
    expect(ctx.req.header()).toEqual({ 'x-a': '1' })
  })
})
