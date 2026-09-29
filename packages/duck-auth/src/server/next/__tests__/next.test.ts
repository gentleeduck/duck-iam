import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { withNextCsrf } from '../index'

function buildAuth() {
  const adapter = new MemoryAdapter()
  const auth = new AuthEngine({
    baseUrl: 'https://x',
    limiter: new MemoryLimiter({ max: 5, windowMs: 60_000 }),
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
  return { auth }
}

describe('withNextCsrf', () => {
  async function run(method: string, headers: Record<string, string>) {
    const { auth } = buildAuth()
    let reached = false
    const wrapped = withNextCsrf(auth, async () => {
      reached = true
      return Response.json({ ok: true })
    })
    const res = await wrapped(new Request('https://x/orders', { headers, method }))
    return { reached, res }
  }

  it('lets a safe method through even from a cross-site context', async () => {
    expect((await run('GET', { 'sec-fetch-site': 'cross-site' })).reached).toBe(true)
  })

  it('rejects a cross-site mutation with 403 and never reaches the handler', async () => {
    const { reached, res } = await run('POST', { 'sec-fetch-site': 'cross-site' })
    expect(reached).toBe(false)
    expect(res.status).toBe(403)
    expect(await res.text()).toContain('AUTH_CSRF')
  })

  it('lets a Bearer request through: no ambient cookie to forge', async () => {
    expect((await run('POST', { authorization: 'Bearer tok', 'sec-fetch-site': 'cross-site' })).reached).toBe(true)
  })

  it('lets an ordinary same-origin mutation through', async () => {
    expect((await run('POST', { 'sec-fetch-site': 'same-origin' })).reached).toBe(true)
  })

  it("hands the route's `{ params }` on to the handler", async () => {
    const { auth } = buildAuth()
    const wrapped = withNextCsrf(auth, async (_req: Request, ctx: { params: Promise<{ id: string }> }) =>
      Response.json(await ctx.params),
    )
    const res = await wrapped(new Request('https://x/orders/7'), { params: Promise.resolve({ id: '7' }) })
    expect(await res.json()).toEqual({ id: '7' })
  })
})
