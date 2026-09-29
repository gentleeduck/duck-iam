import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { elysiaCsrf } from '../index'

describe('elysiaCsrf', () => {
  async function run(method: string, headers: Record<string, string>) {
    const adapter = new MemoryAdapter()
    const auth = new AuthEngine({
      baseUrl: 'https://app',
      limiter: new MemoryLimiter({ max: 20, windowMs: 60_000 }),
      stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
      transport: new CookieTransport({ name: 'duck-sid', secure: false }),
    })
    const request = new Request('https://app/orders', { headers, method })
    return elysiaCsrf(auth)({ request })
  }

  it('lets a safe method through even from a cross-site context', async () => {
    expect(await run('GET', { 'sec-fetch-site': 'cross-site' })).toBeUndefined()
  })

  it('short-circuits a cross-site mutation with a 403 Response', async () => {
    const res = await run('POST', { 'sec-fetch-site': 'cross-site' })
    expect(res?.status).toBe(403)
    expect(await res?.text()).toContain('AUTH_CSRF')
  })

  it('lets a Bearer request through: no ambient cookie to forge', async () => {
    expect(await run('POST', { authorization: 'Bearer tok', 'sec-fetch-site': 'cross-site' })).toBeUndefined()
  })

  it('lets an ordinary same-origin mutation through', async () => {
    expect(await run('POST', { 'sec-fetch-site': 'same-origin' })).toBeUndefined()
  })
})
