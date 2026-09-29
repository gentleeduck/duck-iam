import express, { type RequestHandler } from 'express'
import { describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import type { Provider } from '~/core/provider/provider.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { executeIntents } from '~/server/generic'
import { applyIntents, expressCaller, expressCsrf, toHeaders } from '../index'

function mockRes() {
  const headers: Record<string, string[]> = {}
  let statusCode = 200
  let jsonBody: unknown = undefined
  let redirected: { status: number; location: string } | undefined
  const res = {
    status: vi.fn((c: number) => {
      statusCode = c
      return res
    }),
    setHeader: vi.fn((n: string, v: string) => {
      headers[n.toLowerCase()] = [String(v)]
      return res
    }),
    append: vi.fn((n: string, v: string) => {
      const key = n.toLowerCase()
      ;(headers[key] ??= []).push(v)
      return res
    }),
    json: vi.fn((b: unknown) => {
      jsonBody = b
      return res
    }),
    redirect: vi.fn((status: number, location: string) => {
      redirected = { status, location }
    }),
    end: vi.fn(),
  }
  return {
    res,
    get status() {
      return statusCode
    },
    get body() {
      return jsonBody
    },
    get redirected() {
      return redirected
    },
    headers,
  }
}

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

describe('toHeaders', () => {
  it('converts flat object to Headers + handles arrays + undefined', () => {
    const h = toHeaders({
      'content-type': 'text/plain',
      'set-cookie': ['a=1', 'b=2'],
      'x-empty': undefined,
    })
    expect(h.get('content-type')).toBe('text/plain')
    // Headers normalises set-cookie comma-joined; just verify both values are accessible.
    const sc = h.get('set-cookie')
    expect(sc).toBeTruthy()
    expect(h.get('x-empty')).toBeNull()
  })
})

describe('applyIntents', () => {
  it('writes setCookie as Set-Cookie header', () => {
    const r = mockRes()
    applyIntents(
      [
        {
          type: 'setCookie',
          name: 'duck-sid',
          value: 'abc',
          options: { httpOnly: true, secure: true, sameSite: 'lax', path: '/' },
        },
      ],
      r.res,
    )
    expect(r.headers['set-cookie']?.[0]).toMatch(/^duck-sid=abc/)
    expect(r.headers['set-cookie']?.[0]).toContain('HttpOnly')
    expect(r.headers['set-cookie']?.[0]).toContain('Secure')
    expect(r.headers['set-cookie']?.[0]).toContain('SameSite=Lax')
  })

  it('json intent writes status + body', () => {
    const r = mockRes()
    applyIntents([{ type: 'json', status: 200, body: { ok: true } }], r.res)
    expect(r.status).toBe(200)
    expect(r.body).toEqual({ ok: true })
  })

  it('redirect intent calls res.redirect', () => {
    const r = mockRes()
    applyIntents([{ type: 'redirect', url: '/foo', status: 303 }], r.res)
    expect(r.redirected).toEqual({ status: 303, location: '/foo' })
  })

  it.each<[string, Provider.Intent[]]>([
    ['an error', [{ type: 'error', code: 'AUTH_PROVIDER_FAILED', status: 400 }]],
    ['an error with a detail', [{ type: 'error', code: 'AUTH_PROVIDER_FAILED', status: 404, detail: 'unknown' }]],
    ['an unsafe redirect', [{ type: 'redirect', url: 'javascript:alert(1)' }]],
  ])('answers %s with the status and body executeIntents does', async (_, intents) => {
    const r = mockRes()
    applyIntents(intents, r.res)
    const web = executeIntents(intents)
    expect(r.status).toBe(web.status)
    expect(r.body).toEqual(await web.json())
    expect(r.body).toMatchObject({ error: { code: expect.any(String), status: web.status }, ok: false })
  })
})

describe('a stock Express 5 app', () => {
  it('takes its own request and response through the guard, the caller and applyIntents', async () => {
    const { auth } = buildAuth()
    const route: RequestHandler = (req, res) => {
      applyIntents([{ body: expressCaller(req), status: 200, type: 'json' }], res)
    }
    const server = express().use(expressCsrf(auth)).post('/orders', route).listen(0, '127.0.0.1')
    await new Promise((resolve) => server.once('listening', resolve))
    const address = server.address()
    if (typeof address !== 'object' || address === null) throw new Error('the server has no port')
    const post = (site: string) =>
      fetch(`http://127.0.0.1:${address.port}/orders`, {
        headers: { 'sec-fetch-site': site, 'user-agent': 'probe/1' },
        method: 'POST',
      })
    try {
      const refused = await post('cross-site')
      expect(refused.status).toBe(403)
      expect(await refused.json()).toMatchObject({ error: { code: 'AUTH_CSRF' }, ok: false })
      const ran = await post('same-origin')
      expect(await ran.json()).toMatchObject({ userAgent: 'probe/1' })
    } finally {
      server.close()
    }
  })
})

describe('expressCsrf', () => {
  function run(method: string, headers: Record<string, string>) {
    const { auth } = buildAuth()
    const rec = mockRes()
    const next = vi.fn()
    const req = { headers, method }
    return { next, rec, run: expressCsrf(auth)(req, rec.res, next) }
  }

  it('lets a safe method through even from a cross-site context', async () => {
    const t = run('GET', { 'sec-fetch-site': 'cross-site' })
    await t.run
    expect(t.next).toHaveBeenCalledOnce()
  })

  it('rejects a cross-site mutation with 403 and never calls next', async () => {
    const t = run('POST', { 'sec-fetch-site': 'cross-site' })
    await t.run
    expect(t.next).not.toHaveBeenCalled()
    expect(t.rec.status).toBe(403)
    expect(t.rec.body).toMatchObject({ error: { code: 'AUTH_CSRF' } })
  })

  it('lets a Bearer request through: no ambient cookie to forge', async () => {
    const t = run('POST', { authorization: 'Bearer tok', 'sec-fetch-site': 'cross-site' })
    await t.run
    expect(t.next).toHaveBeenCalledOnce()
  })

  it('lets an ordinary same-origin mutation through', async () => {
    const t = run('POST', { 'sec-fetch-site': 'same-origin' })
    await t.run
    expect(t.next).toHaveBeenCalledOnce()
  })
})
