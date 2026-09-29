import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { type FastifyAdapter, fastifyCsrf } from '../index'

function makeReply(): FastifyAdapter.Reply & {
  _status?: number
  _headers: Map<string, string[]>
  _body?: string
} {
  const headers = new Map<string, string[]>()
  const reply: FastifyAdapter.Reply & {
    _status?: number
    _headers: Map<string, string[]>
    _body?: string
  } = {
    _headers: headers,
    status(code) {
      this._status = code
      return this
    },
    header(key, value) {
      const k = key.toLowerCase()
      const existing = this._headers.get(k) ?? []
      existing.push(value)
      this._headers.set(k, existing)
      return this
    },
    send(payload) {
      this._body = typeof payload === 'string' ? payload : JSON.stringify(payload)
      return this
    },
  }
  return reply
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

describe('fastifyCsrf', () => {
  async function run(method: string, headers: Record<string, string>) {
    const { auth } = buildAuth()
    const reply = makeReply()
    await fastifyCsrf(auth)({ headers, method }, reply)
    return reply
  }

  it('lets a safe method through even from a cross-site context', async () => {
    expect((await run('GET', { 'sec-fetch-site': 'cross-site' }))._status).toBeUndefined()
  })

  it('rejects a cross-site mutation with 403', async () => {
    const reply = await run('POST', { 'sec-fetch-site': 'cross-site' })
    expect(reply._status).toBe(403)
    expect(reply._body).toContain('AUTH_CSRF')
  })

  it('lets a Bearer request through: no ambient cookie to forge', async () => {
    const reply = await run('POST', { authorization: 'Bearer tok', 'sec-fetch-site': 'cross-site' })
    expect(reply._status).toBeUndefined()
  })

  it('lets an ordinary same-origin mutation through', async () => {
    expect((await run('POST', { 'sec-fetch-site': 'same-origin' }))._status).toBeUndefined()
  })
})
