import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { elysiaCaller } from '../elysia'
import { expressCaller } from '../express'
import { fastifyCaller } from '../fastify'
import { honoCaller } from '../hono'
import { koaCaller } from '../koa'
import { nestCaller } from '../nestjs'
import { nextCaller } from '../next'

/** Each adapter's caller reads what its framework resolved, and never a forwarded header. */

const UA = 'iryss-adapter-probe/1.0'
const IP = '203.0.113.9'
const FORWARDED = { 'user-agent': UA, 'x-forwarded-for': '198.51.100.1' }

describe('adapters read the caller their framework resolved', () => {
  it('express takes req.ip and the user agent', () => {
    expect(expressCaller({ headers: FORWARDED, ip: IP, method: 'POST' })).toEqual({ ip: IP, userAgent: UA })
  })

  it('fastify does the same', () => {
    expect(fastifyCaller({ headers: FORWARDED, ip: IP, method: 'POST' })).toEqual({ ip: IP, userAgent: UA })
  })

  it('koa reads them off ctx.request', () => {
    const ctx = { body: undefined, request: { headers: FORWARDED, ip: IP, method: 'POST' }, set: () => {}, status: 200 }
    expect(koaCaller(ctx)).toEqual({ ip: IP, userAgent: UA })
  })

  it('nest takes req.ip, not a forwarded header', () => {
    expect(nestCaller({ headers: FORWARDED, identity: null, ip: IP, method: 'POST' })).toEqual({
      ip: IP,
      userAgent: UA,
    })
  })

  it('hono records the user agent, and no address because it resolves none', () => {
    const req = { header: (n?: string) => (n === 'user-agent' ? UA : undefined) }
    expect(honoCaller({ req })).toEqual({ userAgent: UA })
    expect(honoCaller({ ip: IP, req })).toEqual({ ip: IP, userAgent: UA })
  })

  it('elysia reads the user agent off the Web Request', () => {
    const request = new Request('http://localhost/', { headers: FORWARDED })
    expect(elysiaCaller({ request })).toEqual({ userAgent: UA })
    expect(elysiaCaller({ ip: IP, request })).toEqual({ ip: IP, userAgent: UA })
  })

  it('next records the user agent and never an address', () => {
    expect(nextCaller(new Request('http://localhost/', { headers: FORWARDED }))).toEqual({ userAgent: UA })
  })

  it('flows.signIn stamps what a caller read onto the session row', async () => {
    type Profile = { email: string; username: string }
    const adapter = new MemoryAdapter<Profile>()
    const auth = new AuthEngine<Profile>({
      baseUrl: 'http://localhost',
      limiter: new MemoryLimiter({ max: 100, windowMs: 60_000 }),
      stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
      transport: new CookieTransport({ name: 'duck-sid', secure: false }),
    })
    auth.providers.register(passwords<Profile>({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) }))
    const identity = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a' }, providers: [] })
    await auth.passwords.set(identity.id, 'correct-horse-battery', adapter.credentials)

    await auth.flows.signIn({
      input: { email: 'a@x.com', password: 'correct-horse-battery' },
      providerId: 'password',
      ...expressCaller({ headers: FORWARDED, ip: IP, method: 'POST' }),
    })

    const [session] = await auth.sessions.listForIdentity(identity.id)
    expect({ ip: session?.ip, userAgent: session?.userAgent }).toEqual({ ip: IP, userAgent: UA })
  })
})
