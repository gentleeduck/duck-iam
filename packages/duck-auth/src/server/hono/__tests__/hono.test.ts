import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '../../../adapters/memory'
import { AuthEngine } from '../../../core/auth'
import { ScryptHasher } from '../../../core/password/scrypt'
import { AuthCookieTransport } from '../../../core/transport/cookie'
import { AuthMemoryLimiter } from '../../../limiters/memory'
import { authPassword } from '../../../providers/password'
import { type AuthHonoAdapter, authHonoSession, authHonoSignIn, authHonoSignOut } from '../index'

interface MyProfile {
  email: string
}

function buildAuth() {
  const adapter = new MemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://x',
    transport: new AuthCookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new AuthMemoryLimiter({ max: 5, windowMs: 60_000 }),
    passwords: { hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) },
  })
  auth.providers.register(
    authPassword<MyProfile>({
      findIdentityByEmail: (email) => adapter.identities.findByEmail(email, {}),
      passwords: auth.passwords,
    }),
  )
  return { auth, adapter }
}

function makeCtx(
  method: string,
  url: string,
  init: { headers?: Record<string, string>; body?: unknown } = {},
): AuthHonoAdapter.IContext {
  const req = new Request(`https://x${url}`, {
    method,
    headers: init.headers,
    body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
  })
  return {
    req: {
      method,
      url,
      raw: req,
      header: (name) => {
        if (name === undefined) {
          const obj: Record<string, string> = {}
          req.headers.forEach((value, key) => {
            obj[key] = value
          })
          return obj
        }
        return req.headers.get(name) ?? undefined
      },
      json: async () => (init.body === undefined ? {} : init.body),
      param: () => undefined,
    },
  }
}

describe('Hono adapter - end-to-end', () => {
  it('authHonoSignIn happy path returns 200 + Set-Cookie', async () => {
    const { auth } = buildAuth()
    const identity = await auth.identities.create({ profile: { email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'correct-pw')
    const res = await authHonoSignIn(auth)(
      makeCtx('POST', '/auth/signin', {
        body: { providerId: 'password', input: { email: 'a@x.com', password: 'correct-pw' } },
      }),
    )
    expect(res.status).toBe(200)
    expect(res.headers.get('set-cookie')).toMatch(/^duck-sid=/)
  })

  it('authHonoSignIn wrong password returns 401', async () => {
    const { auth } = buildAuth()
    const identity = await auth.identities.create({ profile: { email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'correct-pw')
    const res = await authHonoSignIn(auth)(
      makeCtx('POST', '/auth/signin', {
        body: { providerId: 'password', input: { email: 'a@x.com', password: 'wrong' } },
      }),
    )
    expect(res.status).toBe(401)
    const body = (await res.json()) as { code: string }
    expect(body.code).toBe('AUTH/INVALID_CREDENTIALS')
  })

  it('authHonoSession returns resolved session after signin', async () => {
    const { auth } = buildAuth()
    const identity = await auth.identities.create({ profile: { email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'correct-pw')
    const signinRes = await authHonoSignIn(auth)(
      makeCtx('POST', '/auth/signin', {
        body: { providerId: 'password', input: { email: 'a@x.com', password: 'correct-pw' } },
      }),
    )
    const sidMatch = signinRes.headers.get('set-cookie')?.match(/^duck-sid=([^;]+)/)
    const sid = sidMatch ? decodeURIComponent(sidMatch[1] ?? '') : ''

    const sessRes = await authHonoSession(auth)(
      makeCtx('GET', '/auth/session', { headers: { cookie: `duck-sid=${sid}` } }),
    )
    expect(sessRes.status).toBe(200)
    const body = (await sessRes.json()) as { identity: { id: string } | null }
    expect(body.identity?.id).toBe(identity.id)
  })

  it('authHonoSignOut revokes + clears cookie', async () => {
    const { auth, adapter } = buildAuth()
    const identity = await auth.identities.create({ profile: { email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'correct-pw')
    const signinRes = await authHonoSignIn(auth)(
      makeCtx('POST', '/auth/signin', {
        body: { providerId: 'password', input: { email: 'a@x.com', password: 'correct-pw' } },
      }),
    )
    // signin now emits both __Host-duck-csrf and the SID; replay
    // both on signout + attach the matching x-csrf-token header.
    const setCookieJoined = signinRes.headers.get('set-cookie') ?? ''
    const sid = decodeURIComponent(setCookieJoined.match(/duck-sid=([^;,]+)/)?.[1] ?? '')
    const csrfToken = decodeURIComponent(setCookieJoined.match(/__Host-duck-csrf=([^;,]+)/)?.[1] ?? '')
    expect(csrfToken).not.toBe('')
    expect((await adapter.sessions.listByIdentity(identity.id)).length).toBe(1)
    const outRes = await authHonoSignOut(auth)(
      makeCtx('POST', '/auth/signout', {
        headers: {
          cookie: `duck-sid=${sid}; __Host-duck-csrf=${csrfToken}`,
          'x-csrf-token': csrfToken,
          'sec-fetch-site': 'same-origin',
        },
      }),
    )
    expect(outRes.status).toBe(200)
    expect(outRes.headers.get('set-cookie')).toContain('Max-Age=0')
    expect((await adapter.sessions.listByIdentity(identity.id)).length).toBe(0)
  })
})
