import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '../../../adapters/memory'
import { AuthEngine } from '../../../core/engine'
import { ScryptHasher } from '../../../core/password/scrypt'
import { CookieTransport } from '../../../core/transport/cookie'
import { AuthMemoryLimiter } from '../../../limiters/memory'
import { password } from '../../../providers/password'
import { type HonoAdapter, honoSession, honoSignIn, honoSignOut } from '../index'

type MyProfile = {
  username: string
  email: string
}

function buildAuth() {
  const adapter = new MemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://x',
    transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new AuthMemoryLimiter({ max: 5, windowMs: 60_000 }),
    passwords: { hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) },
  })
  auth.providers.register(
    password<MyProfile>({
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
): HonoAdapter.Context {
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
  it('honoSignIn happy path returns 200 + Set-Cookie', async () => {
    const { auth } = buildAuth()
    const identity = await auth.identities.create({ profile: { username: 'user', email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'correct-pw')
    const res = await honoSignIn(auth)(
      makeCtx('POST', '/AUTH/signin', {
        body: { providerId: 'password', input: { email: 'a@x.com', password: 'correct-pw' } },
      }),
    )
    expect(res.status).toBe(200)
    expect(res.headers.get('set-cookie')).toMatch(/^duck-sid=/)
  })

  it('honoSignIn wrong password returns 401', async () => {
    const { auth } = buildAuth()
    const identity = await auth.identities.create({ profile: { username: 'user', email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'correct-pw')
    const res = await honoSignIn(auth)(
      makeCtx('POST', '/AUTH/signin', {
        body: { providerId: 'password', input: { email: 'a@x.com', password: 'wrong' } },
      }),
    )
    expect(res.status).toBe(401)
    const body = (await res.json()) as { error: { code: string } }
    expect(body.error.code).toBe('AUTH_INVALID_CREDENTIALS')
  })

  it('honoSession returns resolved session after signin', async () => {
    const { auth } = buildAuth()
    const identity = await auth.identities.create({ profile: { username: 'user', email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'correct-pw')
    const signinRes = await honoSignIn(auth)(
      makeCtx('POST', '/AUTH/signin', {
        body: { providerId: 'password', input: { email: 'a@x.com', password: 'correct-pw' } },
      }),
    )
    const sidMatch = signinRes.headers.get('set-cookie')?.match(/^duck-sid=([^;]+)/)
    const sid = sidMatch ? decodeURIComponent(sidMatch[1] ?? '') : ''

    const sessRes = await honoSession(auth)(makeCtx('GET', '/AUTH/session', { headers: { cookie: `duck-sid=${sid}` } }))
    expect(sessRes.status).toBe(200)
    const body = (await sessRes.json()) as { identity: { id: string } | null }
    expect(body.identity?.id).toBe(identity.id)
  })

  it('honoSignOut revokes + clears cookie', async () => {
    const { auth, adapter } = buildAuth()
    const identity = await auth.identities.create({ profile: { username: 'user', email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'correct-pw')
    const signinRes = await honoSignIn(auth)(
      makeCtx('POST', '/AUTH/signin', {
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
    const outRes = await honoSignOut(auth)(
      makeCtx('POST', '/AUTH/signout', {
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
