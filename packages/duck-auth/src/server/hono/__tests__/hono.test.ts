import { describe, expect, it } from 'vitest'
import { MemoryAuthAdapter } from '../../../adapters/memory'
import { AuthRoot } from '../../../core/auth'
import { ScryptHasher } from '../../../core/password/scrypt'
import { CookieTransport } from '../../../core/transport/cookie'
import { MemoryLimiter } from '../../../limiters/memory'
import { password } from '../../../providers/password'
import { type HonoContextLike, honoSession, honoSignIn, honoSignOut } from '../index'

interface MyProfile {
  email: string
}

function buildAuth() {
  const adapter = new MemoryAuthAdapter<MyProfile>()
  const auth = new AuthRoot<MyProfile>({
    baseUrl: 'https://x',
    transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new MemoryLimiter({ max: 5, windowMs: 60_000 }),
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
): HonoContextLike {
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
      header: (name) => (name === undefined ? Object.fromEntries(req.headers) : (req.headers.get(name) ?? undefined)),
      json: async () => (init.body === undefined ? {} : init.body),
      param: () => undefined,
    },
  }
}

describe('Hono adapter — end-to-end', () => {
  it('honoSignIn happy path returns 200 + Set-Cookie', async () => {
    const { auth } = buildAuth()
    const identity = await auth.identities.create({ profile: { email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'correct-pw')
    const res = await honoSignIn(auth)(
      makeCtx('POST', '/auth/signin', {
        body: { providerId: 'password', input: { email: 'a@x.com', password: 'correct-pw' } },
      }),
    )
    expect(res.status).toBe(200)
    expect(res.headers.get('set-cookie')).toMatch(/^duck-sid=/)
  })

  it('honoSignIn wrong password returns 401', async () => {
    const { auth } = buildAuth()
    const identity = await auth.identities.create({ profile: { email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'correct-pw')
    const res = await honoSignIn(auth)(
      makeCtx('POST', '/auth/signin', {
        body: { providerId: 'password', input: { email: 'a@x.com', password: 'wrong' } },
      }),
    )
    expect(res.status).toBe(401)
    const body = (await res.json()) as { code: string }
    expect(body.code).toBe('AUTH/INVALID_CREDENTIALS')
  })

  it('honoSession returns resolved session after signin', async () => {
    const { auth } = buildAuth()
    const identity = await auth.identities.create({ profile: { email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'correct-pw')
    const signinRes = await honoSignIn(auth)(
      makeCtx('POST', '/auth/signin', {
        body: { providerId: 'password', input: { email: 'a@x.com', password: 'correct-pw' } },
      }),
    )
    const sidMatch = signinRes.headers.get('set-cookie')?.match(/^duck-sid=([^;]+)/)
    const sid = sidMatch ? decodeURIComponent(sidMatch[1] ?? '') : ''

    const sessRes = await honoSession(auth)(makeCtx('GET', '/auth/session', { headers: { cookie: `duck-sid=${sid}` } }))
    expect(sessRes.status).toBe(200)
    const body = (await sessRes.json()) as { identity: { id: string } | null }
    expect(body.identity?.id).toBe(identity.id)
  })

  it('honoSignOut revokes + clears cookie', async () => {
    const { auth, adapter } = buildAuth()
    const identity = await auth.identities.create({ profile: { email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'correct-pw')
    const signinRes = await honoSignIn(auth)(
      makeCtx('POST', '/auth/signin', {
        body: { providerId: 'password', input: { email: 'a@x.com', password: 'correct-pw' } },
      }),
    )
    const sid = decodeURIComponent(
      (signinRes.headers.get('set-cookie')?.match(/^duck-sid=([^;]+)/)?.[1] ?? '') as string,
    )
    expect((await adapter.sessions.listByIdentity(identity.id)).length).toBe(1)
    const outRes = await honoSignOut(auth)(makeCtx('POST', '/auth/signout', { headers: { cookie: `duck-sid=${sid}` } }))
    expect(outRes.status).toBe(200)
    expect(outRes.headers.get('set-cookie')).toContain('Max-Age=0')
    expect((await adapter.sessions.listByIdentity(identity.id)).length).toBe(0)
  })
})
