import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '../../../adapters/memory'
import { AuthEngine } from '../../../core/auth'
import { ScryptHasher } from '../../../core/password/scrypt'
import { AuthCookieTransport } from '../../../core/transport/cookie'
import { AuthMemoryLimiter } from '../../../limiters/memory'
import { authPassword } from '../../../providers/password'
import { authMountNext, authNextSession, authNextSignIn, authNextSignOut } from '../index'

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

describe('Next.js adapter - handler primitives', () => {
  it('authNextSignIn happy path', async () => {
    const { auth } = buildAuth()
    const identity = await auth.identities.create({ profile: { email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'correct-pw')
    const res = await authNextSignIn(auth)(
      new Request('https://x/api/auth/signin', {
        method: 'POST',
        body: JSON.stringify({ providerId: 'password', input: { email: 'a@x.com', password: 'correct-pw' } }),
      }),
    )
    expect(res.status).toBe(200)
    expect(res.headers.get('set-cookie')).toMatch(/^duck-sid=/)
  })

  it('authNextSession after signin', async () => {
    const { auth } = buildAuth()
    const identity = await auth.identities.create({ profile: { email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'correct-pw')
    const signin = await authNextSignIn(auth)(
      new Request('https://x/api/auth/signin', {
        method: 'POST',
        body: JSON.stringify({ providerId: 'password', input: { email: 'a@x.com', password: 'correct-pw' } }),
      }),
    )
    const sid = decodeURIComponent((signin.headers.get('set-cookie')?.match(/^duck-sid=([^;]+)/)?.[1] ?? '') as string)
    const res = await authNextSession(auth)(
      new Request('https://x/api/auth/session', { headers: { cookie: `duck-sid=${sid}` } }),
    )
    expect(res.status).toBe(200)
    const body = (await res.json()) as { identity: { id: string } | null }
    expect(body.identity?.id).toBe(identity.id)
  })

  it('authNextSignOut revokes', async () => {
    const { auth, adapter } = buildAuth()
    const identity = await auth.identities.create({ profile: { email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'correct-pw')
    const signin = await authNextSignIn(auth)(
      new Request('https://x/api/auth/signin', {
        method: 'POST',
        body: JSON.stringify({ providerId: 'password', input: { email: 'a@x.com', password: 'correct-pw' } }),
      }),
    )
    // signin issues both SID + CSRF cookies; replay both on signout.
    const setCookieJoined = signin.headers.get('set-cookie') ?? ''
    const sid = decodeURIComponent(setCookieJoined.match(/duck-sid=([^;,]+)/)?.[1] ?? '')
    const csrfToken = decodeURIComponent(setCookieJoined.match(/__Host-duck-csrf=([^;,]+)/)?.[1] ?? '')
    expect(csrfToken).not.toBe('')
    const out = await authNextSignOut(auth)(
      new Request('https://x/api/auth/signout', {
        method: 'POST',
        headers: {
          cookie: `duck-sid=${sid}; __Host-duck-csrf=${csrfToken}`,
          'x-csrf-token': csrfToken,
          'sec-fetch-site': 'same-origin',
        },
      }),
    )
    expect(out.status).toBe(200)
    expect((await adapter.sessions.listByIdentity(identity.id)).length).toBe(0)
  })
})

describe('authMountNext - catch-all router', () => {
  it('routes POST /api/auth/signin to authNextSignIn', async () => {
    const { auth } = buildAuth()
    const identity = await auth.identities.create({ profile: { email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'correct-pw')
    const { POST } = authMountNext(auth)
    const res = await POST(
      new Request('https://x/api/auth/signin', {
        method: 'POST',
        body: JSON.stringify({ providerId: 'password', input: { email: 'a@x.com', password: 'correct-pw' } }),
      }),
    )
    expect(res.status).toBe(200)
    expect(res.headers.get('set-cookie')).toMatch(/^duck-sid=/)
  })

  it('routes GET /api/auth/session', async () => {
    const { auth } = buildAuth()
    const { GET } = authMountNext(auth)
    const res = await GET(new Request('https://x/api/auth/session'))
    expect(res.status).toBe(200)
    const body = (await res.json()) as { identity: null | object }
    expect(body.identity).toBeNull()
  })

  it('unknown route returns 404 AUTH/PROVIDER_FAILED', async () => {
    const { auth } = buildAuth()
    const { POST } = authMountNext(auth)
    const res = await POST(new Request('https://x/api/auth/unknown', { method: 'POST' }))
    expect(res.status).toBe(404)
  })
})
