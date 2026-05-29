import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAuthAdapter } from '../../../adapters/memory'
import { AuthRoot } from '../../../core/auth'
import { ScryptHasher } from '../../../core/password/scrypt'
import { CookieTransport } from '../../../core/transport/cookie'
import { MemoryLimiter } from '../../../limiters/memory'
import { password } from '../../../providers/password'
import { type ElysiaAdapter, elysiaProviderBegin, elysiaSession, elysiaSignIn, elysiaSignOut } from '../index'

interface MyProfile {
  email: string
}

function buildAuth() {
  const adapter = new MemoryAuthAdapter<MyProfile>()
  const auth = new AuthRoot<MyProfile>({
    baseUrl: 'https://app',
    transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new MemoryLimiter({ max: 20, windowMs: 60_000 }),
    passwords: { hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) },
  })
  auth.providers.register(
    password({
      passwords: auth.passwords,
      findIdentityByEmail: async (email) => (await adapter.identities.findByEmail(email, {})) as { id: string } | null,
    }),
  )
  return { auth, adapter }
}

function ctx(
  body: unknown = {},
  params: Record<string, string> = {},
  headers: HeadersInit = {},
): ElysiaAdapter.IContext {
  return {
    request: new Request('https://app/auth/x', { method: 'POST', headers }),
    body,
    params,
  }
}

describe('Elysia adapter', () => {
  let auth: ReturnType<typeof buildAuth>['auth']
  let adapter: ReturnType<typeof buildAuth>['adapter']

  beforeEach(() => {
    ;({ auth, adapter } = buildAuth())
  })

  it('signIn rejects missing providerId with 400', async () => {
    const res = await elysiaSignIn(auth)(ctx({}))
    expect(res.status).toBe(400)
    expect(await res.text()).toContain('AUTH/INVALID_CREDENTIALS')
  })

  it('signIn happy path sets cookie + 200', async () => {
    const ident = await adapter.identities.create({ profile: { email: 'user@x.com' }, providers: [] }, {})
    await auth.passwords.set(ident.id, 'correcthorsebatterystaple', {})
    const res = await elysiaSignIn(auth)(
      ctx({
        providerId: 'password',
        input: { email: 'user@x.com', password: 'correcthorsebatterystaple' },
      }),
    )
    expect(res.status).toBe(200)
    const setCookie = res.headers.get('set-cookie') ?? ''
    expect(setCookie).toContain('duck-sid=')
  })

  it('session returns null body without cookie', async () => {
    const res = await elysiaSession(auth)(ctx())
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ session: null, identity: null })
  })

  it('signOut clears cookie without session', async () => {
    const res = await elysiaSignOut(auth)(ctx())
    const setCookie = res.headers.get('set-cookie') ?? ''
    expect(setCookie).toMatch(/Max-Age=0/i)
  })

  it('providerBegin requires :id', async () => {
    const res = await elysiaProviderBegin(auth)(ctx({}, {}))
    expect(res.status).toBe(400)
    expect(await res.text()).toContain('AUTH/PROVIDER_FAILED')
  })
})
