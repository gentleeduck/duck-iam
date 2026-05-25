import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAuthAdapter } from '../../../adapters/memory'
import { AuthRoot } from '../../../core/auth'
import { ScryptHasher } from '../../../core/password/scrypt'
import { CookieTransport } from '../../../core/transport/cookie'
import { MemoryLimiter } from '../../../limiters/memory'
import { password } from '../index'

interface MyProfile {
  email: string
}

function buildAuth(): {
  auth: AuthRoot<MyProfile>
  adapter: MemoryAuthAdapter<MyProfile>
} {
  const adapter = new MemoryAuthAdapter<MyProfile>()
  const fastHasher = new ScryptHasher({ N: 1 << 10, keylen: 32 })
  const auth = new AuthRoot<MyProfile>({
    baseUrl: 'https://x',
    transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new MemoryLimiter({ max: 5, windowMs: 60_000 }),
    passwords: { hasher: fastHasher },
  })
  auth.providers.register(
    password<MyProfile>({
      findIdentityByEmail: (email) => adapter.identities.findByEmail(email, {}),
      passwords: auth.passwords,
    }),
  )
  return { auth, adapter }
}

describe('password provider — end-to-end sign-in', () => {
  let auth: AuthRoot<MyProfile>
  let adapter: MemoryAuthAdapter<MyProfile>

  beforeEach(() => {
    ;({ auth, adapter } = buildAuth())
  })

  it('full happy path: create identity → set password → sign in → cookie issued', async () => {
    const identity = await auth.identities.create({ profile: { email: 'alice@x.com' } })
    await auth.passwords.set(identity.id, 'correct-horse-battery')

    const signinHandler = vi.fn()
    auth.events.on('signin.success', signinHandler)

    const result = await auth.flows.signIn({
      providerId: 'password',
      input: { email: 'alice@x.com', password: 'correct-horse-battery' },
    })

    expect(result.session.identityId).toBe(identity.id)
    expect(result.session.factors).toHaveLength(1)
    expect(result.session.factors[0]?.method).toBe('password')
    expect(signinHandler).toHaveBeenCalledOnce()

    // Cookie intent carries the PLAINTEXT sid, not the row hash.
    const cookieIntent = result.intents.find((i) => i.type === 'setCookie')
    expect(cookieIntent).toBeDefined()
    if (cookieIntent?.type === 'setCookie') {
      expect(cookieIntent.name).toBe('duck-sid')
      expect(cookieIntent.value).toBe(result.sid)
    }
  })

  it('wrong password surfaces AUTH/INVALID_CREDENTIALS without revealing which side failed', async () => {
    const identity = await auth.identities.create({ profile: { email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'correct-pw')

    const failedHandler = vi.fn()
    auth.events.on('signin.failed', failedHandler)

    await expect(
      auth.flows.signIn({
        providerId: 'password',
        input: { email: 'a@x.com', password: 'wrong-pw' },
      }),
    ).rejects.toMatchObject({ code: 'AUTH/INVALID_CREDENTIALS' })
    expect(failedHandler).toHaveBeenCalledOnce()
  })

  it('unknown email surfaces AUTH/INVALID_CREDENTIALS (no enumeration)', async () => {
    await expect(
      auth.flows.signIn({
        providerId: 'password',
        input: { email: 'ghost@x.com', password: 'anything-strong' },
      }),
    ).rejects.toMatchObject({ code: 'AUTH/INVALID_CREDENTIALS' })
  })

  it('rate limit trips after configured attempts', async () => {
    const identity = await auth.identities.create({ profile: { email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'correct-pw')

    for (let i = 0; i < 5; i++) {
      await auth.flows
        .signIn({
          providerId: 'password',
          input: { email: 'a@x.com', password: 'wrong' },
        })
        .catch(() => {})
    }
    await expect(
      auth.flows.signIn({
        providerId: 'password',
        input: { email: 'a@x.com', password: 'wrong' },
      }),
    ).rejects.toMatchObject({ code: 'AUTH/RATE_LIMITED' })
  })

  it('unknown provider id surfaces AUTH/PROVIDER_FAILED', async () => {
    await expect(
      auth.flows.signIn({
        providerId: 'does-not-exist',
        input: {},
      }),
    ).rejects.toMatchObject({ code: 'AUTH/PROVIDER_FAILED' })
  })

  it('signOut revokes the session and emits clearCookie intent', async () => {
    const identity = await auth.identities.create({ profile: { email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'correct-pw')
    const signin = await auth.flows.signIn({
      providerId: 'password',
      input: { email: 'a@x.com', password: 'correct-pw' },
    })
    const { intents } = await auth.flows.signOut(signin.sid)
    expect(intents.some((i) => i.type === 'clearCookie')).toBe(true)

    // Session no longer resolvable via store.
    const headers = new Headers({ cookie: `duck-sid=${signin.sid}` })
    const resolved = await auth.resolveSession({ headers })
    expect(resolved).toBeNull()
    void adapter
  })

  it('AuthRoot.resolveSession() returns the (session, identity) pair after sign-in', async () => {
    const identity = await auth.identities.create({ profile: { email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'correct-pw')
    const signin = await auth.flows.signIn({
      providerId: 'password',
      input: { email: 'a@x.com', password: 'correct-pw' },
    })
    const headers = new Headers({ cookie: `duck-sid=${signin.sid}` })
    const resolved = await auth.resolveSession({ headers })
    expect(resolved?.session.id).toBe(signin.session.id)
    expect(resolved?.identity?.profile?.email).toBe('a@x.com')
  })
})
