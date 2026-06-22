import { beforeEach, describe, expect, it, vi } from 'vitest'
import { AuthMemoryAdapter } from '../../../adapters/memory'
import { AuthEngine } from '../../../core/auth'
import { AuthScryptHasher } from '../../../core/password/scrypt'
import { AuthCookieTransport } from '../../../core/transport/cookie'
import { AuthMemoryLimiter } from '../../../limiters/memory'
import { authPassword } from '../index'

interface MyProfile {
  email: string
}

function buildAuth(): {
  auth: AuthEngine<MyProfile>
  adapter: AuthMemoryAdapter<MyProfile>
} {
  const adapter = new AuthMemoryAdapter<MyProfile>()
  const fastHasher = new AuthScryptHasher({ N: 1 << 10, keylen: 32 })
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://x',
    transport: new AuthCookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new AuthMemoryLimiter({ max: 5, windowMs: 60_000 }),
    passwords: { hasher: fastHasher },
  })
  auth.providers.register(
    authPassword<MyProfile>({
      findIdentityByEmail: (email) => adapter.identities.findByEmail(email, {}),
      passwords: auth.passwords,
    }),
  )
  return { auth, adapter }
}

describe('password provider - end-to-end sign-in', () => {
  let auth: AuthEngine<MyProfile>
  let adapter: AuthMemoryAdapter<MyProfile>

  beforeEach(() => {
    ;({ auth, adapter } = buildAuth())
  })

  it('full happy path: create identity -> set password -> sign in -> cookie issued', async () => {
    const identity = await auth.identities.create({ profile: { email: 'alice@x.com' } })
    await auth.passwords.set(identity.id, 'correct-horse-battery')

    const signinHandler = vi.fn()
    auth.events.on('signin.success', signinHandler)

    const result = await auth.flows.signIn({
      providerId: 'password',
      input: { email: 'alice@x.com', password: 'correct-horse-battery' },
    })

    expect(result.session!.identityId).toBe(identity.id)
    expect(result.session!.factors).toHaveLength(1)
    expect(result.session!.factors[0]?.method).toBe('password')
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

    // AuthSession no longer resolvable via store.
    const headers = new Headers({ cookie: `duck-sid=${signin.sid}` })
    const resolved = await auth.resolveSession({ headers })
    expect(resolved).toBeNull()
    void adapter
  })

  it('AuthEngine.resolveSession() returns the (session, identity) pair after sign-in', async () => {
    const identity = await auth.identities.create({ profile: { email: 'a@x.com' } })
    await auth.passwords.set(identity.id, 'correct-pw')
    const signin = await auth.flows.signIn({
      providerId: 'password',
      input: { email: 'a@x.com', password: 'correct-pw' },
    })
    const headers = new Headers({ cookie: `duck-sid=${signin.sid}` })
    const resolved = await auth.resolveSession({ headers })
    expect(resolved?.session.id).toBe(signin.session!.id)
    expect(resolved?.identity?.profile?.email).toBe('a@x.com')
  })

  describe('email case-folding parity', () => {
    it('signs in with mixed-case email when identity is stored lowercase', async () => {
      const identity = await auth.identities.create({ profile: { email: 'alice@x.com' } })
      await auth.passwords.set(identity.id, 'correct-pw')
      const result = await auth.flows.signIn({
        providerId: 'password',
        input: { email: '  ALICE@X.com  ', password: 'correct-pw' },
      })
      expect(result.session!.identityId).toBe(identity.id)
    })

    it('rate-limit shares one bucket across mixed-case + whitespace variants', async () => {
      // Two unsuccessful attempts in different casing should still count
      // against the same email key. The limit is 5 / 60s in buildAuth().
      for (let i = 0; i < 5; i++) {
        const caseStyle = i % 2 === 0 ? 'GHOST@x.com' : ' ghost@x.com '
        await auth.flows
          .signIn({ providerId: 'password', input: { email: caseStyle, password: 'bad' } })
          .catch(() => {})
      }
      await expect(
        auth.flows.signIn({ providerId: 'password', input: { email: 'ghost@x.com', password: 'bad' } }),
      ).rejects.toMatchObject({ code: 'AUTH/RATE_LIMITED' })
    })
  })
})
