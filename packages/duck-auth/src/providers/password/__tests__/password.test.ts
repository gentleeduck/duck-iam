import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '../../../adapters/memory'
import { Identity } from '../../../core'
import { AuthEngine } from '../../../core/engine'
import { CookieTransport } from '../../../core/transport/cookie'
import { AuthMemoryLimiter } from '../../../limiters/memory'
import { passwordProvider } from '..'
import { ScryptHasher } from '../hashers/scrypt.hasher'
import { password } from '../index'

interface MyProfile extends Identity.ProfileMetadataBase {}

function buildAuth(): {
  auth: AuthEngine<MyProfile>
  adapter: MemoryAdapter<MyProfile>
} {
  const adapter = new MemoryAdapter<MyProfile>()
  const fastHasher = new ScryptHasher({ N: 1 << 10, keylen: 32 })
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://x',
    transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new AuthMemoryLimiter({ max: 5, windowMs: 60_000 }),
    providers: [passwordProvider({ hasher: fastHasher })],
  })
  auth.providers.register(
    password<MyProfile>({
      findIdentityByEmail: (email) => adapter.identities.findByEmail(email, {}),
      passwords: auth.passwords,
    }),
  )
  return { auth, adapter }
}

describe('password provider - end-to-end sign-in', () => {
  let auth: AuthEngine<MyProfile>
  let adapter: MemoryAdapter<MyProfile>

  beforeEach(() => {
    ;({ auth, adapter } = buildAuth())
  })

  it('full happy path: create identity -> set password -> sign in -> cookie issued', async () => {
    const identity = await auth.identities.create({ profile: { email: 'alice@x.com', username: 'alice' } })
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
    const identity = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a' } })
    await auth.passwords.set(identity.id, 'correct-pw')

    const failedHandler = vi.fn()
    auth.events.on('signin.failed', failedHandler)

    await expect(
      auth.flows.signIn({
        providerId: 'password',
        input: { email: 'a@x.com', password: 'wrong-pw' },
      }),
    ).rejects.toMatchObject({ code: 'AUTH_INVALID_CREDENTIALS' })
    expect(failedHandler).toHaveBeenCalledOnce()
  })

  it('unknown email surfaces AUTH/INVALID_CREDENTIALS (no enumeration)', async () => {
    await expect(
      auth.flows.signIn({
        providerId: 'password',
        input: { email: 'ghost@x.com', password: 'anything-strong' },
      }),
    ).rejects.toMatchObject({ code: 'AUTH_INVALID_CREDENTIALS' })
  })

  it('no-user branch queries credentials with a syntactically valid UUID (pg uuid column safe)', async () => {
    // Regression: the timing-defense verify on the no-such-user branch must
    // feed a well-formed UUID. A non-UUID sentinel (e.g. '__never__') makes
    // Postgres reject `identity_id = '__never__'` on the uuid column with
    // `invalid input syntax for type uuid`, turning a 401 into a raw 500.
    const uuidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
    const spy = vi.spyOn(adapter.credentials, 'listByIdentity')

    await auth.flows
      .signIn({ providerId: 'password', input: { email: 'ghost@x.com', password: 'anything-strong' } })
      .catch(() => {})

    expect(spy).toHaveBeenCalled()
    const [identityId] = spy.mock.calls[0]!
    expect(identityId).toMatch(uuidRe)
  })

  it('rate limit trips after configured attempts', async () => {
    const identity = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a' } })
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
    ).rejects.toMatchObject({ code: 'AUTH_RATE_LIMITED' })
  })

  it('unknown provider id surfaces AUTH/PROVIDER_FAILED', async () => {
    await expect(
      auth.flows.signIn({
        providerId: 'does-not-exist',
        input: {},
      }),
    ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
  })

  it('signOut revokes the session and emits clearCookie intent', async () => {
    const identity = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a' } })
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

  it('AuthEngine.resolveSession() returns the (session, identity) pair after sign-in', async () => {
    const identity = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a' } })
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
      const identity = await auth.identities.create({ profile: { email: 'alice@x.com', username: 'alice' } })
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
      ).rejects.toMatchObject({ code: 'AUTH_RATE_LIMITED' })
    })
  })
})
