import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { callerContext } from '../generic'

/**
 * Every adapter has to hand the caller to `flows.signIn`, because the flow, the store and the
 * columns all take it and a session row that cannot name a device is worse than none: somebody
 * reads their own device list, recognises nothing, and concludes nothing is wrong.
 *
 * The rule the helper encodes is that an address is only ever what the framework resolved.
 * Reading a forwarded header inside the library would take the value the caller wrote, and the
 * host is the only layer that knows how many proxies it trusts.
 */

const EMAIL = 'caller@example.test'
const PASSWORD = 'a-very-long-test-password'

type Profile = { email: string; username: string }

async function engineWithIdentity() {
  const adapter = new MemoryAdapter<Profile>()
  const auth = new AuthEngine<Profile>({
    baseUrl: 'http://localhost',
    limiter: new MemoryLimiter({ max: 100, windowMs: 60_000 }),
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
  auth.providers.register(passwords<Profile>({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) }))

  const identity = await auth.identities.create({
    emailVerified: false,
    profile: { email: EMAIL, username: 'caller' },
    providers: [],
  })
  await auth.passwords.set(identity.id, PASSWORD, adapter.credentials)
  return { auth, identity }
}

async function signInThen(extra: {
  ip?: string
  userAgent?: string
}): Promise<{ ip: string | null; userAgent: string | null }> {
  const { auth, identity } = await engineWithIdentity()
  await auth.flows.signIn({ input: { email: EMAIL, password: PASSWORD }, providerId: 'password', ...extra })
  const [session] = await auth.sessions.listForIdentity(identity.id)
  return { ip: session?.ip ?? null, userAgent: session?.userAgent ?? null }
}

describe('callerContext', () => {
  it('passes both through when the framework resolved them', () => {
    expect(callerContext({ ip: '203.0.113.7', userAgent: 'curl/8.0' })).toEqual({
      ip: '203.0.113.7',
      userAgent: 'curl/8.0',
    })
  })

  it('omits rather than nulls, so the flow defaults still apply', () => {
    expect(callerContext({})).toEqual({})
  })

  it('omits an address the framework could not resolve', () => {
    expect(callerContext({ userAgent: 'curl/8.0' })).toEqual({ userAgent: 'curl/8.0' })
  })

  it('drops an empty string, which is absence wearing a value', () => {
    expect(callerContext({ ip: '', userAgent: '' })).toEqual({})
  })

  it('drops a non-string user agent, which is what a repeated header gives you', () => {
    expect(callerContext({ ip: '203.0.113.7', userAgent: ['a', 'b'] })).toEqual({ ip: '203.0.113.7' })
  })
})

describe('what reaches the session row', () => {
  it('records both when the adapter supplies them', async () => {
    expect(await signInThen({ ip: '203.0.113.7', userAgent: 'curl/8.0' })).toEqual({
      ip: '203.0.113.7',
      userAgent: 'curl/8.0',
    })
  })

  it('records null rather than a placeholder when the adapter supplies nothing', async () => {
    expect(await signInThen({})).toEqual({ ip: null, userAgent: null })
  })

  it('truncates a hostile user agent rather than storing it whole', async () => {
    const { userAgent } = await signInThen({ userAgent: 'x'.repeat(4096) })
    expect(userAgent).toHaveLength(512)
  })

  it('truncates a hostile address the same way', async () => {
    const { ip } = await signInThen({ ip: 'x'.repeat(4096) })
    expect(ip).toHaveLength(64)
  })
})
