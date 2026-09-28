import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import type { Identities } from '~/core/identities/identities.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { authTestDeliver } from '~/test'

interface MyProfile extends Identities.ProfileMetadataBase {
  email: string
}

async function build() {
  const adapter = new MemoryAdapter<MyProfile>()
  const channel = authTestDeliver()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app.example.com',
    deliver: channel.deliver,
    limiter: new MemoryLimiter({ max: 50, windowMs: 60_000 }),
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
  const identity = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a@x.com' } })
  const tokens = () => adapter.credentials.listByIdentity(identity.id, 'recovery', {})
  return { auth, channel, identityId: identity.id, tokens }
}

type Request = (auth: AuthEngine<MyProfile>, identityId: string, ttlMs: number) => Promise<{ ok: true }>

const FLOWS: Record<string, Request> = {
  'account deletion': (auth, identityId, ttlMs) => auth.flows.requestAccountDeletion({ identityId, ttlMs }),
  'email verification': (auth, identityId, ttlMs) => auth.flows.requestEmailVerification({ identityId, ttlMs }),
  'password reset': (auth, identityId, ttlMs) =>
    auth.flows.requestPasswordReset({
      findIdentityByEmail: async () => ({ id: identityId }),
      input: { email: 'a@x.com', ttlMs },
    }),
}

const UNUSABLE = [Number.NaN, 0, -1, Number.POSITIVE_INFINITY]

describe.each(Object.entries(FLOWS))('%s: the token lifetime', (_, request) => {
  it.each(UNUSABLE)('refuses ttlMs %o before writing or sending anything', async (ttlMs) => {
    const { auth, channel, identityId, tokens } = await build()
    await expect(request(auth, identityId, ttlMs)).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
    expect(await tokens()).toEqual([])
    expect(channel.outbox).toEqual([])
  })

  it('stamps the token with the lifetime it was given', async () => {
    const { auth, channel, identityId, tokens } = await build()
    const before = Date.now()
    await expect(request(auth, identityId, 120_000)).resolves.toEqual({ ok: true })
    const [row] = await tokens()
    expect(row?.expiresAt?.getTime()).toBeGreaterThanOrEqual(before + 120_000)
    expect(row?.expiresAt?.getTime()).toBeLessThanOrEqual(Date.now() + 120_000)
    await expect.poll(() => channel.outbox[0]?.vars.ttlMin).toBe(2)
  })
})

describe('password reset: a refused lifetime says nothing about who exists', () => {
  it('answers an unknown address exactly as it answers a known one', async () => {
    const { auth, identityId } = await build()
    const findIdentityByEmail = async (email: string) => (email === 'a@x.com' ? { id: identityId } : null)
    for (const email of ['a@x.com', 'ghost@x.com']) {
      await expect(
        auth.flows.requestPasswordReset({ findIdentityByEmail, input: { email, ttlMs: Number.NaN } }),
      ).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
    }
  })
})
