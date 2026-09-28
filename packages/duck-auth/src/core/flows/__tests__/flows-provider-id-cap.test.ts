import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import type { Identities } from '~/core/identities/identities.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'

interface MyProfile extends Identities.ProfileMetadataBase {
  email: string
}

function buildAuth(): AuthEngine<MyProfile> {
  const adapter = new MemoryAdapter<MyProfile>()
  return new AuthEngine<MyProfile>({
    baseUrl: 'https://app',
    transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new MemoryLimiter({ max: 20, windowMs: 60_000 }),
  })
}

describe('FlowsImpl provider id reflection-DoS defense', () => {
  const refused = { code: 'AUTH_PROVIDER_FAILED', meta: { providerId: 'invalid' } }

  it('signIn refuses an oversize providerId without echoing it back in meta', async () => {
    const auth = buildAuth()
    await expect(auth.flows.signIn({ providerId: 'x'.repeat(129), input: {} })).rejects.toMatchObject(refused)
  })

  it.each([['nope'], ['x'.repeat(128)]])('signIn echoes an in-range unknown providerId (%#)', async (providerId) => {
    const auth = buildAuth()
    await expect(auth.flows.signIn({ providerId, input: {} })).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
      meta: { providerId },
    })
  })

  it('beginProvider refuses an oversize providerId without echoing it back', async () => {
    const auth = buildAuth()
    await expect(auth.flows.beginProvider('y'.repeat(200), {})).rejects.toMatchObject(refused)
  })

  it('beginProvider rejects non-string providerId (typeof guard)', async () => {
    const auth = buildAuth()
    // @ts-expect-error not a string
    await expect(auth.flows.beginProvider(42, {})).rejects.toMatchObject(refused)
  })
})
